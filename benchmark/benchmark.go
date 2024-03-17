package benchmark

import (
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"log"
	"log/slog"
	"sync/atomic"
	"time"
)

type SessionEncryption string

const (
	SessionEncryptionNone      SessionEncryption = "SessionEncryptionNone"
	SessionEncryptionReuse                       = "SessionEncryptionReuse"
	SessionEncryptionEphemeral                   = "SessionEncryptionEphemeral"
)

func Signature(tpm transport.TPMCloser, keyType tpm2.TPMAlgID, iterations int, parallelism int, sessionEncryption SessionEncryption) error {
	digest := []byte("12341234123412341234123412341234")
	digestalg := tpm2.TPMAlgSHA256

	k, err := createKey(tpm, keyType)
	if err != nil {
		log.Fatal(err)
	}

	digestlength := 32
	if len(digest) != digestlength {
		return fmt.Errorf("incorrect checksum length. expected %v got %v", digestlength, len(digest))
	}

	srkHandle, srkPublic, err := createSRK(tpm)
	if err != nil {
		return fmt.Errorf("failed creating SRK: %v", err)
	}
	defer flushHandle(tpm, srkHandle)

	handle, err := loadKeyWithParent(tpm, *srkHandle, k)
	if err != nil {
		return err
	}
	defer flushHandle(tpm, handle)

	var sigscheme tpm2.TPMTSigScheme
	switch k.tPMKey.KeyAlgo() {
	case tpm2.TPMAlgECC:
		sigscheme = newECCSigScheme(digestalg)
	case tpm2.TPMAlgRSA:
		sigscheme = newRSASigScheme(digestalg)
	}

	var correct atomic.Uint64
	var tpmFail atomic.Uint64
	var duration atomic.Int64

	var reusedSession tpm2.Session
	var reusedSessionCloser func() error = nil

	if sessionEncryption == SessionEncryptionReuse {
		reusedSession, reusedSessionCloser, err = tpm2.HMACSession(tpm, tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic))
		if err != nil {
			slog.Debug("%s", err)
		}
	}

	sigFunction := func(index int) error {
		start := time.Now()
		sign := tpm2.Sign{
			KeyHandle: *handle,
			Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
			InScheme:  sigscheme,
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}

		var rspSign *tpm2.SignResponse
		var err error

		switch sessionEncryption {
		case SessionEncryptionNone:
			rspSign, err = sign.Execute(tpm)
		case SessionEncryptionEphemeral:
			session := tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Salted(srkHandle.Handle, *srkPublic))
			rspSign, err = sign.Execute(tpm, session)
		case SessionEncryptionReuse:
			rspSign, err = sign.Execute(tpm, reusedSession)
		default:
			return fmt.Errorf("unsupported sessionEncryption")
		}

		if err != nil {
			tpmFail.Add(1)
			return fmt.Errorf("failed to sign: %v", err)
		}

		switch k.tPMKey.KeyAlgo() {
		case tpm2.TPMAlgECC:
			_, err := rspSign.Signature.Signature.ECDSA()
			if err != nil {
				tpmFail.Add(1)
				return fmt.Errorf("failed to get signature: %v", err)
			}
		case tpm2.TPMAlgRSA:
			_, err := rspSign.Signature.Signature.RSASSA()
			if err != nil {
				tpmFail.Add(1)
				return fmt.Errorf("failed to get signature: %v", err)
			}
		}

		elapsed := time.Since(start)
		duration.Add(elapsed.Microseconds())
		correct.Add(1)
		return nil
	}

	correct.Store(0)
	var results []error

	resultChannels := make([]chan error, parallelism)
	for i := 0; i < iterations; i++ {
		for j := 0; j < parallelism; j++ {
			resultChannels[j] = make(chan error)

			k := j
			go func() {
				resultChannels[k] <- sigFunction(i % 2)
			}()
		}
		for j := 0; j < len(resultChannels); j++ {
			results = append(results, <-resultChannels[j])
		}
	}

	if reusedSessionCloser != nil {
		err = reusedSessionCloser()
		if err != nil {
			slog.Debug("%s", err)
		}
	}

	elapsed := float64(duration.Load()) / 1000000.0
	failed := 0
	for _, result := range results {
		if result != nil {
			slog.Debug(result.Error())
			failed += 1
		}
	}

	signatures := iterations * len(resultChannels)
	if correct.Load()+tpmFail.Load() != uint64(signatures) {
		return fmt.Errorf("internal error")
	}

	fmt.Println("## TPM SIGNATURE BENCHMARK RUN ##")

	switch k.tPMKey.KeyAlgo() {
	case tpm2.TPMAlgECC:
		fmt.Println("  key type: ECC 256")
	case tpm2.TPMAlgRSA:
		fmt.Println("  key type: RSA 2048")
	}
	fmt.Printf("  Session: %s\n", sessionEncryption)

	fmt.Printf("  Iterations: %d\n", iterations)
	fmt.Printf("  Parallelism: %d\n", len(resultChannels))
	fmt.Printf("  Time elapsed %f seconds\n", elapsed)
	fmt.Printf("  Completed signatures: %d of %d\n", correct.Load(), signatures)
	fmt.Printf("  Signatures/second: %f\n", float64(signatures-failed)/elapsed)
	fmt.Printf("  Average latency: %f seconds\n", elapsed/float64(signatures-failed))

	return nil
}

func Hmac(tpm transport.TPMCloser, iterations int, parallelism int, sessionEncryption SessionEncryption) {
	digest := []byte("12341234123412341234123412341234")

	var srkHandle *tpm2.AuthHandle
	var srkPublic *tpm2.TPMTPublic
	var err error
	if sessionEncryption == SessionEncryptionReuse || sessionEncryption == SessionEncryptionEphemeral {
		srkHandle, srkPublic, err = createSRK(tpm)
		if err != nil {
			slog.Debug("failed creating SRK: %v", err)
		}
		defer flushHandle(tpm, srkHandle)
	}

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
							&tpm2.TPMSSchemeHMAC{
								HashAlg: tpm2.TPMAlgSHA256,
							}),
					},
				}),
		}),
	}

	primaryResponse, err := createPrimary.Execute(tpm)
	if err != nil {
		slog.Debug(err.Error())
	}

	flushContext := tpm2.FlushContext{FlushHandle: primaryResponse.ObjectHandle}
	defer func() {
		_, _ = flushContext.Execute(tpm)
	}()

	var correct atomic.Uint64
	var tpmFail atomic.Uint64
	var duration atomic.Int64

	var reusedSession tpm2.Session
	var reusedSessionCloser func() error = nil

	if sessionEncryption == SessionEncryptionReuse {
		reusedSession, reusedSessionCloser, err = tpm2.HMACSession(tpm, tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic))
		if err != nil {
			slog.Debug("%s", err)
		}
	}

	hmacFunction := func() error {
		start := time.Now()

		hmac := tpm2.Hmac{
			Handle: tpm2.AuthHandle{
				Handle: primaryResponse.ObjectHandle,
				Name:   primaryResponse.Name,
				Auth:   tpm2.PasswordAuth(nil),
			},
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: digest,
			},
			HashAlg: tpm2.TPMAlgSHA256,
		}

		var hmacResponse *tpm2.HmacResponse
		var err error

		switch sessionEncryption {
		case SessionEncryptionNone:
			hmacResponse, err = hmac.Execute(tpm)
		case SessionEncryptionEphemeral:
			session := tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Salted(srkHandle.Handle, *srkPublic))
			hmacResponse, err = hmac.Execute(tpm, session)
		case SessionEncryptionReuse:
			hmacResponse, err = hmac.Execute(tpm, reusedSession)
		default:
			return fmt.Errorf("unsupported sessionEncryption")
		}

		if err != nil {
			tpmFail.Add(1)
			return fmt.Errorf("failed to hmac: %v", err)
		}

		_ = hmacResponse.OutHmac
		correct.Add(1)
		duration.Add(time.Since(start).Microseconds())

		return nil
	}

	var results []error
	resultChannels := make([]chan error, parallelism)
	for i := 0; i < iterations; i++ {
		for j := 0; j < parallelism; j++ {
			resultChannels[j] = make(chan error)

			k := j
			go func() {
				resultChannels[k] <- hmacFunction()
			}()
		}
		for j := 0; j < len(resultChannels); j++ {
			results = append(results, <-resultChannels[j])
		}
	}

	if uint64(iterations) != tpmFail.Load()+correct.Load() {
		slog.Debug("internal error")
	}

	if reusedSessionCloser != nil {
		err = reusedSessionCloser()
		if err != nil {
			slog.Debug("%s", err)
		}
	}

	elapsed := float64(duration.Load()) / 1000000.0
	hmacs := iterations * len(resultChannels)

	fmt.Println("## TPM HMAC BENCHMARK RUN ##")

	fmt.Println("  HASH: SHA256")
	fmt.Printf("  Session: %s\n", sessionEncryption)

	fmt.Printf("  Iterations: %d\n", iterations)
	fmt.Printf("  Parallelism: %d\n", len(resultChannels))
	fmt.Printf("  Time elapsed %f seconds\n", elapsed)
	fmt.Printf("  Completed HMACs: %d of %d\n", correct.Load(), hmacs)
	fmt.Printf("  HMACs/second: %f\n", float64(correct.Load())/elapsed)
	fmt.Printf("  Average latency: %f seconds\n", elapsed/float64(correct.Load()))
}

type tPMKey struct {
	emptyAuth   bool
	policy      []*tPMPolicy
	secret      []byte
	authPolicy  []*tPMAuthPolicy
	description string
	Parent      tpm2.TPMHandle
	Pubkey      tpm2.TPMTPublic
	Privkey     tpm2.TPM2BPrivate
}

func (t *tPMKey) KeyAlgo() tpm2.TPMAlgID {
	return t.Pubkey.Type
}

func (t *tPMKey) SetDescription(s string) {
	t.description = s
}

type tPMPolicy struct {
	commandCode   int
	commandPolicy []byte
}

type tPMAuthPolicy struct {
	name   string
	policy []*tPMPolicy
}

type key struct {
	*tPMKey
}

func newLoadableKey(public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate, parent tpm2.TPMHandle, emptyAuth bool) (*tPMKey, error) {
	var key tPMKey
	key.emptyAuth = emptyAuth

	pub, err := public.Contents()
	if err != nil {
		return nil, err
	}
	key.Pubkey = *pub
	key.Privkey = private

	key.Parent = parent

	return &key, nil
}

func createSRK(tpm transport.TPMCloser) (*tpm2.AuthHandle, *tpm2.TPMTPublic, error) {
	srk := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(nil),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	var rsp *tpm2.CreatePrimaryResponse
	rsp, err := srk.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating primary key: %v", err)
	}

	srkPublic, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting srk public content: %v", err)
	}

	return &tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, srkPublic, nil
}

func loadKeyWithParent(tpm transport.TPMCloser, parent tpm2.AuthHandle, key *key) (*tpm2.AuthHandle, error) {
	loadBlobCmd := tpm2.Load{
		ParentHandle: parent,
		InPrivate:    key.tPMKey.Privkey,
		InPublic:     tpm2.New2B(key.tPMKey.Pubkey),
	}
	loadBlobRsp, err := loadBlobCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed getting handle: %v", err)
	}

	// Return a AuthHandle with a nil PasswordAuth
	return &tpm2.AuthHandle{
		Handle: loadBlobRsp.ObjectHandle,
		Name:   loadBlobRsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}, nil
}

func createECCKey(ecc tpm2.TPMECCCurve, sha tpm2.TPMAlgID) tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic] {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: sha,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: ecc,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
	})
}

func createRSAKey(bits tpm2.TPMKeyBits, sha tpm2.TPMAlgID) tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic] {
	return tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: sha,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: bits,
			},
		),
	})
}

// shadow the unexported interface from go-tpm
type handle interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}

// Helper to flush handles
func flushHandle(tpm transport.TPM, h handle) {
	flushSrk := tpm2.FlushContext{FlushHandle: h}
	flushSrk.Execute(tpm)
}

func createKey(tpm transport.TPMCloser, keytype tpm2.TPMAlgID) (*key, error) {
	comment := ""

	srkHandle, srkPublic, err := createSRK(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed creating SRK: %v", err)
	}

	var keyPublic tpm2.TPM2BPublic
	switch keytype {
	case tpm2.TPMAlgECC:
		keyPublic = createECCKey(tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	case tpm2.TPMAlgRSA:
		keyPublic = createRSAKey(2048, tpm2.TPMAlgSHA256)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	defer flushHandle(tpm, srkHandle)

	// Template for en ECC key for signing
	createKey := tpm2.Create{
		ParentHandle: srkHandle,
		InPublic:     keyPublic,
	}

	emptyAuth := true

	var createRsp *tpm2.CreateResponse
	createRsp, err = createKey.Execute(tpm,
		tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.AESEncryption(128, tpm2.EncryptIn),
			tpm2.Salted(srkHandle.Handle, *srkPublic)))
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM key: %v", err)
	}

	tpmkey, err := newLoadableKey(createRsp.OutPublic, createRsp.OutPrivate, srkHandle.Handle, emptyAuth)
	if err != nil {
		return nil, err
	}

	tpmkey.SetDescription(comment)

	return &key{tpmkey}, nil
}

func newECCSigScheme(digest tpm2.TPMAlgID) tpm2.TPMTSigScheme {
	return tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgECDSA,
		Details: tpm2.NewTPMUSigScheme(
			tpm2.TPMAlgECDSA,
			&tpm2.TPMSSchemeHash{
				HashAlg: digest,
			},
		),
	}
}

func newRSASigScheme(digest tpm2.TPMAlgID) tpm2.TPMTSigScheme {
	return tpm2.TPMTSigScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUSigScheme(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSchemeHash{
				HashAlg: digest,
			},
		),
	}
}
