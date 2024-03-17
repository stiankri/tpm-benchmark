package benchmark

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"log"
	"log/slog"
)

func Example() {
	tpm, err := transport.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()

	tpmAlgorithms := []tpm2.TPMAlgID{tpm2.TPMAlgECC, tpm2.TPMAlgRSA}
	sessionEncryptions := []SessionEncryption{SessionEncryptionNone}

	var (
		sessionEncryption  SessionEncryption
		signatureAlgorithm tpm2.TPMAlgID
	)

	iterations := 30
	parallelism := 1

	for _, sessionEncryption = range sessionEncryptions {
		for _, signatureAlgorithm = range tpmAlgorithms {
			err := Signature(tpm, signatureAlgorithm, iterations, parallelism, sessionEncryption)
			if err != nil {
				slog.Debug(err.Error())
			}
		}

		Hmac(tpm, iterations, parallelism, sessionEncryption)
	}
}
