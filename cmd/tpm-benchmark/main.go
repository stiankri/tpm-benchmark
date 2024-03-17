package main

import (
	"flag"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stiankri/tpm-benchmark/benchmark"
	"log"
	"log/slog"
	"os"
)

const usage = `Usage:
    tpm-benchmark [OPTIONS]

Options:
    --all                   Run all algorithms (ECC 256, RSA 2048 and HMAC) and
                            all session encryption (none, reuse, ephemeral).

    -a ALGORITHM            Choose 'ecc' for 256 bit ECDSA, 'rsa' for 2048 
                            bit RSASSA signature or 'hmac' for SHA256 HMAC.

    -e SESSION_ENCRYPTION   Choose 'none', 'reuse' (same session for all
                            signature calls to the TPM) or 'ephemeral' session
                            encryption.

    -p PARALLELISM          Dispatch TPM commands in parallel. Calls that fail
                            are tracked, and error messages can be displayed
                            with '-d'.

tpm-benchmark is a tool to figure out how fast TPMs can sign a 32 byte message.

Run default with ECC 256 and no session encryption
    $ tpm-benchmark

Run all tests with parallelism 1
    $ tpm-benchmark --all

Run RSA 2048 with session encryption reuse
    $ tpm-benchmark -s rsa -e reuse

Run all tests with 10 iterations and parallelism 2 and debug logs
    $ tpm-benchmark -a -i 10 -p 2 -d`

func main() {
	tpm, err := transport.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()

	flag.Usage = func() {
		fmt.Println(usage)
	}

	var (
		allFlag, debugMode                    bool
		algorithm, sessionEncryptionAlgorithm string
		parallelism, iterations               int
	)

	flag.BoolVar(&allFlag, "all", false, "Run all signatures and all session encryption benchmark")
	flag.StringVar(&algorithm, "a", "", "Algorithm 'ecc', 'rsa' or 'hmac'")
	flag.StringVar(&sessionEncryptionAlgorithm, "e", "", "Session encryption 'none', 'reuse', 'ephemeral'")
	flag.IntVar(&parallelism, "p", 1, "Parallelism 1,2,...,10")
	flag.IntVar(&iterations, "i", 30, "Iterations 1,2,...,100")
	flag.BoolVar(&debugMode, "d", false, "debug mode")
	flag.Parse()

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if debugMode {
		opts.Level = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))

	slog.SetDefault(logger)

	if allFlag && (algorithm != "" || sessionEncryptionAlgorithm != "") {
		flag.Usage()
		os.Exit(1)
	}

	signatureAlgorithm := tpm2.TPMAlgECC
	hmac := false
	if algorithm != "" {
		if algorithm != "rsa" && algorithm != "ecc" && algorithm != "hmac" {
			flag.Usage()
			os.Exit(1)
		} else {
			switch algorithm {
			case "ecc":
				signatureAlgorithm = tpm2.TPMAlgECC
			case "rsa":
				signatureAlgorithm = tpm2.TPMAlgRSA
			case "hmac":
				hmac = true
			}
		}
	}

	sessionEncryption := benchmark.SessionEncryptionNone
	if sessionEncryptionAlgorithm != "" {
		if sessionEncryptionAlgorithm != "none" && sessionEncryptionAlgorithm != "reuse" && sessionEncryptionAlgorithm != "ephemeral" {
			flag.Usage()
			os.Exit(1)
		} else {
			switch sessionEncryptionAlgorithm {
			case "none":
				sessionEncryption = benchmark.SessionEncryptionNone
			case "reuse":
				sessionEncryption = benchmark.SessionEncryptionReuse
			case "ephemeral":
				sessionEncryption = benchmark.SessionEncryptionEphemeral
			}
		}
	}

	if parallelism < 1 || parallelism > 10 {
		flag.Usage()
		os.Exit(1)
	}

	if iterations < 1 || parallelism > 100 {
		flag.Usage()
		os.Exit(1)
	}

	if allFlag {
		allTpmAlgs := []tpm2.TPMAlgID{tpm2.TPMAlgECC, tpm2.TPMAlgRSA}
		allSessionEncryptions := []benchmark.SessionEncryption{benchmark.SessionEncryptionNone, benchmark.SessionEncryptionReuse, benchmark.SessionEncryptionEphemeral}

		var signatureAlgorithm tpm2.TPMAlgID
		for _, sessionEncryption = range allSessionEncryptions {
			for _, signatureAlgorithm = range allTpmAlgs {
				benchmark.Benchmark(tpm, signatureAlgorithm, iterations, parallelism, sessionEncryption)
			}

			benchmark.HmacBenchmark(tpm, iterations, parallelism, sessionEncryption)
		}
	} else {
		if hmac {
			benchmark.HmacBenchmark(tpm, iterations, parallelism, sessionEncryption)
		} else {
			benchmark.Benchmark(tpm, signatureAlgorithm, iterations, parallelism, sessionEncryption)
		}
	}
}
