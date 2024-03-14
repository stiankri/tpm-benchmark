package main

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stiankri/tpm-benchmark/benchmark"
	"log"
)

func main() {
	tpm, err := transport.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()

	tpmAlgorithms := []tpm2.TPMAlgID{tpm2.TPMAlgECC, tpm2.TPMAlgRSA}
	sessionEncryptions := []benchmark.SessionEncryption{benchmark.SessionEncryptionNone}

	var (
		sessionEncryption  benchmark.SessionEncryption
		signatureAlgorithm tpm2.TPMAlgID
	)

	iterations := 30
	parallelism := 1

	for _, sessionEncryption = range sessionEncryptions {
		for _, signatureAlgorithm = range tpmAlgorithms {
			benchmark.Benchmark(tpm, signatureAlgorithm, iterations, parallelism, sessionEncryption)
		}
	}
}
