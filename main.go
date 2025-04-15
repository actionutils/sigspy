package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/smallstep/pkcs7"
)

func main() {
	// Define command-line flags
	inputFormat := flag.String("input-format", "pkcs7", "Input format: pkcs7, der, pem")
	flag.Parse()

	// Read data from standard input
	inputData, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Failed to read from stdin: %v", err)
	}

	var cert *x509.Certificate

	// Process based on input format
	switch *inputFormat {
	case "der":
		// Parse binary DER certificate data directly
		cert, err = x509.ParseCertificate(inputData)
		if err != nil {
			log.Fatalf("Failed to parse DER certificate: %v", err)
		}

	case "pem":
		// Decode PEM block expecting a certificate
		block, _ := pem.Decode(inputData)
		if block == nil {
			log.Fatal("Failed to decode PEM block")
		}
		if block.Type != "CERTIFICATE" {
			log.Fatalf("Expected PEM type 'CERTIFICATE', got '%s'", block.Type)
		}

		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse certificate from PEM: %v", err)
		}

	case "pkcs7":
		// Convert "SIGNED MESSAGE" to "PKCS7" if needed
		pemContent := string(inputData)
		pemContent = strings.ReplaceAll(pemContent, "SIGNED MESSAGE", "PKCS7")

		// Decode PEM block
		block, _ := pem.Decode([]byte(pemContent))
		if block == nil {
			log.Fatal("Failed to decode PEM block")
		}

		// Parse PKCS7 data
		p7, err := pkcs7.Parse(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse PKCS7 data: %v", err)
		}

		// Get certificates from PKCS7
		if len(p7.Certificates) == 0 {
			log.Fatal("No certificates found in PKCS7 data")
		}

		// Use the first certificate (signer's certificate)
		cert = p7.Certificates[0]

	default:
		log.Fatalf("Unknown input format: %s. Supported formats: pkcs7, der, pem", *inputFormat)
	}

	// Parse certificate extensions using fulcio's certificate package
	extensions, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil {
		log.Fatalf("Failed to parse certificate extensions: %v", err)
	}

	if err := json.NewEncoder(os.Stdout).Encode(extensions); err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
}
