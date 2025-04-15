package main

import (
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/smallstep/pkcs7"
)

func main() {
	// Read signed message from standard input
	signedData, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Failed to read from stdin: %v", err)
	}

	// Convert "SIGNED MESSAGE" to "PKCS7" if needed
	pemContent := string(signedData)
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
	cert := p7.Certificates[0]

	// Parse certificate extensions using fulcio's certificate package
	extensions, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil {
		log.Fatalf("Failed to parse certificate extensions: %v", err)
	}

	if err := json.NewEncoder(os.Stdout).Encode(extensions); err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
}
