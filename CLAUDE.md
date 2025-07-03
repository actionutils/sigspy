# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sigspy is a command-line tool that extracts and parses certificate extensions from Sigstore-signed certificates. It reads certificate data from stdin and outputs parsed Fulcio certificate extensions as JSON.

## Commands

### Build
```bash
# Standard build
go build -v -o sigspy main.go

# Build for release (multiple platforms)
goreleaser build --snapshot --clean
```

### Test
The project uses example-based testing. Run these commands to test functionality:
```bash
# Test with gitsign example (PKCS7 format)
git cat-file tag v1.0.0 | sed -n '/-BEGIN/, /-END/p' | sed 's/^ //g' | sed 's/gpgsig //g' | ./sigspy -input-format=pkcs7 | jq -S .

# Test with PEM certificate
curl -sL https://github.com/actionutils/sigspy/releases/download/v1.0.0/checksums.txt.pem | base64 -d | ./sigspy -input-format=pem | jq -S .

# Test with DER certificate (requires GH_TOKEN env var)
gh attestation verify checksums.txt --owner actionutils --format json | jq -r '.[0].attestation.bundle.verificationMaterial.certificate.rawBytes' | base64 -d | ./sigspy -input-format=der | jq -S .
```

### Development
```bash
# Run directly without building
go run main.go -input-format=pkcs7 < input.pem

# Install dependencies
go mod download
```

## Architecture

This is a single-file CLI application (`main.go`) with minimal dependencies:
- **Input**: Reads certificate data from stdin
- **Processing**: Parses certificates based on format flag (pkcs7/der/pem)
- **Output**: JSON representation of Fulcio certificate extensions to stdout

The application supports three input formats:
1. **PKCS7** (default): For Git signatures and signed messages
2. **DER**: Raw binary certificate format
3. **PEM**: Base64-encoded certificate format

## Key Dependencies
- `github.com/sigstore/fulcio`: Parses Sigstore certificate extensions
- `github.com/smallstep/pkcs7`: Handles PKCS7 signature parsing

## Release Process

Releases are automated via GitHub Actions:
1. Push to main branch triggers release workflow
2. Uses `actionutils/trusted-go-releaser` with environment protection
3. Creates multi-platform binaries, SBOMs, and signed artifacts
4. All releases are signed with Cosign

## Testing Approach

The project doesn't have traditional unit tests. Instead, it uses real-world examples in CI to verify functionality against actual Sigstore signatures. The test workflow (`test.yml`) runs three example scenarios covering all supported input formats.