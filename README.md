# sigspy

A command-line tool to extract and parse certificate extensions from Sigstore-signed certificates.

## Overview

Sigspy reads certificate data from stdin and outputs parsed Fulcio certificate extensions as JSON. It's designed to help inspect and understand the claims embedded in Sigstore certificates used for software supply chain security.

## Installation

### Using Go

```bash
go install github.com/actionutils/sigspy@latest
```

### Download Binary

Download pre-built binaries from the [releases page](https://github.com/actionutils/sigspy/releases).

### Build from Source

```bash
git clone https://github.com/actionutils/sigspy.git
cd sigspy
go build -o sigspy main.go
```

## Usage

```bash
sigspy -input-format=<format> < certificate_file
```

### Input Formats

- **pkcs7** (default): For Git signatures and signed messages
- **der**: Raw binary certificate format
- **pem**: Base64-encoded certificate format

### Examples

#### Parse a gitsign signature

```bash
git cat-file tag v1.0.0 | sed -n '/-BEGIN/, /-END/p' | sed 's/^ //g' | sed 's/gpgsig //g' | sigspy -input-format=pkcs7 | jq .
```

#### Parse a PEM certificate

```bash
cat certificate.pem | sigspy -input-format=pem | jq .
```

#### Parse a DER certificate

```bash
cat certificate.der | sigspy -input-format=der | jq .
```

#### Parse GitHub attestation certificate

```bash
gh attestation verify artifact.txt --owner myorg --format json | \
  jq -r '.[0].attestation.bundle.verificationMaterial.certificate.rawBytes' | \
  base64 -d | \
  sigspy -input-format=der | jq .
```

## Output

Sigspy outputs JSON containing the parsed Fulcio certificate extensions, which may include:

- Build signer URI
- Build signer digest
- Runner environment
- Source repository URI
- Source repository digest
- Source repository ref
- Source repository identifier
- Source repository owner URI
- Source repository owner identifier
- Build config URI
- Build config digest
- Build trigger
- Run invocation URI
- Issuer (V2)

## Use Cases

- **Inspect gitsign signatures**: Understand the identity claims in Git commit/tag signatures
- **Verify GitHub Actions attestations**: Extract build provenance from GitHub-generated attestations
- **Debug Sigstore certificates**: Troubleshoot issues with Fulcio-issued certificates
- **Audit software supply chain**: Analyze the build metadata in signed artifacts

## Requirements

- Go 1.24.2 or later (for building)
- No runtime dependencies (static binary)

## License

[Add license information here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.