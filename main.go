package main

import (
    "crypto/sha256"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "encoding/pem"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "math/big"
    "os"
    "strings"
    "time"

    "github.com/sigstore/fulcio/pkg/certificate"
    "github.com/smallstep/pkcs7"
    protov1 "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/encoding/protojson"
    rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
)

// Output structures kept simple and forward-extensible
type Output struct {
    Version     string           `json:"version"`
    Input       InputMeta        `json:"input"`
    Certificate *CertSummary     `json:"certificate,omitempty"`
    Fulcio      any              `json:"fulcio_extensions,omitempty"`
    CMS         *CMSSummary      `json:"cms,omitempty"`
    Rekor       *RekorSummary    `json:"rekor,omitempty"`
}

type InputMeta struct {
    Format string `json:"format"`
}

type CertSummary struct {
    Subject       Name   `json:"subject"`
    Issuer        Name   `json:"issuer"`
    SerialNumber  string `json:"serialNumberHex"`
    NotBefore     string `json:"notBefore"`
    NotAfter      string `json:"notAfter"`
    Fingerprint   string `json:"sha256FingerprintHex"`
    PublicKeyAlgo string `json:"publicKeyAlgorithm"`
    PublicKeySize int    `json:"publicKeySizeBits,omitempty"`
    SANs          SANs   `json:"sans,omitempty"`
}

type Name struct {
    CommonName         string            `json:"commonName,omitempty"`
    Organization       []string          `json:"organization,omitempty"`
    OrganizationalUnit []string          `json:"organizationalUnit,omitempty"`
    Country            []string          `json:"country,omitempty"`
    Province           []string          `json:"province,omitempty"`
    Locality           []string          `json:"locality,omitempty"`
    ExtraNames         map[string]string `json:"extraNames,omitempty"`
}

type SANs struct {
    DNS   []string `json:"dns,omitempty"`
    Email []string `json:"email,omitempty"`
    URI   []string `json:"uri,omitempty"`
    IP    []string `json:"ip,omitempty"`
}

type CMSSummary struct {
    HasSignedAttributes bool   `json:"hasSignedAttributes"`
    SignedAttrsDER      string `json:"signedAttributesDERBase64,omitempty"`
    SignedAttrsSHA256   string `json:"signedAttributesSHA256Hex,omitempty"`
    SignatureAlgorithm  string `json:"signatureAlgorithm,omitempty"`
    Signature           string `json:"signatureBase64,omitempty"`
}

type RekorSummary struct {
    Present  bool            `json:"present"`
    OID      string          `json:"oid"`
    Entry    json.RawMessage `json:"transparencyLogEntry,omitempty"`
    Error    string          `json:"error,omitempty"`
}

// Helper to summarize x509.Name
func summarizeName(n pkix.Name) Name {
    m := map[string]string{}
    for _, atv := range n.ExtraNames {
        oid := atv.Type.String()
        if s, ok := atv.Value.(string); ok {
            m[oid] = s
        }
    }
    return Name{
        CommonName:         n.CommonName,
        Organization:       n.Organization,
        OrganizationalUnit: n.OrganizationalUnit,
        Country:            n.Country,
        Province:           n.Province,
        Locality:           n.Locality,
        ExtraNames:         m,
    }
}

// PEM or DER decoder for certificate input
func parseCertFromPEMOrDER(data []byte) (*x509.Certificate, error) {
    // Try PEM
    if b, _ := pem.Decode(data); b != nil {
        if b.Type != "CERTIFICATE" {
            return nil, fmt.Errorf("expected PEM CERTIFICATE, got %s", b.Type)
        }
        return x509.ParseCertificate(b.Bytes)
    }
    // Try DER
    return x509.ParseCertificate(data)
}

func summarizeCert(cert *x509.Certificate) *CertSummary {
    if cert == nil {
        return nil
    }
    fp := sha256.Sum256(cert.Raw)
    // SANs
    var ips []string
    for _, ip := range cert.IPAddresses {
        ips = append(ips, ip.String())
    }
    var uris []string
    for _, u := range cert.URIs {
        uris = append(uris, u.String())
    }
    return &CertSummary{
        Subject:       summarizeName(cert.Subject),
        Issuer:        summarizeName(cert.Issuer),
        SerialNumber:  strings.ToUpper(cert.SerialNumber.Text(16)),
        NotBefore:     cert.NotBefore.UTC().Format(time.RFC3339),
        NotAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
        Fingerprint:   strings.ToUpper(hex.EncodeToString(fp[:])),
        PublicKeyAlgo: cert.PublicKeyAlgorithm.String(),
        PublicKeySize: 0,
        SANs: SANs{
            DNS:   cert.DNSNames,
            Email: cert.EmailAddresses,
            URI:   uris,
            IP:    ips,
        },
    }
}

// signerMatch checks serial and issuer raw bytes
func signerMatch(cert *x509.Certificate, issuerName asn1.RawValue, serial *big.Int) bool {
    if cert == nil || serial == nil {
        return false
    }
    if cert.SerialNumber.Cmp(serial) != 0 {
        return false
    }
    return asn1Equal(cert.RawIssuer, issuerName.FullBytes)
}

func asn1Equal(a, b []byte) bool { return len(a) == len(b) && (len(a) == 0 || string(a) == string(b)) }

// Convert smallstep/pkcs7 attribute slice to a marshable copy we control
type ourAttribute struct {
    Type  asn1.ObjectIdentifier
    Value asn1.RawValue `asn1:"set"`
}

// extract CMS/SignedAttrs/Rekor from a PKCS7 structure
func extractFromPKCS7(p7 *pkcs7.PKCS7) (*x509.Certificate, *CMSSummary, *RekorSummary, error) {
    if len(p7.Signers) == 0 {
        return nil, nil, nil, fmt.Errorf("no signers in PKCS7 data")
    }
    s := p7.Signers[0]

    // Select signer certificate by Issuer+Serial match; fallback to GetOnlySigner/first cert
    var signerCert *x509.Certificate
    for _, c := range p7.Certificates {
        if signerMatch(c, s.IssuerAndSerialNumber.IssuerName, s.IssuerAndSerialNumber.SerialNumber) {
            signerCert = c
            break
        }
    }
    if signerCert == nil {
        signerCert = p7.GetOnlySigner()
        if signerCert == nil && len(p7.Certificates) > 0 {
            signerCert = p7.Certificates[0]
        }
    }

    cms := &CMSSummary{}
    if len(s.AuthenticatedAttributes) > 0 {
        conv := make([]ourAttribute, 0, len(s.AuthenticatedAttributes))
        for _, a := range s.AuthenticatedAttributes {
            conv = append(conv, ourAttribute{Type: a.Type, Value: a.Value})
        }
        type container struct{ A []ourAttribute `asn1:"set"` }
        if enc, err := asn1.Marshal(container{A: conv}); err == nil {
            var raw asn1.RawValue
            _, _ = asn1.Unmarshal(enc, &raw)
            cms.HasSignedAttributes = true
            cms.SignedAttrsDER = base64.StdEncoding.EncodeToString(raw.Bytes)
            sum := sha256.Sum256(raw.Bytes)
            cms.SignedAttrsSHA256 = strings.ToUpper(hex.EncodeToString(sum[:]))
        }
    }
    if len(s.EncryptedDigest) > 0 {
        cms.Signature = base64.StdEncoding.EncodeToString(s.EncryptedDigest)
    }
    cms.SignatureAlgorithm = s.DigestEncryptionAlgorithm.Algorithm.String()

    // Rekor proto in unauthenticated attributes
    var rekor *RekorSummary
    const rekorOID = "1.3.6.1.4.1.57264.3.1"
    for _, a := range s.UnauthenticatedAttributes {
        if a.Type.String() == rekorOID {
            var embedded []byte
            if _, err := asn1.Unmarshal(a.Value.Bytes, &embedded); err == nil {
                pb := new(rekorpb.TransparencyLogEntry)
                if err := protov1.Unmarshal(embedded, pb); err == nil {
                    opts := protojson.MarshalOptions{EmitUnpopulated: false, UseProtoNames: true}
                    if jb, err := opts.Marshal(pb); err == nil {
                        rekor = &RekorSummary{Present: true, OID: rekorOID, Entry: json.RawMessage(jb)}
                    } else {
                        rekor = &RekorSummary{Present: true, OID: rekorOID, Error: err.Error()}
                    }
                } else {
                    rekor = &RekorSummary{Present: true, OID: rekorOID, Error: err.Error()}
                }
            } else {
                rekor = &RekorSummary{Present: true, OID: rekorOID, Error: err.Error()}
            }
            break
        }
    }
    if rekor == nil {
        rekor = &RekorSummary{Present: false, OID: rekorOID}
    }

    return signerCert, cms, rekor, nil
}

func extractFromPKCS7DER(der []byte) (*x509.Certificate, *CMSSummary, *RekorSummary, error) {
    p7, err := pkcs7.Parse(der)
    if err != nil {
        return nil, nil, nil, err
    }
    return extractFromPKCS7(p7)
}

func detectAndParse(data []byte, mode string) (*x509.Certificate, *CMSSummary, *RekorSummary, error) {
    switch mode {
    case "auto":
        if b, _ := pem.Decode(data); b != nil {
            t := strings.ToUpper(strings.TrimSpace(b.Type))
            switch t {
            case "CERTIFICATE":
                cert, err := x509.ParseCertificate(b.Bytes)
                if err != nil { return nil, nil, nil, err }
                return cert, nil, nil, nil
            case "PKCS7", "SIGNED MESSAGE":
                return extractFromPKCS7DER(b.Bytes)
            default:
                // Try PKCS7, then certificate
                if cert, cms, rekor, err := extractFromPKCS7DER(b.Bytes); err == nil {
                    return cert, cms, rekor, nil
                }
                if cert, err := x509.ParseCertificate(b.Bytes); err == nil {
                    return cert, nil, nil, nil
                }
                return nil, nil, nil, fmt.Errorf("unsupported PEM block: %s", b.Type)
            }
        }
        // No PEM armor: try PKCS7 DER then cert DER
        if cert, cms, rekor, err := extractFromPKCS7DER(data); err == nil {
            return cert, cms, rekor, nil
        }
        if cert, err := x509.ParseCertificate(data); err == nil { return cert, nil, nil, nil }
        return nil, nil, nil, errors.New("failed to auto-detect input (not PKCS7 nor certificate)")
    case "pkcs7":
        // Accept PEM or DER
        pemContent := string(data)
        pemContent = strings.ReplaceAll(pemContent, "SIGNED MESSAGE", "PKCS7")
        if b, _ := pem.Decode([]byte(pemContent)); b != nil {
            return extractFromPKCS7DER(b.Bytes)
        }
        return extractFromPKCS7DER(data)
    case "der":
        cert, err := x509.ParseCertificate(data)
        return cert, nil, nil, err
    case "pem":
        cert, err := parseCertFromPEMOrDER(data)
        return cert, nil, nil, err
    default:
        return nil, nil, nil, fmt.Errorf("unknown input format: %s", mode)
    }
}

func main() {
    inputFormat := flag.String("input-format", "auto", "Input format: auto, pkcs7, der, pem")
    pretty := flag.Bool("pretty", false, "Pretty-print JSON output")
    flag.Parse()

    // Read all stdin
    inputData, err := io.ReadAll(os.Stdin)
    if err != nil {
        log.Fatalf("Failed to read from stdin: %v", err)
    }

    out := Output{Version: "1", Input: InputMeta{Format: *inputFormat}}

    cert, cms, rekor, err := detectAndParse(inputData, *inputFormat)
    if err != nil {
        log.Fatalf("Failed to parse input: %v", err)
    }

    if cert != nil {
        out.Certificate = summarizeCert(cert)
        // Parse Fulcio extensions
        if ext, err := certificate.ParseExtensions(cert.Extensions); err == nil {
            out.Fulcio = ext
        } else {
            out.Fulcio = map[string]any{"error": err.Error()}
        }
    }
    if cms != nil { out.CMS = cms }
    if rekor != nil { out.Rekor = rekor }

    enc := json.NewEncoder(os.Stdout)
    if *pretty {
        enc.SetIndent("", "  ")
    }
    if err := enc.Encode(out); err != nil {
        log.Fatalf("Failed to marshal JSON: %v", err)
    }
}
