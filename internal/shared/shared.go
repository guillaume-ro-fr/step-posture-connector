package shared

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"
)

var LoggingLevel int

// ValidateCSR checks the DER encoded certificate request supplied by step-ca in
// the raw field of webhook.RequestBody.X509CertificateRequest to ensure that it can
// be successfully parsed and passes very simple tests.
// For valid requests it returns the common name, and for invalid ones it returns an error.
func ValidateCSR(der []byte) (string, error) {
	parsedCsr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate request data")
	}
	WriteLog(fmt.Sprintf("Parsed CSR subject for validation: %+v", parsedCsr.Subject), 2, 0)
	if parsedCsr.Subject.CommonName == "" {
		return "", fmt.Errorf("certificate request common name is empty")
	}
	return parsedCsr.Subject.CommonName, nil
}

// ValidatePEM checks a PEM certificate block to ensure that it can be
// successfully decoded, passes very simple tests and is current.
// For valid PEMs it returns the common name, and for invalid PEMs it returns an error.
func ValidatePEM(raw string) (string, error) {
	pemBlock, _ := pem.Decode([]byte(raw))
	if pemBlock == nil {
		return "", fmt.Errorf("failed to decode PEM data")
	}
	parsedPem, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate data")
	}
	WriteLog(fmt.Sprintf("Parsed PEM for validation: %+v", parsedPem), 2, 0)
	if parsedPem.Subject.CommonName == "" {
		return "", fmt.Errorf("certificate common name is empty")
	}
	if parsedPem.NotAfter.Before(time.Now()) {
		return "", fmt.Errorf("certificate has expired")
	}
	if parsedPem.NotBefore.After(time.Now()) {
		return "", fmt.Errorf("certificate not yet valid")
	}
	return parsedPem.Subject.CommonName, nil
}

// ExtractSCEPSerial is a public function that resolves a device identifier out of a SCEP
// CSR subject already decoded by step-ca. It prefers the X.520 serialNumber attribute
// (OID 2.5.4.5), which is the conventional place an MDM places a device serial number in a
// SCEP enrollment subject, and falls back to the common name. It returns an error if
// neither field carries a value.
func ExtractSCEPSerial(serialNumber, commonName string) (string, error) {
	if serialNumber != "" {
		return serialNumber, nil
	}
	if commonName != "" {
		return commonName, nil
	}
	return "", fmt.Errorf("CSR subject carries neither a serialNumber nor a commonName")
}

// ValidateSerial is a public function that checks a device identifier against the format
// providers expect a device serial number to take. It is shared by every provider so that
// both the ACME (attestation) and SCEP (CSR subject) identifier extraction paths apply the
// same rule.
func ValidateSerial(serial string) error {
	if serial == "" {
		return fmt.Errorf("serial number is empty")
	}
	// count runes, not bytes, to match the rune-counted min/max semantics of the
	// go-playground/validator "alphanum,min=8,max=14" rule this replaces
	count := 0
	for _, r := range serial {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') {
			return fmt.Errorf("serial number must be alphanumeric")
		}
		count++
	}
	if count < 8 || count > 14 {
		return fmt.Errorf("serial number must be between 8 and 14 characters")
	}
	return nil
}

// CompareChallenge is a public function that compares a presented SCEP challenge against
// the expected value in constant time, to avoid leaking timing information about a secret
// challenge value.
func CompareChallenge(presented, expected string) bool {
	if presented == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

// WriteLog is a shared logging function that can be used right across the project.
// It supports writing to stdout using multiple colors and takes a verbosity level
// Some colors that can be used are 31-Red, 32-Green, 33-Yellow, 36-Aqua
func WriteLog(content string, level int, color int) {
	if LoggingLevel >= level {
		if color > 0 {
			log.Println(fmt.Sprintf("\x1b[%dm%s\x1b[0m", color, content))
		} else {
			log.Println(content)
		}
	}
}
