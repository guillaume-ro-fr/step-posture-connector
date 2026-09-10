package shared

import (
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
	WriteLog(fmt.Sprintf("Parsed CSR for validation: %+v", parsedCsr), 2, 0)
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
