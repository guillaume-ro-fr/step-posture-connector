package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/jedda/step-posture-connector/internal/providers/file"
	"github.com/jedda/step-posture-connector/internal/providers/jamf"
	"github.com/jedda/step-posture-connector/internal/providers/mosyle"
	"github.com/jedda/step-posture-connector/internal/shared"
	"github.com/joho/godotenv"
	"github.com/smallstep/certificates/webhook"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const version string = "1.0.0"

var validate *validator.Validate
var provider ProviderInterface
var config map[string]interface{}
var webhooks map[string]string

// ProviderInterface defines the function signatures that a provider must implement
type ProviderInterface interface {
	Bootstrap() error
	Handler(string, webhook.RequestBody) (webhook.ResponseBody, error)
	SCEPHandler(string, webhook.RequestBody) (webhook.ResponseBody, error)
}

// main execution function. validates config and bootstraps provider
// prior to starting HTTPS webhook server
func main() {
	shared.WriteLog(fmt.Sprintf("Step Posture Connector v%s", version), 0, 36)
	shared.WriteLog("by Jedda Wignall <oss@jedda.me>", 0, 36)
	shared.WriteLog("For information & documentation, see https://github.com/jedda/step-posture-connector", 0, 36)

	// instantiate our global validator
	validate = validator.New(validator.WithRequiredStructEnabled())
	// attempt to load environment variables from a .env file
	envErr := godotenv.Load()
	if envErr != nil {
		shared.WriteLog(fmt.Sprintf(".env was not loaded: %s", envErr), 0, 0)
	}
	// read in our config from env variables and validate
	config = map[string]interface{}{
		"LOGGING_LEVEL":   os.Getenv("LOGGING_LEVEL"),
		"PORT":            os.Getenv("PORT"),
		"PROVIDER":        os.Getenv("PROVIDER"),
		"TLS_CERT_PATH":   os.Getenv("TLS_CERT_PATH"),
		"TLS_KEY_PATH":    os.Getenv("TLS_KEY_PATH"),
		"TLS_CA_PATH":     os.Getenv("TLS_CA_PATH"),
		"ENABLE_MTLS":     os.Getenv("ENABLE_MTLS"),
		"WEBHOOK_IDS":     os.Getenv("WEBHOOK_IDS"),
		"WEBHOOK_SECRETS": os.Getenv("WEBHOOK_SECRETS"),
	}
	configRules := map[string]interface{}{
		"LOGGING_LEVEL":   "omitempty,oneof=0 1 2",
		"PORT":            "omitempty,number",
		"PROVIDER":        "required,oneof=file jamf mosyle",
		"TLS_CERT_PATH":   "required,file",
		"TLS_KEY_PATH":    "required,file",
		"TLS_CA_PATH":     "omitempty,file",
		"ENABLE_MTLS":     "omitempty,oneof=0 1",
		"WEBHOOK_IDS":     "required",
		"WEBHOOK_SECRETS": "required",
	}
	errs := validate.ValidateMap(config, configRules)
	if len(errs) > 0 {
		shared.WriteLog(fmt.Sprintf("Failed to start due to invalid config: %s", errs), 0, 33)
		os.Exit(1)
	}

	// set our LOGGING_LEVEL variable from config
	loggingLevel, ok := config["LOGGING_LEVEL"].(string)
	if ok {
		shared.LoggingLevel, _ = strconv.Atoi(loggingLevel)
	}
	shared.WriteLog("Verbose logging enabled", 1, 0)
	shared.WriteLog("Debug logging enabled", 2, 0)

	// initialise our provider and ensure it complies with ProviderInterface
	providerName := config["PROVIDER"].(string)
	if providerName == "file" {
		provider = file.Provider{}
	} else if providerName == "jamf" {
		provider = jamf.Provider{}
	} else if providerName == "mosyle" {
		provider = mosyle.Provider{}
	}
	_, providerOk := provider.(ProviderInterface)
	if !providerOk {
		shared.WriteLog(fmt.Sprintf("Failed to initialise provider \"%s\".", errs), 1, 33)
		os.Exit(1)
	}

	// bootstrap our provider
	err := provider.Bootstrap()
	if err != nil {
		shared.WriteLog(fmt.Sprintf("Failed to bootstrap provider \"%s\": %s", providerName, err), 0, 33)
		os.Exit(1)
	}

	// put our webhook ids and secrets into a map and initialise our handlers
	ids := strings.Split(config["WEBHOOK_IDS"].(string), ",")
	secrets := strings.Split(config["WEBHOOK_SECRETS"].(string), ",")
	if len(ids) != len(secrets) {
		shared.WriteLog(fmt.Sprintf("Mismatched number of webhook IDs and secrets. Cannot initialise."), 1, 33)
		os.Exit(1)
	}
	webhooks = make(map[string]string)
	for i := range ids {
		idErr := validate.Var(ids[i], "required,uuid")
		secretErr := validate.Var(secrets[i], "required,base64")
		if idErr == nil && secretErr == nil {
			webhooks[ids[i]] = secrets[i]
			// fingerprint only - never the secret itself. Lets a stale/mismatched
			// environment be confirmed by comparing against `printf '%s' '<secret>' | sha256sum`
			// run against the value actually in .env.posture, without ever printing the secret.
			fingerprint := sha256.Sum256([]byte(secrets[i]))
			shared.WriteLog(fmt.Sprintf("Initialised a handler & stored secret for webhook ID %s (secret sha256:%s)", ids[i], hex.EncodeToString(fingerprint[:])), 0, 0)

		} else {
			shared.WriteLog(fmt.Sprintf("Webhook ID or it's secret failed validation: %s, %s, %s", ids[i], idErr, secretErr), 1, 33)
			os.Exit(1)
		}
	}

	http.HandleFunc("/webhook/device-attest", webhookHandlerAttestDevice)
	http.HandleFunc("/webhook/scep-challenge", webhookHandlerSCEPChallenge)

	// configure our TLS settings
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	// are we enabling mutual TLS?
	mtlsConfig, mtlsErr := strconv.ParseBool(config["ENABLE_MTLS"].(string))
	if mtlsErr != nil {
		mtlsConfig = false
	}
	if mtlsConfig {
		caCert, err := os.ReadFile(config["TLS_CA_PATH"].(string))
		if err != nil {
			shared.WriteLog(fmt.Sprintf("Failed to load CA from TLS_CA_PATH: %s", err), 0, 33)
			os.Exit(1)
		}
		caCn, err := shared.ValidatePEM(string(caCert))
		if err != nil {
			shared.WriteLog(fmt.Sprintf("Failed to validate CA for mTLS: %s", err), 0, 33)
			os.Exit(1)
		}
		shared.WriteLog(fmt.Sprintf("Mutual TLS CA loaded: %s", caCn), 1, 0)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		shared.WriteLog(fmt.Sprintf("Mutual TLS enabled"), 0, 0)
	}
	port, ok := config["PORT"].(string)
	if !ok {
		port = "9443" // default port 9443
	}
	server := &http.Server{
		Addr:      fmt.Sprintf(":%s", port),
		TLSConfig: tlsConfig,
	}
	// validate our local server TLS certificate
	caCert, err := os.ReadFile(config["TLS_CERT_PATH"].(string))
	if err != nil {
		shared.WriteLog(fmt.Sprintf("Failed to load local server TLS certificate from %s: %s", config["TLS_CERT_PATH"].(string), err), 0, 33)
		os.Exit(1)
	}
	tlsCn, err := shared.ValidatePEM(string(caCert))
	if err != nil {
		shared.WriteLog(fmt.Sprintf("Failed to validate local server TLS certificate: %s", err), 0, 33)
		os.Exit(1)
	}
	shared.WriteLog(fmt.Sprintf("TLS certificate loaded: %s", tlsCn), 1, 0)
	shared.WriteLog(fmt.Sprintf("Webhook listener starting on port :%s", port), 0, 0)
	if err := server.ListenAndServeTLS(config["TLS_CERT_PATH"].(string), config["TLS_KEY_PATH"].(string)); err != nil {
		shared.WriteLog(fmt.Sprintf("Failed to start webhook server :%d", err), 0, 33)
		os.Exit(1)
	}
}

// webhookHandlerAttestDevice is the route handler for ACME (device-attest-01) requests.
// step-ca must be configured to send this provisioner's AUTHORIZING/ENRICHING webhook here.
func webhookHandlerAttestDevice(w http.ResponseWriter, r *http.Request) {
	processWebhook(w, r, validateACMERequest, provider.Handler, acmeIdentifier)
}

// webhookHandlerSCEPChallenge is the route handler for SCEP challenge validation requests.
// step-ca must be configured to send this provisioner's SCEPCHALLENGE webhook here. Using a
// dedicated route - rather than inferring the request kind from its body - lets step-ca's
// provisioner configuration force which validation path a request takes, instead of the
// connector having to guess.
func webhookHandlerSCEPChallenge(w http.ResponseWriter, r *http.Request) {
	processWebhook(w, r, validateSCEPRequest, provider.SCEPHandler, scepIdentifier)
}

// processWebhook is a private function shared by both webhook routes. it handles
// authentication and validation of the request before handing off to the supplied dispatch
// function, then performs some final error handling before returning the decision to
// step-ca. validate, dispatch and identify are supplied by the calling route handler so
// that each route enforces its own request shape and talks to its own provider method.
func processWebhook(w http.ResponseWriter, r *http.Request, validateFn func(webhook.RequestBody) error, dispatch func(string, webhook.RequestBody) (webhook.ResponseBody, error), identify func(webhook.RequestBody) string) {
	handlerMode := r.URL.Query().Get("mode")
	shared.WriteLog(fmt.Sprintf("Received a new webhook request for %s (mode=%s)", r.URL.Path, handlerMode), 2, 0)
	// authenticate the incoming request using step-ca signature
	body, authErr := authenticateRequest(r)
	if authErr != nil {
		shared.WriteLog(fmt.Sprintf("[DENY] Failed to authenticate request: %s", authErr), 0, 31)
		deny(w, http.StatusUnauthorized)
		return
	}
	// decode the incoming request JSON body into a webhook.RequestBody struct
	var stepInputData webhook.RequestBody
	parseErr := json.NewDecoder(bytes.NewReader(body)).Decode(&stepInputData)
	if parseErr != nil {
		shared.WriteLog(fmt.Sprintf("[DENY] Failed to parse request: %s", parseErr), 0, 31)
		deny(w, http.StatusBadRequest)
		return
	}
	// validate the data prior to processing
	validErr := validateFn(stepInputData)
	if validErr != nil {
		shared.WriteLog(fmt.Sprintf("[DENY] Failed to validate request: %s", validErr), 0, 31)
		deny(w, http.StatusBadRequest)
		return
	}
	// compute an identifier purely for logging purposes - never used for authorization
	// decisions, which remain the provider's responsibility
	identifier := identify(stepInputData)

	// make the request to the provider
	response, err := dispatch(handlerMode, stepInputData)

	// deny the request on any error
	if err != nil {
		shared.WriteLog(fmt.Sprintf("[DENY] %s", err), 0, 31)
		deny(w, http.StatusBadRequest)
		return
	}

	// double check that the request was allowed
	if response.Allow == true {
		responseJSON, err := json.Marshal(response)
		if err != nil {
			shared.WriteLog(fmt.Sprintf("[DENY] Failed to marshal JSON response: %s", err), 0, 31)
			deny(w, http.StatusInternalServerError)
		}
		if response.Data != nil {
			shared.WriteLog(fmt.Sprintf("Returning enrichment data for identifier %s: %s", identifier, string(responseJSON)), 1, 0)
		}
		shared.WriteLog(fmt.Sprintf("[ALLOW] Request was allowed for identifier %s", identifier), 0, 32)
		allow(w, response)
		return
	} else {
		// would be unlikely to get here - denials should come with an error
		// but just in case this ever happens we will return an implicit deny
		shared.WriteLog("[DENY] Request denied.", 0, 31)
		deny(w, http.StatusBadRequest)
		return
	}
}

// validateTimestamp is a private function shared by both request validators. To ensure no
// replay, it checks the request carries a timestamp within the last 10 seconds.
func validateTimestamp(stepInputData webhook.RequestBody) error {
	if stepInputData.Timestamp.IsZero() {
		return fmt.Errorf("received a request without a timestamp")
	}
	if time.Since(stepInputData.Timestamp) > time.Duration(10)*time.Second {
		return fmt.Errorf("request aged over 10 seconds: %s", stepInputData.Timestamp.Format(time.RFC3339))
	}
	return nil
}

// validateACMERequest is a private function that validates an incoming request on the ACME
// webhook route. It performs some checks on the submitted request including validation of
// the attestation identifiers. If validation fails, it returns an error.
func validateACMERequest(stepInputData webhook.RequestBody) error {
	if err := validateTimestamp(stepInputData); err != nil {
		return err
	}
	// a scepTransactionID on this route means step-ca (or its provisioner config) is
	// pointing a SCEPCHALLENGE webhook at the ACME route by mistake
	if stepInputData.SCEPTransactionID != "" {
		return fmt.Errorf("received a scepTransactionID on the ACME webhook route - point this provisioner's SCEPCHALLENGE webhook at /webhook/scep-challenge instead")
	}
	// as step-ca only populates these on an acme device-attest-01 challenge,
	// they are optional pointers and need to be checked before we use them
	if stepInputData.AttestationData == nil {
		return fmt.Errorf("received a request without any attestationData")
	}
	// check to ensure that we have a permanentIdentifier (serial number)
	if stepInputData.AttestationData.PermanentIdentifier == "" {
		return fmt.Errorf("received a request without a permanentIdentifier in attestationData")
	}
	return nil
}

// validateSCEPRequest is a private function that validates an incoming request on the SCEP
// webhook route. It performs some checks on the submitted request including validation of
// the X.509 CSR and SCEP challenge fields. If validation fails, it returns an error.
func validateSCEPRequest(stepInputData webhook.RequestBody) error {
	if err := validateTimestamp(stepInputData); err != nil {
		return err
	}
	// a missing scepTransactionID on this route means step-ca is pointing something other
	// than a SCEPCHALLENGE webhook at it
	if stepInputData.SCEPTransactionID == "" {
		return fmt.Errorf("received a request without a scepTransactionID on the SCEP webhook route - only a provisioner's SCEPCHALLENGE webhook belongs at /webhook/scep-challenge")
	}
	if stepInputData.SCEPChallenge == "" {
		return fmt.Errorf("received a SCEP request without a scepChallenge")
	}
	if stepInputData.X509CertificateRequest == nil || stepInputData.X509CertificateRequest.CertificateRequest == nil {
		return fmt.Errorf("received a SCEP request without a usable x509CertificateRequest")
	}
	return nil
}

// acmeIdentifier is a private function that extracts a device identifier from an ACME
// request, purely for logging purposes.
func acmeIdentifier(stepInputData webhook.RequestBody) string {
	if stepInputData.AttestationData != nil {
		return stepInputData.AttestationData.PermanentIdentifier
	}
	return "(unknown)"
}

// scepIdentifier is a private function that extracts a device identifier from a SCEP
// request's CSR subject, purely for logging purposes.
func scepIdentifier(stepInputData webhook.RequestBody) string {
	if stepInputData.X509CertificateRequest != nil && stepInputData.X509CertificateRequest.CertificateRequest != nil {
		if serial, err := shared.ExtractSCEPSerial(stepInputData.X509CertificateRequest.Subject.SerialNumber, stepInputData.X509CertificateRequest.Subject.CommonName); err == nil {
			return serial
		}
	}
	return "(unknown)"
}

// authenticateRequest is a private function that checks and authenticates an
// incoming webhook request using step-ca's headers and HMAC signature.
// for valid, authenticated hooks it returns a byte slice of the request body,
// and for failures it returns an error
func authenticateRequest(r *http.Request) ([]byte, error) {
	if r.Method != "POST" {
		return nil, fmt.Errorf("ignoring a %s request as we only accept POST", r.Method)
	}
	// check for webhook id in HTTP header X-Smallstep-Webhook-ID
	id := r.Header.Get("X-Smallstep-Webhook-ID")
	if id == "" {
		return nil, fmt.Errorf("missing X-Smallstep-Webhook-ID header")
	}
	// check for signature in HTTP header X-Smallstep-Signature then decode
	rawSig := r.Header.Get("X-Smallstep-Signature")
	if rawSig == "" {
		return nil, fmt.Errorf("missing X-Smallstep-Signature-ID header")
	}
	sig, err := hex.DecodeString(rawSig)
	if err != nil {
		return nil, fmt.Errorf("invalid X-Smallstep-Webhook-ID header: %s", err)
	}
	// get the webhook request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read webhook body: %s", err)
	}
	// look up the signing secret for this webhook ID - an unknown ID must be rejected
	// here, before any HMAC is computed. Without this check, an unrecognised id looks
	// up as the empty string, which base64-decodes to an empty (but valid) key, letting
	// anyone forge a signature for a webhook ID we never configured
	rawSecret, known := webhooks[id]
	if !known {
		return nil, fmt.Errorf("unknown webhook ID %s", id)
	}
	sigSecret, err := base64.StdEncoding.DecodeString(rawSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signing secret for webhook %s: %s", id, err)
	}
	// verify the signed request
	hm := hmac.New(sha256.New, sigSecret)
	hm.Write(body)
	mac := hm.Sum(nil)
	if ok := hmac.Equal(sig, mac); !ok {
		// diagnostic detail only - never the body or secret itself, since the body
		// carries the SCEP challenge in cleartext. The digest lets a mismatch between
		// what step-ca signed and what we received (eg. a proxy altering the body in
		// transit) be told apart from a wrong secret, without logging any secret material.
		shared.WriteLog(fmt.Sprintf("Signature mismatch for webhook %s: received=%s computed=%s body=%d bytes sha256:%x", id, rawSig, hex.EncodeToString(mac), len(body), sha256.Sum256(body)), 1, 33)
		return nil, fmt.Errorf("invalid signature for incoming webhook %s", id)
	}
	shared.WriteLog(fmt.Sprintf("Successfully authenticated & confirmed signature of webhook ID %s.", id), 1, 0)
	return body, nil
}

// deny is a private function that writes a denial to the http response
// with a specific status code. it is used as part of errors or denials
// and will exit fatally if the response cannot be marshaled as json
func deny(w http.ResponseWriter, s int) {
	deny := webhook.ResponseBody{Allow: false}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s)
	err := json.NewEncoder(w).Encode(deny)
	if err != nil {
		shared.WriteLog(fmt.Sprintf("error when encoding json: %s.", err), 1, 33)
		os.Exit(1)
	}
	return
}

// allow is a private function that writes a allow to the http response
// along with any included enrichment data. it will exit fatally
// if the response cannot be marshaled as json
func allow(w http.ResponseWriter, data webhook.ResponseBody) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		shared.WriteLog(fmt.Sprintf("error when encoding json: %s.", err), 1, 33)
		os.Exit(1)
	}
	return
}
