package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/x509util"
)

// TestMain silences the connector's own logging. shared.WriteLog emits level-0 lines
// unconditionally through the standard logger, straight to stderr, which go test does not
// capture per test - so the allow/deny decisions from tests that deliberately exercise
// those paths would print on every run and read like failures.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// stubProvider is a minimal ProviderInterface implementation used to exercise the webhook
// route handlers without depending on a real provider.
type stubProvider struct {
	handlerResponse     webhook.ResponseBody
	handlerErr          error
	handlerCalled       bool
	scepHandlerResponse webhook.ResponseBody
	scepHandlerErr      error
	scepHandlerCalled   bool
}

func (s *stubProvider) Bootstrap() error { return nil }

func (s *stubProvider) Handler(string, webhook.RequestBody) (webhook.ResponseBody, error) {
	s.handlerCalled = true
	return s.handlerResponse, s.handlerErr
}

func (s *stubProvider) SCEPHandler(string, webhook.RequestBody) (webhook.ResponseBody, error) {
	s.scepHandlerCalled = true
	return s.scepHandlerResponse, s.scepHandlerErr
}

func acmeRequestBody() webhook.RequestBody {
	return webhook.RequestBody{
		Timestamp:       time.Now(),
		AttestationData: &webhook.AttestationData{PermanentIdentifier: "C02ABCDEFGH1"},
	}
}

func scepRequestBody(subject x509util.Subject) webhook.RequestBody {
	return webhook.RequestBody{
		Timestamp:         time.Now(),
		SCEPTransactionID: "txn-1",
		SCEPChallenge:     "myChallenge",
		X509CertificateRequest: &webhook.X509CertificateRequest{
			CertificateRequest: &x509util.CertificateRequest{Subject: subject},
		},
	}
}

// setWebhook installs a single webhook ID/secret pair for the duration of the calling test.
func setWebhook(t *testing.T, id string, secret []byte) {
	t.Helper()
	webhooks = map[string]string{id: base64.StdEncoding.EncodeToString(secret)}
	t.Cleanup(func() { webhooks = nil })
}

// setProvider installs stub as the package-level provider for the duration of the calling test.
func setProvider(t *testing.T, stub *stubProvider) {
	t.Helper()
	provider = stub
	t.Cleanup(func() { provider = nil })
}

// signedRequest builds a POST to path carrying a valid HMAC signature for body under secret.
func signedRequest(path, webhookID string, secret, body []byte) *http.Request {
	hm := hmac.New(sha256.New, secret)
	hm.Write(body)
	sig := hex.EncodeToString(hm.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("X-Smallstep-Webhook-ID", webhookID)
	req.Header.Set("X-Smallstep-Signature", sig)
	return req
}

const testWebhookID = "6d9b2e24-91f7-4c39-895c-0a9c4d84636a"

// ---- validateACMERequest / validateSCEPRequest ----

func TestValidateACMERequest(t *testing.T) {
	if err := validateACMERequest(acmeRequestBody()); err != nil {
		t.Fatalf("expected a valid ACME request to pass validation, got: %s", err)
	}

	noAttestation := acmeRequestBody()
	noAttestation.AttestationData = nil
	if err := validateACMERequest(noAttestation); err == nil {
		t.Fatal("expected a request without attestationData to fail validation")
	}

	emptyIdentifier := acmeRequestBody()
	emptyIdentifier.AttestationData = &webhook.AttestationData{PermanentIdentifier: ""}
	if err := validateACMERequest(emptyIdentifier); err == nil {
		t.Fatal("expected a request with an empty permanentIdentifier to fail validation")
	}

	zeroTimestamp := acmeRequestBody()
	zeroTimestamp.Timestamp = time.Time{}
	if err := validateACMERequest(zeroTimestamp); err == nil {
		t.Fatal("expected a request without a timestamp to fail validation")
	}

	staleTimestamp := acmeRequestBody()
	staleTimestamp.Timestamp = time.Now().Add(-1 * time.Minute)
	if err := validateACMERequest(staleTimestamp); err == nil {
		t.Fatal("expected a stale request to fail validation")
	}

	// a scepTransactionID here means a SCEPCHALLENGE webhook is misconfigured to point at
	// the ACME route instead of /webhook/scep-challenge
	scepShaped := acmeRequestBody()
	scepShaped.SCEPTransactionID = "txn-1"
	if err := validateACMERequest(scepShaped); err == nil {
		t.Fatal("expected a request carrying a scepTransactionID to fail ACME validation")
	}
}

func TestValidateSCEPRequest(t *testing.T) {
	valid := scepRequestBody(x509util.Subject{SerialNumber: "C02ABCDEFGH1"})
	if err := validateSCEPRequest(valid); err != nil {
		t.Fatalf("expected a valid SCEP request to pass validation, got: %s", err)
	}

	// a missing scepTransactionID here means something other than a SCEPCHALLENGE webhook
	// is misconfigured to point at the SCEP route
	noTransactionID := scepRequestBody(x509util.Subject{SerialNumber: "C02ABCDEFGH1"})
	noTransactionID.SCEPTransactionID = ""
	if err := validateSCEPRequest(noTransactionID); err == nil {
		t.Fatal("expected a request without a scepTransactionID to fail SCEP validation")
	}

	noChallenge := scepRequestBody(x509util.Subject{SerialNumber: "C02ABCDEFGH1"})
	noChallenge.SCEPChallenge = ""
	if err := validateSCEPRequest(noChallenge); err == nil {
		t.Fatal("expected a SCEP request without a scepChallenge to fail validation")
	}

	noCSR := scepRequestBody(x509util.Subject{SerialNumber: "C02ABCDEFGH1"})
	noCSR.X509CertificateRequest = nil
	if err := validateSCEPRequest(noCSR); err == nil {
		t.Fatal("expected a SCEP request without an x509CertificateRequest to fail validation")
	}

	// this is the shape produced when incoming JSON carries only the "raw" field and no
	// "subject" (or other promoted CertificateRequest field) - encoding/json then leaves
	// the embedded *x509util.CertificateRequest pointer nil. Any code that dereferences
	// .Subject on this without checking would panic; validateSCEPRequest must deny it instead.
	truncatedCSR := scepRequestBody(x509util.Subject{SerialNumber: "C02ABCDEFGH1"})
	truncatedCSR.X509CertificateRequest = &webhook.X509CertificateRequest{}
	if err := validateSCEPRequest(truncatedCSR); err == nil {
		t.Fatal("expected a SCEP request with a nil embedded CertificateRequest to fail validation")
	}

	zeroTimestamp := scepRequestBody(x509util.Subject{SerialNumber: "C02ABCDEFGH1"})
	zeroTimestamp.Timestamp = time.Time{}
	if err := validateSCEPRequest(zeroTimestamp); err == nil {
		t.Fatal("expected a request without a timestamp to fail validation")
	}
}

// ---- /webhook/scep-challenge ----

func TestWebhookHandlerSCEPChallenge_TruncatedCSRDoesNotPanic(t *testing.T) {
	stub := &stubProvider{}
	setProvider(t, stub)
	secret := []byte("test-secret")
	setWebhook(t, testWebhookID, secret)

	// deliberately omit "subject" (and every other promoted CertificateRequest field) so
	// the embedded *x509util.CertificateRequest pointer decodes as nil
	body := []byte(`{"timestamp":"` + time.Now().Format(time.RFC3339) + `","scepTransactionID":"txn-1","scepChallenge":"myChallenge","x509CertificateRequest":{"raw":"AAA="}}`)
	req := signedRequest("/webhook/scep-challenge", testWebhookID, secret, body)
	rec := httptest.NewRecorder()

	webhookHandlerSCEPChallenge(rec, req)

	if stub.scepHandlerCalled {
		t.Fatal("expected the provider to never be reached for a request that fails validation")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400, got %d", rec.Code)
	}
	var resp webhook.ResponseBody
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %s", err)
	}
	if resp.Allow {
		t.Fatal("expected the response to deny the request")
	}
}

func TestWebhookHandlerSCEPChallenge_Allow(t *testing.T) {
	stub := &stubProvider{scepHandlerResponse: webhook.ResponseBody{Allow: true}}
	setProvider(t, stub)
	secret := []byte("test-secret")
	setWebhook(t, testWebhookID, secret)

	body := []byte(`{"timestamp":"` + time.Now().Format(time.RFC3339) +
		`","scepTransactionID":"txn-1","scepChallenge":"myChallenge","x509CertificateRequest":{"subject":{"serialNumber":"C02ABCDEFGH1"},"raw":"AAA="}}`)
	req := signedRequest("/webhook/scep-challenge?mode=mobiledevice", testWebhookID, secret, body)
	rec := httptest.NewRecorder()

	webhookHandlerSCEPChallenge(rec, req)

	if !stub.scepHandlerCalled {
		t.Fatal("expected SCEPHandler to be called")
	}
	if stub.handlerCalled {
		t.Fatal("expected the ACME Handler to never be called from the SCEP route")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}
	var resp webhook.ResponseBody
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %s", err)
	}
	if !resp.Allow {
		t.Fatal("expected the response to allow the request")
	}
}

// TestWebhookHandlerSCEPChallenge_RejectsACMEShapedRequest confirms that pointing an ACME
// (AUTHORIZING/ENRICHING) webhook at /webhook/scep-challenge by mistake is rejected, rather
// than silently validated as if it were a SCEP request.
func TestWebhookHandlerSCEPChallenge_RejectsACMEShapedRequest(t *testing.T) {
	stub := &stubProvider{handlerResponse: webhook.ResponseBody{Allow: true}}
	setProvider(t, stub)
	secret := []byte("test-secret")
	setWebhook(t, testWebhookID, secret)

	body := []byte(`{"timestamp":"` + time.Now().Format(time.RFC3339) + `","attestationData":{"permanentIdentifier":"C02ABCDEFGH1"}}`)
	req := signedRequest("/webhook/scep-challenge", testWebhookID, secret, body)
	rec := httptest.NewRecorder()

	webhookHandlerSCEPChallenge(rec, req)

	if stub.handlerCalled || stub.scepHandlerCalled {
		t.Fatal("expected the provider to never be reached for a misrouted request")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400, got %d", rec.Code)
	}
}

// ---- /webhook/device-attest ----

func TestWebhookHandlerAttestDevice_Allow(t *testing.T) {
	stub := &stubProvider{handlerResponse: webhook.ResponseBody{Allow: true}}
	setProvider(t, stub)
	secret := []byte("test-secret")
	setWebhook(t, testWebhookID, secret)

	body := []byte(`{"timestamp":"` + time.Now().Format(time.RFC3339) + `","attestationData":{"permanentIdentifier":"C02ABCDEFGH1"}}`)
	req := signedRequest("/webhook/device-attest?mode=mobiledevice", testWebhookID, secret, body)
	rec := httptest.NewRecorder()

	webhookHandlerAttestDevice(rec, req)

	if !stub.handlerCalled {
		t.Fatal("expected Handler to be called")
	}
	if stub.scepHandlerCalled {
		t.Fatal("expected SCEPHandler to never be called from the ACME route")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}
	var resp webhook.ResponseBody
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %s", err)
	}
	if !resp.Allow {
		t.Fatal("expected the response to allow the request")
	}
}

// TestWebhookHandlerAttestDevice_RejectsSCEPShapedRequest confirms that pointing a SCEP
// provisioner's SCEPCHALLENGE webhook at /webhook/device-attest by mistake is rejected,
// rather than silently being handled as SCEP validation on the wrong route.
func TestWebhookHandlerAttestDevice_RejectsSCEPShapedRequest(t *testing.T) {
	stub := &stubProvider{scepHandlerResponse: webhook.ResponseBody{Allow: true}}
	setProvider(t, stub)
	secret := []byte("test-secret")
	setWebhook(t, testWebhookID, secret)

	body := []byte(`{"timestamp":"` + time.Now().Format(time.RFC3339) +
		`","scepTransactionID":"txn-1","scepChallenge":"myChallenge","x509CertificateRequest":{"subject":{"serialNumber":"C02ABCDEFGH1"},"raw":"AAA="}}`)
	req := signedRequest("/webhook/device-attest", testWebhookID, secret, body)
	rec := httptest.NewRecorder()

	webhookHandlerAttestDevice(rec, req)

	if stub.handlerCalled || stub.scepHandlerCalled {
		t.Fatal("expected the provider to never be reached for a misrouted request")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400, got %d", rec.Code)
	}
}

func TestAuthenticateRequest_UnknownWebhookID(t *testing.T) {
	setWebhook(t, testWebhookID, []byte("test-secret"))

	body := []byte(`{}`)
	// a signature computed with an empty key, which is what an unknown webhook ID would
	// decode to if the lookup weren't rejected before use
	req := signedRequest("/webhook/device-attest", "00000000-0000-0000-0000-000000000000", []byte{}, body)

	if _, err := authenticateRequest(req); err == nil {
		t.Fatal("expected an unknown webhook ID to be rejected")
	}
}
