package mosyle

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/x509util"
)

// TestMain silences the provider's own logging, which shared.WriteLog sends straight to
// stderr and go test does not capture per test.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// mosyleTestFixture builds a minimal Mosyle POST /v1/devices response.
func mosyleTestFixture(devices []MosyleDevice) []byte {
	if devices == nil {
		devices = []MosyleDevice{}
	}
	resp := mosyleListDevicesResponse{
		Status: "OK",
		Response: []struct {
			Devices []MosyleDevice `json:"devices"`
		}{
			{Devices: devices},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// defaultLoginHandler serves a successful Mosyle /login response with a test bearer token.
func defaultLoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Authorization", "Bearer test-bearer-token")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"UserID":"test-user","email":"test@example.com"}`))
}

// setupServer creates an httptest server whose handler function is provided by the caller.
func setupServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// setupMosyleServer creates an httptest server that handles /login with a default success
// response and routes all other paths to devicesHandler.
func setupMosyleServer(t *testing.T, devicesHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			defaultLoginHandler(w, r)
			return
		}
		if devicesHandler != nil {
			devicesHandler(w, r)
		}
	})
}

// mosyleEnvVars lists every environment variable this provider reads. setEnv blanks the
// ones a test doesn't set itself, so the suite is hermetic: running `go test` from a shell
// that has the deployment's own .env exported must not change any outcome.
var mosyleEnvVars = []string{
	"MOSYLE_BASE_URL", "MOSYLE_ACCESS_TOKEN", "MOSYLE_EMAIL", "MOSYLE_PASSWORD",
	"MOSYLE_TAGS", "MOSYLE_ENRICH", "MOSYLE_SCEP_CHALLENGE", "MOSYLE_SCEP_CHALLENGE_KEY",
	"TIMEOUT",
}

// setEnv sets env vars for the test and restores them on cleanup.
func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	originals := map[string]string{}
	// start from a blank slate so an ambient value can never leak into a test
	for _, k := range mosyleEnvVars {
		if _, ok := vars[k]; !ok {
			originals[k] = os.Getenv(k)
			os.Setenv(k, "")
		}
	}
	for k, v := range vars {
		originals[k] = os.Getenv(k)
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		for k, v := range originals {
			os.Setenv(k, v)
		}
		complianceTags = nil
		enrichEnabled = false
		validate = nil
		config = nil
		client = Client{}
		scepStaticChallenge = ""
		scepChallengeKey = ""
	})
}

// baseEnv returns the minimum env needed for a successful Bootstrap against a given URL.
func baseEnv(url string) map[string]string {
	return map[string]string{
		"MOSYLE_BASE_URL":     url,
		"MOSYLE_ACCESS_TOKEN": "test-token-bootstrap",
		"MOSYLE_EMAIL":        "test@example.com",
		"MOSYLE_PASSWORD":     "testpassword",
		"MOSYLE_TAGS":         "",
		"MOSYLE_ENRICH":       "0",
		"TIMEOUT":             "",
	}
}

func defaultDevice() MosyleDevice {
	return MosyleDevice{
		Serial:         "SERIALNUM0001",
		UDID:           "UDID-0001",
		DeviceName:     "Test MacBook",
		DeviceModel:    "MacBookPro18,1",
		OS:             "mac",
		OSVersion:      "14.0",
		IsSupervised:   false,
		IsDeleted:      false,
		Status:         "INSTALLED",
		UserID:         "user42",
		EnrollmentType: "DEP",
		Tags:           []string{"corp", "production"},
	}
}

func defaultInput(serial string) webhook.RequestBody {
	return webhook.RequestBody{
		AttestationData: &webhook.AttestationData{PermanentIdentifier: serial},
	}
}

// dataMap asserts that the enrichment data returned by the handler is a map
// and returns it, as webhook.ResponseBody carries Data as an any.
func dataMap(t *testing.T, resp webhook.ResponseBody) map[string]interface{} {
	t.Helper()
	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected response data to be a map, got %T", resp.Data)
	}
	return data
}

// bootstrapWithServer sets env vars and calls Bootstrap against the given server.
func bootstrapWithServer(t *testing.T, srv *httptest.Server, extraEnv map[string]string) {
	t.Helper()
	env := baseEnv(srv.URL)
	for k, v := range extraEnv {
		env[k] = v
	}
	setEnv(t, env)
	p := Provider{}
	if err := p.Bootstrap(); err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
}

// ---- Bootstrap tests ----

func TestBootstrap_Valid(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	setEnv(t, baseEnv(srv.URL))

	p := Provider{}
	if err := p.Bootstrap(); err != nil {
		t.Fatalf("expected bootstrap to succeed, got: %v", err)
	}
}

func TestBootstrap_MissingURL(t *testing.T) {
	setEnv(t, map[string]string{
		"MOSYLE_BASE_URL":     "",
		"MOSYLE_ACCESS_TOKEN": "test-token-bootstrap",
		"MOSYLE_EMAIL":        "test@example.com",
		"MOSYLE_PASSWORD":     "testpassword",
		"MOSYLE_TAGS":         "",
		"MOSYLE_ENRICH":       "",
		"TIMEOUT":             "",
	})
	p := Provider{}
	if err := p.Bootstrap(); err == nil {
		t.Fatal("expected error when MOSYLE_BASE_URL is empty")
	}
}

func TestBootstrap_MissingToken(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	setEnv(t, map[string]string{
		"MOSYLE_BASE_URL":     srv.URL,
		"MOSYLE_ACCESS_TOKEN": "",
		"MOSYLE_EMAIL":        "test@example.com",
		"MOSYLE_PASSWORD":     "testpassword",
		"MOSYLE_TAGS":         "",
		"MOSYLE_ENRICH":       "",
		"TIMEOUT":             "",
	})
	p := Provider{}
	if err := p.Bootstrap(); err == nil {
		t.Fatal("expected error when MOSYLE_ACCESS_TOKEN is empty")
	}
}

func TestBootstrap_MissingEmail(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	env := baseEnv(srv.URL)
	env["MOSYLE_EMAIL"] = ""
	setEnv(t, env)
	p := Provider{}
	if err := p.Bootstrap(); err == nil {
		t.Fatal("expected error when MOSYLE_EMAIL is empty")
	}
}

func TestBootstrap_MissingPassword(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	env := baseEnv(srv.URL)
	env["MOSYLE_PASSWORD"] = ""
	setEnv(t, env)
	p := Provider{}
	if err := p.Bootstrap(); err == nil {
		t.Fatal("expected error when MOSYLE_PASSWORD is empty")
	}
}

func TestBootstrap_APIAuthFailure(t *testing.T) {
	srv := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	setEnv(t, baseEnv(srv.URL))

	p := Provider{}
	if err := p.Bootstrap(); err == nil {
		t.Fatal("expected bootstrap to fail when API returns 401")
	}
}

func TestLogin_MissingAuthHeader(t *testing.T) {
	srv := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		// /login returns 200 but no Authorization header
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"UserID":"test-user"}`))
	})
	setEnv(t, baseEnv(srv.URL))
	p := Provider{}
	if err := p.Bootstrap(); err == nil {
		t.Fatal("expected bootstrap to fail when login response has no Authorization header")
	}
}

// ---- Handler tests ----

func TestHandler_HappyPath(t *testing.T) {
	dev := defaultDevice()
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput(dev.Serial))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected Allow=true")
	}
	if resp.Data != nil {
		t.Fatal("expected no enrichment data when MOSYLE_ENRICH=0")
	}
}

func TestHandler_HappyPath_WithEnrich(t *testing.T) {
	dev := defaultDevice()
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_ENRICH": "1"})

	resp, err := Provider{}.Handler("", defaultInput(dev.Serial))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected Allow=true")
	}
	if resp.Data == nil {
		t.Fatal("expected enrichment data when MOSYLE_ENRICH=1")
	}
	data := dataMap(t, resp)
	deviceMap, ok := data["device"].(map[string]interface{})
	if !ok {
		t.Fatal("expected data.device to be a map")
	}
	if deviceMap["udid"] != dev.UDID {
		t.Errorf("expected udid %s, got %v", dev.UDID, deviceMap["udid"])
	}
	if deviceMap["serial_number"] != dev.Serial {
		t.Errorf("expected serial_number %s, got %v", dev.Serial, deviceMap["serial_number"])
	}
	if _, ok := data["user"]; !ok {
		t.Fatal("expected data.user key in enrichment")
	}
	if _, ok := data["tags"]; !ok {
		t.Fatal("expected data.tags key in enrichment")
	}
}

func TestHandler_DeviceNotFound(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput("SERIALNUM0001"))
	if err == nil {
		t.Fatal("expected an error for missing device")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false for missing device")
	}
}

func TestHandler_DeviceDeleted(t *testing.T) {
	dev := defaultDevice()
	dev.IsDeleted = true

	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput(dev.Serial))
	if err == nil {
		t.Fatal("expected an error for deleted device")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false for deleted device")
	}
}

func TestHandler_DeviceStatusNotInstalled(t *testing.T) {
	dev := defaultDevice()
	dev.Status = "UNINSTALLED"

	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput(dev.Serial))
	if err == nil {
		t.Fatal("expected an error for non-INSTALLED device")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false for non-INSTALLED device")
	}
}

func TestHandler_APIReturns500(t *testing.T) {
	srv := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			defaultLoginHandler(w, r)
			return
		}
		// /devices: let the bootstrap probe succeed, fail for real requests.
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		opts, _ := req["options"].(map[string]interface{})
		serials, _ := opts["serial_numbers"].([]interface{})
		if len(serials) > 0 && serials[0] == "BOOTSTRAPTEST00" {
			w.WriteHeader(http.StatusOK)
			w.Write(mosyleTestFixture(nil))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput("SERIALNUM0001"))
	if err == nil {
		t.Fatal("expected an error for 500 response")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false on HTTP 500")
	}
}

func TestHandler_TagMatch(t *testing.T) {
	dev := defaultDevice()
	dev.Tags = []string{"corp", "vip"}

	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_TAGS": "vip,staging"})

	resp, err := Provider{}.Handler("", defaultInput(dev.Serial))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected Allow=true when device carries a matching tag")
	}
}

func TestHandler_TagMissing(t *testing.T) {
	dev := defaultDevice()
	dev.Tags = []string{"personal"}

	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_TAGS": "corp,vip"})

	resp, err := Provider{}.Handler("", defaultInput(dev.Serial))
	if err == nil {
		t.Fatal("expected error when device lacks all required tags")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false when device lacks required tags")
	}
}

func TestHandler_SerialTooShort(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput("SHORT"))
	if err == nil {
		t.Fatal("expected validation error for short serial")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false for invalid serial")
	}
}

func TestHandler_SerialInvalidChars(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput("SERIAL-001!@#$"))
	if err == nil {
		t.Fatal("expected validation error for serial with invalid chars")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false for invalid serial chars")
	}
}

// TestHandler_ValidModes verifies that all supported handler modes are accepted.
func TestHandler_ValidModes(t *testing.T) {
	dev := defaultDevice()
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, nil)

	for _, mode := range []string{"", "mobiledevice", "computer", "tvos", "visionos"} {
		resp, err := Provider{}.Handler(mode, defaultInput(dev.Serial))
		if err != nil {
			t.Errorf("mode=%q: unexpected error: %v", mode, err)
		}
		if !resp.Allow {
			t.Errorf("mode=%q: expected Allow=true", mode)
		}
	}
}

// TestHandler_InvalidMode verifies that an unknown mode is rejected.
func TestHandler_InvalidMode(t *testing.T) {
	dev := defaultDevice()
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("arbitrary", defaultInput(dev.Serial))
	if err == nil {
		t.Fatal("expected error for unknown handler mode")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false for unknown handler mode")
	}
}

// TestHandler_ModeMapping verifies handlerMode maps to the correct Mosyle os value.
func TestHandler_ModeMapping(t *testing.T) {
	cases := []struct {
		mode       string
		expectedOS string
	}{
		{"", "ios"},
		{"mobiledevice", "ios"},
		{"computer", "mac"},
		{"tvos", "tvos"},
		{"visionos", "visionos"},
	}

	dev := defaultDevice()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			var receivedOS string
			srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
				var body map[string]interface{}
				json.NewDecoder(r.Body).Decode(&body)
				opts, _ := body["options"].(map[string]interface{})
				receivedOS, _ = opts["os"].(string)
				w.WriteHeader(http.StatusOK)
				w.Write(mosyleTestFixture([]MosyleDevice{dev}))
			})
			bootstrapWithServer(t, srv, nil)

			Provider{}.Handler(tc.mode, defaultInput(dev.Serial))

			if receivedOS != tc.expectedOS {
				t.Errorf("mode=%q: expected os=%q, got %q", tc.mode, tc.expectedOS, receivedOS)
			}
		})
	}
}

// TestHandler_RequestFormat verifies that accessToken, Authorization, operation, and os
// are sent correctly to the /devices endpoint.
func TestHandler_RequestFormat(t *testing.T) {
	dev := defaultDevice()
	const expectedAccessToken = "my-mosyle-jwt-token"
	const expectedBearer = "test-bearer-token"

	var receivedAccessToken, receivedAuthorization, receivedOperation, receivedOS string
	srv := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			defaultLoginHandler(w, r)
			return
		}
		receivedAccessToken = r.Header.Get("accessToken")
		receivedAuthorization = r.Header.Get("Authorization")
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		receivedOperation, _ = body["operation"].(string)
		opts, _ := body["options"].(map[string]interface{})
		receivedOS, _ = opts["os"].(string)
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})

	env := baseEnv(srv.URL)
	env["MOSYLE_ACCESS_TOKEN"] = expectedAccessToken
	setEnv(t, env)
	p := Provider{}
	if err := p.Bootstrap(); err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	// mode=mobiledevice should map to os=ios
	Provider{}.Handler("mobiledevice", defaultInput(dev.Serial))

	if receivedAccessToken != expectedAccessToken {
		t.Errorf("expected accessToken header %q, got %q", expectedAccessToken, receivedAccessToken)
	}
	if receivedAuthorization != "Bearer "+expectedBearer {
		t.Errorf("expected Authorization header %q, got %q", "Bearer "+expectedBearer, receivedAuthorization)
	}
	if receivedOperation != "list" {
		t.Errorf("expected operation=list, got %q", receivedOperation)
	}
	if receivedOS != "ios" {
		t.Errorf("expected os=ios, got %q", receivedOS)
	}
}

// TestLogin_TokenRefreshOnExpiry verifies that an expired bearer token triggers a new login.
func TestLogin_TokenRefreshOnExpiry(t *testing.T) {
	loginCount := 0
	dev := defaultDevice()
	srv := setupServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			loginCount++
			defaultLoginHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, nil)

	// First handler call — token is fresh, no extra login.
	Provider{}.Handler("", defaultInput(dev.Serial))
	countAfterFirst := loginCount

	// Force expiry, then call again — must re-login.
	client.tokenExpiry = time.Now().Add(-time.Second)
	Provider{}.Handler("", defaultInput(dev.Serial))

	if loginCount != countAfterFirst+1 {
		t.Errorf("expected one extra login on token expiry, got %d extra (initial=%d, final=%d)",
			loginCount-countAfterFirst, countAfterFirst, loginCount)
	}
}

// Client-side serial filter: device with wrong serial in response is not matched.
func TestHandler_ClientSideSerialFilter(t *testing.T) {
	other := defaultDevice()
	other.Serial = "OTHERDEVICE01"

	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{other}))
	})
	bootstrapWithServer(t, srv, nil)

	// Request for a different serial — the response contains a different device.
	resp, err := Provider{}.Handler("", defaultInput("SERIALNUM0001"))
	if err == nil {
		t.Fatal("expected error when API returns no matching device")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false when returned device serial does not match")
	}
}

// Verify enrichment data structure matches the documented format.
func TestHandler_EnrichDataStructure(t *testing.T) {
	dev := defaultDevice()
	dev.IsSupervised = true

	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_ENRICH": "1"})

	resp, err := Provider{}.Handler("", defaultInput(dev.Serial))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data := dataMap(t, resp)
	deviceMap, _ := data["device"].(map[string]interface{})
	expected := map[string]interface{}{
		"udid":            "UDID-0001",
		"serial_number":   "SERIALNUM0001",
		"name":            "Test MacBook",
		"model":           "MacBookPro18,1",
		"os":              "mac",
		"os_version":      "14.0",
		"is_supervised":   true,
		"enrollment_type": "DEP",
	}
	for k, want := range expected {
		got := deviceMap[k]
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
			t.Errorf("device[%s]: want %v, got %v", k, want, got)
		}
	}

	userMap, _ := data["user"].(map[string]interface{})
	if userMap["userid"] != "user42" {
		t.Errorf("user.userid: want user42, got %v", userMap["userid"])
	}

	tags, _ := data["tags"].([]string)
	if len(tags) != 2 || tags[0] != "corp" {
		t.Errorf("unexpected tags: %v", data["tags"])
	}
}

// rawDeviceFixture builds a POST /v1/devices response from a hand-written device
// object. Unlike mosyleTestFixture it does not round-trip through MosyleDevice, so
// it can reproduce the shapes Mosyle really sends — notably is_supervised and
// is_deleted as the strings "1" and "0".
func rawDeviceFixture(deviceJSON string) []byte {
	return []byte(`{"status":"OK","response":[{"devices":[` + deviceJSON + `]}]}`)
}

// rawEmptyFixture builds a POST /v1/devices response with no device records.
func rawEmptyFixture() []byte {
	return []byte(`{"status":"OK","response":[{"devices":[]}]}`)
}

// stringBoolDevice is a device record whose booleans arrive as strings.
const stringBoolDevice = `{
	"serial_number": "SERIALNUM0001",
	"deviceudid": "UDID-0001",
	"device_name": "Test MacBook",
	"device_model": "MacBookPro18,1",
	"os": "mac",
	"osversion": "14.0",
	"is_supervised": "1",
	"is_deleted": "0",
	"status": "INSTALLED",
	"userid": "user42",
	"enrollment_type": "DEP",
	"tags": ["corp", "production"]
}`

// Mosyle sends is_supervised/is_deleted as strings; decoding must not fail and the
// values must reach the enrichment data as real booleans.
func TestHandler_StringBooleansFromAPI(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(rawDeviceFixture(stringBoolDevice))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_ENRICH": "1"})

	resp, err := Provider{}.Handler("", defaultInput("SERIALNUM0001"))
	if err != nil {
		t.Fatalf("unexpected error decoding string booleans: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected Allow=true for a supervised, non-deleted device")
	}

	deviceMap, _ := dataMap(t, resp)["device"].(map[string]interface{})
	if got := deviceMap["is_supervised"]; got != true {
		t.Errorf("is_supervised: want true (bool), got %v (%T)", got, got)
	}
}

// is_deleted arriving as the string "1" must still deny the request.
func TestHandler_StringBooleanDeleted(t *testing.T) {
	device := strings.Replace(stringBoolDevice, `"is_deleted": "0"`, `"is_deleted": "1"`, 1)
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(rawDeviceFixture(device))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput("SERIALNUM0001"))
	if err == nil {
		t.Fatal(`expected an error for a device with is_deleted "1"`)
	}
	if resp.Allow {
		t.Fatal(`expected Allow=false for a device with is_deleted "1"`)
	}
}

// An uninterpretable boolean must deny the request rather than fail open.
func TestHandler_UnparseableBooleanDenies(t *testing.T) {
	device := strings.Replace(stringBoolDevice, `"is_deleted": "0"`, `"is_deleted": "maybe"`, 1)
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		// Keep the bootstrap sanity-check probe clean so only the handler call
		// under test sees the malformed record.
		if strings.Contains(string(body), "BOOTSTRAPTEST00") {
			w.Write(rawEmptyFixture())
			return
		}
		w.Write(rawDeviceFixture(device))
	})
	bootstrapWithServer(t, srv, nil)

	resp, err := Provider{}.Handler("", defaultInput("SERIALNUM0001"))
	if err == nil {
		t.Fatal("expected an error for an uninterpretable boolean")
	}
	if resp.Allow {
		t.Fatal("expected Allow=false for an uninterpretable boolean")
	}
}

func TestFlexBool_Unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    bool
		wantErr bool
	}{
		{"string one", `{"is_supervised":"1"}`, true, false},
		{"string zero", `{"is_supervised":"0"}`, false, false},
		{"string true", `{"is_supervised":"true"}`, true, false},
		{"string false", `{"is_supervised":"false"}`, false, false},
		{"string empty", `{"is_supervised":""}`, false, false},
		{"bool true", `{"is_supervised":true}`, true, false},
		{"bool false", `{"is_supervised":false}`, false, false},
		{"number one", `{"is_supervised":1}`, true, false},
		{"number zero", `{"is_supervised":0}`, false, false},
		{"null", `{"is_supervised":null}`, false, false},
		{"absent", `{}`, false, false},
		{"unparseable string", `{"is_supervised":"maybe"}`, false, true},
		{"unparseable number", `{"is_supervised":2}`, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var device MosyleDevice
			err := json.Unmarshal([]byte(test.json), &device)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %s", test.json)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", test.json, err)
			}
			if bool(device.IsSupervised) != test.want {
				t.Errorf("%s: want %v, got %v", test.json, test.want, device.IsSupervised)
			}
		})
	}
}

// ---- SCEP challenge tests ----

// scepInput builds a SCEPCHALLENGE-shaped webhook.RequestBody carrying the serial in the
// CSR subject's serialNumber attribute, as step-ca's challengeValidationController sends it.
func scepInput(serial, challenge string) webhook.RequestBody {
	return webhook.RequestBody{
		SCEPTransactionID: "txn-1",
		SCEPChallenge:     challenge,
		X509CertificateRequest: &webhook.X509CertificateRequest{
			CertificateRequest: &x509util.CertificateRequest{
				Subject: x509util.Subject{SerialNumber: serial},
			},
		},
	}
}

// mosyleEmbedded encodes a JSON document the way Mosyle embeds nested structures in its
// responses: as a JSON string containing the document.
func mosyleEmbedded(document string) string {
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// deviceWithAttributes builds a device record whose CustomDeviceAttributes carries the given
// attribute list, embedded as a JSON string exactly as POST /v1/devices delivers it, and
// with the string booleans and null tags that endpoint really returns.
func deviceWithAttributes(attributes string) string {
	return `{
	"serial_number": "SERIALNUM0001",
	"deviceudid": "UDID-0001",
	"device_name": "Test MacBook",
	"device_model": "MacBookPro18,1",
	"os": "mac",
	"osversion": "14.0",
	"is_supervised": "1",
	"is_deleted": "0",
	"status": "INSTALLED",
	"userid": "user42",
	"enrollment_type": "1:1",
	"tags": null,
	"CustomDeviceAttributes": ` + mosyleEmbedded(attributes) + `
}`
}

// devicesEndpointAttributes is the attribute shape POST /v1/devices returns: the identifier
// is CustomAttributeUniqueID and the bookkeeping fields are absent.
const devicesEndpointAttributes = `[` +
	`{"Name":"Some Other Attribute","CustomAttributeUniqueID":"custom_other","Value":"irrelevant"},` +
	`{"Name":"SCEP Challenge","CustomAttributeUniqueID":"custom_cc_scepChallenge","Value":"myDynamicChallenge123"}` +
	`]`

// customAttributeEndpointAttributes is the shape Mosyle's custom attribute endpoints return:
// the identifier is UniqueID, alongside LastUpdate, Source, OS and IsDeleted.
const customAttributeEndpointAttributes = `[` +
	`{"Name":"SCEP Challenge","UniqueID":"custom_cc_scepChallenge","Value":"myDynamicChallenge123",` +
	`"LastUpdate":"1710266724","Source":"API","OS":"mac","IsDeleted":"0"}` +
	`]`

func TestSCEPHandler_StaticChallenge(t *testing.T) {
	dev := defaultDevice()
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE": "myStaticChallenge"})

	resp, err := Provider{}.SCEPHandler("", scepInput(dev.Serial, "myStaticChallenge"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected the correct static challenge to be allowed")
	}

	resp, err = Provider{}.SCEPHandler("", scepInput(dev.Serial, "wrongChallenge"))
	if err == nil || resp.Allow {
		t.Fatal("expected an incorrect static challenge to be denied")
	}
}

// TestSCEPHandler_DynamicChallenge exercises the exact shape POST /v1/devices returns:
// CustomDeviceAttributes as a JSON-encoded string, identifier in CustomAttributeUniqueID.
func TestSCEPHandler_DynamicChallenge(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(rawDeviceFixture(deviceWithAttributes(devicesEndpointAttributes)))
	})
	// note the surrounding %...% as Mosyle's own profile variable syntax would produce -
	// these must be trimmed automatically
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE_KEY": "%custom_cc_scepChallenge%"})

	resp, err := Provider{}.SCEPHandler("", scepInput("SERIALNUM0001", "myDynamicChallenge123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected the correct dynamic challenge to be allowed")
	}

	resp, err = Provider{}.SCEPHandler("", scepInput("SERIALNUM0001", "wrongChallenge"))
	if err == nil || resp.Allow {
		t.Fatal("expected an incorrect dynamic challenge to be denied")
	}
}

// The other identifier field name Mosyle uses must resolve identically.
func TestSCEPHandler_DynamicChallengeByUniqueID(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(rawDeviceFixture(deviceWithAttributes(customAttributeEndpointAttributes)))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE_KEY": "custom_cc_scepChallenge"})

	resp, err := Provider{}.SCEPHandler("", scepInput("SERIALNUM0001", "myDynamicChallenge123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected an attribute identified by UniqueID to resolve too")
	}
}

// The display Name is accepted as well, since that is what the Mosyle console shows.
func TestSCEPHandler_DynamicChallengeByAttributeName(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(rawDeviceFixture(deviceWithAttributes(devicesEndpointAttributes)))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE_KEY": "SCEP Challenge"})

	resp, err := Provider{}.SCEPHandler("", scepInput("SERIALNUM0001", "myDynamicChallenge123"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected a challenge held in a Custom Device Attribute to be matched by Name")
	}
}

// A deleted attribute must not be usable as a challenge.
func TestSCEPHandler_DynamicChallengeDeletedAttribute(t *testing.T) {
	attributes := strings.Replace(customAttributeEndpointAttributes, `"IsDeleted":"0"`, `"IsDeleted":"1"`, 1)
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(rawDeviceFixture(deviceWithAttributes(attributes)))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE_KEY": "custom_cc_scepChallenge"})

	resp, err := Provider{}.SCEPHandler("", scepInput("SERIALNUM0001", "myDynamicChallenge123"))
	if err == nil || resp.Allow {
		t.Fatal("expected a deleted custom device attribute to be ignored, denying the request")
	}
}

// TestMosyleDevice_UnmarshalJSON_CustomAttributes confirms the embedded attribute list
// decodes into typed values alongside the device's own string booleans.
func TestMosyleDevice_UnmarshalJSON_CustomAttributes(t *testing.T) {
	var device MosyleDevice
	if err := json.Unmarshal([]byte(deviceWithAttributes(devicesEndpointAttributes)), &device); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bool(device.IsSupervised) {
		t.Error(`expected is_supervised "1" to decode to true via flexBool`)
	}
	if len(device.CustomAttributes) != 2 {
		t.Fatalf("expected 2 custom device attributes, got %d", len(device.CustomAttributes))
	}
	attribute := device.CustomAttributes[1]
	if attribute.ID() != "custom_cc_scepChallenge" {
		t.Errorf("expected ID() to resolve to custom_cc_scepChallenge, got %q", attribute.ID())
	}
	if attribute.Value != "myDynamicChallenge123" {
		t.Errorf("expected the attribute value to decode, got %q", attribute.Value)
	}
}

// TestMosyleCustomAttribute_ID covers both identifier field names, and the precedence
// between them when a payload somehow carries both.
func TestMosyleCustomAttribute_ID(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"devices endpoint", `{"CustomAttributeUniqueID":"custom_a"}`, "custom_a"},
		{"custom attribute endpoint", `{"UniqueID":"custom_b"}`, "custom_b"},
		{"both present", `{"CustomAttributeUniqueID":"custom_a","UniqueID":"custom_b"}`, "custom_a"},
		{"neither present", `{"Name":"SCEP Challenge"}`, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var attribute MosyleCustomAttribute
			if err := json.Unmarshal([]byte(test.json), &attribute); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := attribute.ID(); got != test.want {
				t.Errorf("expected ID() %q, got %q", test.want, got)
			}
		})
	}
}

// CustomDeviceAttributes arrives as a JSON document embedded in a JSON string. Absent, null
// and empty mean the device carries none; any other shape must be a loud error rather than
// a silently empty list.
func TestCustomAttributes_Unmarshal(t *testing.T) {
	attribute := `{"Name":"SCEP Challenge","CustomAttributeUniqueID":"custom_cc_scepChallenge","Value":"abc"}`
	tests := []struct {
		name    string
		json    string
		want    int
		wantErr bool
	}{
		{"embedded list", `{"CustomDeviceAttributes":` + mosyleEmbedded(`[`+attribute+`]`) + `}`, 1, false},
		{"embedded empty list", `{"CustomDeviceAttributes":"[]"}`, 0, false},
		{"empty string", `{"CustomDeviceAttributes":""}`, 0, false},
		{"null", `{"CustomDeviceAttributes":null}`, 0, false},
		{"absent", `{}`, 0, false},
		{"bare list", `{"CustomDeviceAttributes":[` + attribute + `]}`, 0, true},
		{"unparseable string", `{"CustomDeviceAttributes":"not a list"}`, 0, true},
		{"unexpected type", `{"CustomDeviceAttributes":42}`, 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var device MosyleDevice
			err := json.Unmarshal([]byte(test.json), &device)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %s", test.json)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", test.json, err)
			}
			if len(device.CustomAttributes) != test.want {
				t.Errorf("expected %d attributes, got %d", test.want, len(device.CustomAttributes))
			}
		})
	}
}

// TestSCEPHandler_FullDeviceRecord replays a complete device record with the field set and
// shapes POST /v1/devices really returns - including the nulls, the string booleans and the
// several structures Mosyle embeds as JSON strings. It is the regression test for the two
// things that broke against the live API: CustomDeviceAttributes arriving as a JSON-encoded
// string, and the identifier field being named CustomAttributeUniqueID.
//
// All values are fictitious; only the structure mirrors a real response.
func TestSCEPHandler_FullDeviceRecord(t *testing.T) {
	const device = `{"deviceudid":"00000000-1111-2222-3333-444444444444","total_disk":"494.0000000000",` +
		`"os":"mac","serial_number":"SERIALNUM0002","device_name":"Example MacBook Pro",` +
		`"device_model":"MacBookPro18,1","osversion":"14.0","carrier":null,"imei":null,` +
		`"is_supervised":"1","status":"INSTALLED","tags":null,"is_deleted":"0",` +
		`"device_type":"COMPUTER","enrollment_type":"1:1","userid":"example.user",` +
		`"OSUpdateSettings":"{\"AutoCheckEnabled\":true}","ActiveManagedUsers":"[\"AAAAAAAA\"]",` +
		`"CustomDeviceAttributes":"[{\"Name\":\"SCEP Challenge\",\"CustomAttributeUniqueID\":\"custom_cc_scepChallenge\",\"Value\":\"example-challenge-value\"}]",` +
		`"DeviceAttestationStatus":"Compliant","last_lan_ip":"10.0.0.1"}`

	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(rawDeviceFixture(device))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE_KEY": "%custom_cc_scepChallenge%"})

	resp, err := Provider{}.SCEPHandler("computer", scepInput("SERIALNUM0002", "example-challenge-value"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allow {
		t.Fatal("expected the challenge from a full Mosyle device record to be resolved and matched")
	}

	resp, err = Provider{}.SCEPHandler("computer", scepInput("SERIALNUM0002", "wrongChallenge"))
	if err == nil || resp.Allow {
		t.Fatal("expected an incorrect challenge to be denied")
	}
}

// A device record must survive a marshal/unmarshal round-trip, so that a fixture built from
// a MosyleDevice value carries its attributes in the same embedded form the API uses.
func TestCustomAttributes_RoundTrip(t *testing.T) {
	original := MosyleDevice{
		Serial: "SERIALNUM0001",
		CustomAttributes: customAttributes{
			{Name: "SCEP Challenge", CustomAttributeUniqueID: "custom_cc_scepChallenge", Value: "abc"},
		},
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("unexpected error marshaling: %v", err)
	}
	var decoded MosyleDevice
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unexpected error unmarshaling: %v", err)
	}
	if len(decoded.CustomAttributes) != 1 {
		t.Fatalf("expected 1 attribute after round-trip, got %d", len(decoded.CustomAttributes))
	}
	if decoded.CustomAttributes[0].ID() != "custom_cc_scepChallenge" {
		t.Errorf("expected the identifier to survive, got %q", decoded.CustomAttributes[0].ID())
	}
	if decoded.CustomAttributes[0].Value != "abc" {
		t.Errorf("expected the value to survive, got %q", decoded.CustomAttributes[0].Value)
	}
}

// A device whose CustomDeviceAttributes came back as "" must be denied cleanly (challenge
// not found) rather than failing the whole response decode.
func TestSCEPHandler_CustomAttributesAsEmptyString(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(rawDeviceFixture(deviceWithAttributes("")))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE_KEY": "custom_cc_scepChallenge"})

	resp, err := Provider{}.SCEPHandler("", scepInput("SERIALNUM0001", "myDynamicChallenge123"))
	if err == nil || resp.Allow {
		t.Fatal("expected a device with no custom attributes to be denied")
	}
	if strings.Contains(err.Error(), "unmarshal") || strings.Contains(err.Error(), "decode") {
		t.Fatalf("expected a challenge-not-found denial, not a decode failure: %v", err)
	}
}

func TestSCEPHandler_DynamicChallengeKeyMissing(t *testing.T) {
	dev := defaultDevice()
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// dev carries no custom device attributes - the configured key won't be found
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE_KEY": "custom_cc_scepChallenge"})

	resp, err := Provider{}.SCEPHandler("", scepInput(dev.Serial, "anything"))
	if err == nil || resp.Allow {
		t.Fatal("expected a device with no value for the dynamic key to be denied")
	}
}

func TestSCEPHandler_DeviceNotFound(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE": "myStaticChallenge"})

	resp, err := Provider{}.SCEPHandler("", scepInput("UNKNOWN00001", "myStaticChallenge"))
	if err == nil || resp.Allow {
		t.Fatal("expected an unregistered serial number to be denied")
	}
}

func TestSCEPHandler_DeviceDeleted(t *testing.T) {
	dev := defaultDevice()
	dev.IsDeleted = true
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	bootstrapWithServer(t, srv, map[string]string{"MOSYLE_SCEP_CHALLENGE": "myStaticChallenge"})

	resp, err := Provider{}.SCEPHandler("", scepInput(dev.Serial, "myStaticChallenge"))
	if err == nil || resp.Allow {
		t.Fatal("expected a deleted device to be denied, even with the correct challenge")
	}
}

func TestSCEPHandler_NotConfigured(t *testing.T) {
	dev := defaultDevice()
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture([]MosyleDevice{dev}))
	})
	// neither MOSYLE_SCEP_CHALLENGE nor MOSYLE_SCEP_CHALLENGE_KEY set
	bootstrapWithServer(t, srv, nil)

	scepResp, err := Provider{}.SCEPHandler("", scepInput(dev.Serial, "anything"))
	if err == nil || scepResp.Allow {
		t.Fatal("expected SCEP to be denied when no challenge validation is configured")
	}

	// ACME must be unaffected by SCEP being unconfigured
	acmeResp, err := Provider{}.Handler("", defaultInput(dev.Serial))
	if err != nil || !acmeResp.Allow {
		t.Fatalf("expected ACME to still be allowed, got allow=%v err=%v", acmeResp.Allow, err)
	}
}

func TestBootstrap_SCEPChallengeBothSet(t *testing.T) {
	srv := setupMosyleServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(mosyleTestFixture(nil))
	})
	env := baseEnv(srv.URL)
	env["MOSYLE_SCEP_CHALLENGE"] = "myStaticChallenge"
	env["MOSYLE_SCEP_CHALLENGE_KEY"] = "custom_cc_scepChallenge"
	setEnv(t, env)

	p := Provider{}
	if err := p.Bootstrap(); err == nil {
		t.Fatal("expected Bootstrap to fail when both MOSYLE_SCEP_CHALLENGE and MOSYLE_SCEP_CHALLENGE_KEY are set")
	}
}

// Decoding a full device record must leave every modelled field populated, including the
// string booleans and the null tags POST /v1/devices really returns.
func TestMosyleDevice_UnmarshalJSON(t *testing.T) {
	var device MosyleDevice
	if err := json.Unmarshal([]byte(deviceWithAttributes(devicesEndpointAttributes)), &device); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if device.Serial != "SERIALNUM0001" {
		t.Errorf("expected serial_number to decode, got %q", device.Serial)
	}
	if !bool(device.IsSupervised) {
		t.Error(`expected is_supervised "1" to decode to true via flexBool`)
	}
	if bool(device.IsDeleted) {
		t.Error(`expected is_deleted "0" to decode to false via flexBool`)
	}
	if device.Tags != nil {
		t.Errorf("expected null tags to decode as nil, got %v", device.Tags)
	}
	if device.Status != "INSTALLED" {
		t.Errorf("expected status to decode, got %q", device.Status)
	}
}
