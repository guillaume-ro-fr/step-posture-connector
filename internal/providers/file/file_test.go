package file

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"os"
	"testing"

	"github.com/smallstep/certificates/webhook"
	"go.step.sm/crypto/x509util"
)

// TestMain silences the provider's own logging, which shared.WriteLog sends straight to
// stderr and go test does not capture per test.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

const stepRequestB64 = `ewogICAgImF0dGVzdGF0aW9uRGF0YSI6IHsKICAgICAgICAicGVybWFuZW50SWRlbnRpZmllciI6ICJDOFJZN05CTlY4RSIKICAgIH0sCiAgICAieDUwOUNlcnRpZmljYXRlUmVxdWVzdCI6IHsKICAgICAgICAicmF3IjogIk1JSUJQRENCeEFJQkFEQkZNUXN3Q1FZRFZRUUdFd0pCVlRFUk1BOEdBMVVFQ0F3SVZtbGpkRzl5YVdFeERUQUxCZ05WQkFvTUJGUmxjM1F4RkRBU0JnTlZCQU1NQzBNNFVsazNUa0pPVmpoRk1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFWExCZzdPa2JSajlYQXIxOWcrN2FGQzIxQ2lxaUREalloTWU1VjZkbzhkQTNmOFFvUTNvN3hSUXZndmY1Y04yOXdyTVBOMlc2UmVpVFBEZ1c2OEZkQlVGVkYrR1JMOWFINExncml1TzNxWlFUQ09PbmV4dElYeWxmNWJWZ3RLT2pvQUF3Q2dZSUtvWkl6ajBFQXdJRFp3QXdaQUl3Sm9jYmFRaU8vUHNlaUJ2dkd4K2xyem5yeSt4OEs4amcrMlZVckczYlRTYXRIMlBoRllnNXlobUYwQkpkaTNUa0FqQjdDYmVLK1RCY3VDc3RnejNKUVBTY2lqRjYyZ0JmS2syOTE2WFdXTFdZR0ppOEluQTcxYVZaVWZQME9DYlBveW89IgogICAgfQp9`

func TestParseJSONValid(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `eyAiZGV2aWNlcyI6WwogIHsKICAgICJpZGVudGlmaWVyIjogIkM4Ulk3TkJOVjhFIiwKICAgICJkYXRhIjogewogICAgICAidXNlcm5hbWUiOiAiZnJhbmsuam9uZXMiCiAgICB9CiAgfSwKICB7CiAgICAiaWRlbnRpZmllciI6ICJDNlJZWVZCTjIxMiIKICB9Cl19`)
	parseErr := parseJSON(b64Data)
	if parseErr != nil {
		t.Fatalf("JSON parse error: %s", parseErr)
	}
	if len(data.Devices) != 2 {
		t.Fatalf("Expecting 2 loaded devices. Got %d.", len(data.Devices))
	}
}

func TestParseJSONInvalid(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `eyJkZXZpY2VzIjpbeyAiaWRlbnRpZmllciI6Ik8yVERWU0lSUVUifSxdfQ==`)
	parseErr := parseJSON(b64Data)
	if parseErr == nil {
		t.Fatal("Should have errored on invalid JSON")
	}
}

func TestParseCSVValid(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `SWRlbnRpZmllcixVc2VybmFtZSxEZXBhcnRtZW50CkcyUk00NUNNUkMsZnJhbmsuam9uZXMsU2FsZXMKQzhSWTdOQk5WOEUsc2lhbi5zbWl0aCxFbmdpbmVlcmluZw==`)
	parseErr := parseCSV(b64Data)
	if parseErr != nil {
		t.Fatalf("CSV parse error: %s", parseErr)
	}
	if len(data.Devices) != 2 {
		t.Fatalf("Expecting 2 loaded devices. Got %d.", len(data.Devices))
	}
}

func TestParseCSVMissingIdentifier(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `U2VyaWFsTnVtYmVyCkYzTlZaMjY1TFgKM1BPQkhQVEcyUwpHR1JUWlZEQUZQCldGQjhMNUJXRFIKV0c3STUxWjk5OA==`)
	parseErr := parseCSV(b64Data)
	if parseErr == nil {
		t.Fatal("Should have errored on missing Identifier")
	}
}

func TestParseCSVInvalid(t *testing.T) {
	data = Data{}
	b64Data := decodeB64(t, `SWRlbnRpZmllcixVc2VybmFtZQpHMlJNNDVDTVJDLGZyYW5rLmpvbmVzLEludmFsaWQKRzI3WTQ4Q1Q0QixzaWFuLnNtaXRoLEludmFsaWQ=`)
	parseErr := parseCSV(b64Data)
	if parseErr == nil {
		t.Fatal("Should have errored on invalid CSV")
	}
}

func TestJSONAttest(t *testing.T) {
	p := Provider{}
	stepRequest := webhook.RequestBody{}
	// first parse and load devices from JSON
	TestParseJSONValid(t)
	b64Data := decodeB64(t, stepRequestB64)
	err := json.Unmarshal(b64Data, &stepRequest)
	if err != nil {
		t.Fatalf("Could not unmarshal example step request: %s ", err)
	}
	resp, err := p.Handler("deviceAttest", stepRequest)
	if err != nil {
		t.Fatalf("Handler error: %s", err)
	}
	if resp.Allow == false {
		t.Fatalf("Device should have been allowed!")
	}
}

func TestCSVAttest(t *testing.T) {
	p := Provider{}
	stepRequest := webhook.RequestBody{}
	// first parse and load devices from JSON
	TestParseCSVValid(t)
	b64Data := decodeB64(t, stepRequestB64)
	err := json.Unmarshal(b64Data, &stepRequest)
	if err != nil {
		t.Fatalf("Could not unmarshal example step request: %s ", err)
	}
	resp, err := p.Handler("deviceAttest", stepRequest)
	if err != nil {
		t.Fatalf("Handler error: %s", err)
	}
	if resp.Allow == false {
		t.Fatalf("Device should have been allowed!")
	}
}

// resetSCEPConfig resets the SCEP challenge package globals to their zero value and
// restores them once the calling test completes, matching how a real Bootstrap() run
// would leave the provider between test cases.
func resetSCEPConfig(t *testing.T) {
	t.Helper()
	scepStaticChallenge = ""
	scepChallengeKey = ""
	t.Cleanup(func() {
		scepStaticChallenge = ""
		scepChallengeKey = ""
	})
}

func scepRequest(serial, challenge string) webhook.RequestBody {
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

func TestSCEPHandler_StaticChallenge(t *testing.T) {
	resetSCEPConfig(t)
	data = Data{}
	TestParseJSONValid(t)
	scepStaticChallenge = "myStaticChallenge"

	p := Provider{}
	resp, err := p.SCEPHandler("", scepRequest("C8RY7NBNV8E", "myStaticChallenge"))
	if err != nil {
		t.Fatalf("SCEPHandler error: %s", err)
	}
	if !resp.Allow {
		t.Fatal("expected the correct static challenge to be allowed")
	}

	resp, err = p.SCEPHandler("", scepRequest("C8RY7NBNV8E", "wrongChallenge"))
	if err == nil || resp.Allow {
		t.Fatal("expected an incorrect static challenge to be denied")
	}
}

func TestSCEPHandler_DynamicChallenge(t *testing.T) {
	resetSCEPConfig(t)
	data = Data{}
	TestParseJSONValid(t)
	// C8RY7NBNV8E carries {"username":"frank.jones"} from the JSON fixture; add a
	// challenge field to it directly for this test
	for i := range data.Devices {
		if data.Devices[i].Identifier == "C8RY7NBNV8E" {
			data.Devices[i].Data["scepChallenge"] = "myDynamicChallenge"
		}
	}
	scepChallengeKey = "scepChallenge"

	p := Provider{}
	resp, err := p.SCEPHandler("", scepRequest("C8RY7NBNV8E", "myDynamicChallenge"))
	if err != nil {
		t.Fatalf("SCEPHandler error: %s", err)
	}
	if !resp.Allow {
		t.Fatal("expected the correct dynamic challenge to be allowed")
	}

	resp, err = p.SCEPHandler("", scepRequest("C8RY7NBNV8E", "wrongChallenge"))
	if err == nil || resp.Allow {
		t.Fatal("expected an incorrect dynamic challenge to be denied")
	}

	// C6RYYVBN212 has no Data map at all, so the dynamic key is simply absent
	resp, err = p.SCEPHandler("", scepRequest("C6RYYVBN212", "anything"))
	if err == nil || resp.Allow {
		t.Fatal("expected a device with no value for the dynamic key to be denied")
	}
}

func TestSCEPHandler_UnknownSerial(t *testing.T) {
	resetSCEPConfig(t)
	data = Data{}
	TestParseJSONValid(t)
	scepStaticChallenge = "myStaticChallenge"

	p := Provider{}
	resp, err := p.SCEPHandler("", scepRequest("UNKNOWN0000", "myStaticChallenge"))
	if err == nil || resp.Allow {
		t.Fatal("expected an unregistered serial number to be denied")
	}
}

func TestSCEPHandler_NotConfigured(t *testing.T) {
	resetSCEPConfig(t)
	data = Data{}
	TestParseJSONValid(t)

	p := Provider{}
	resp, err := p.SCEPHandler("", scepRequest("C8RY7NBNV8E", "anything"))
	if err == nil || resp.Allow {
		t.Fatal("expected SCEP to be denied when neither FILE_SCEP_CHALLENGE nor FILE_SCEP_CHALLENGE_KEY is set")
	}
}

func decodeB64(t *testing.T, b64String string) []byte {
	b64Data := make([]byte, base64.StdEncoding.DecodedLen(len(b64String)))
	_, decodeErr := base64.StdEncoding.Decode(b64Data, []byte(b64String))
	if decodeErr != nil {
		t.Fatalf("Base64 decode error: %s", decodeErr)
	}
	return b64Data
}
