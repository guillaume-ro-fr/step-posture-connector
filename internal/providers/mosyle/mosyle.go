package mosyle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/jedda/step-posture-connector/internal/shared"
	"github.com/smallstep/certificates/webhook"
)

type Provider struct{}

// Client stores the API config for Mosyle.
type Client struct {
	baseUrl     string
	accessToken string
	email       string
	password    string
	bearerToken string
	tokenExpiry time.Time
	timeout     time.Duration
}

// mosyleListDevicesResponse models the envelope returned by POST /v1/devices.
type mosyleListDevicesResponse struct {
	Status   string `json:"status"`
	Response []struct {
		Devices []MosyleDevice `json:"devices"`
	} `json:"response"`
}

// MosyleDevice holds the fields we consume from each device record.
type MosyleDevice struct {
	Serial         string   `json:"serial_number"`
	UDID           string   `json:"deviceudid"`
	DeviceName     string   `json:"device_name"`
	DeviceModel    string   `json:"device_model"`
	OS             string   `json:"os"`
	OSVersion      string   `json:"osversion"`
	IsSupervised   flexBool `json:"is_supervised"`
	IsDeleted      flexBool `json:"is_deleted"`
	Status         string   `json:"status"`
	UserID         string   `json:"userid"`
	EnrollmentType string   `json:"enrollment_type"`
	Tags           []string `json:"tags"`
	// CustomAttributes holds the device's Custom Device Attributes. This is where Mosyle
	// returns the values behind its %custom_...% profile variables, and so where a dynamic
	// SCEP challenge configured via MOSYLE_SCEP_CHALLENGE_KEY is looked up.
	CustomAttributes customAttributes `json:"CustomDeviceAttributes"`
}

// customAttributes decodes the CustomDeviceAttributes field of a device record.
//
// Mosyle delivers nested structures as a JSON document embedded in a JSON string rather
// than as JSON in its own right - the same convention it applies to OSUpdateSettings,
// ManagementStatus and ActiveManagedUsers - so this field arrives as a quoted string
// holding the attribute list. A null or empty value means the device carries no custom
// attributes; anything else is an error rather than a silent empty list, so a device is
// never treated as simply lacking a challenge because the payload changed shape.
type customAttributes []MosyleCustomAttribute

func (a *customAttributes) UnmarshalJSON(data []byte) error {
	var encoded *string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("CustomDeviceAttributes is not the expected JSON-encoded string")
	}
	if encoded == nil || strings.TrimSpace(*encoded) == "" {
		*a = nil
		return nil
	}
	var list []MosyleCustomAttribute
	if err := json.Unmarshal([]byte(*encoded), &list); err != nil {
		// never echo the string itself - it carries the SCEP challenge
		return fmt.Errorf("cannot decode the CustomDeviceAttributes string (%d chars) as a list of attributes", len(*encoded))
	}
	*a = list
	return nil
}

// MarshalJSON re-encodes the list using the same embedded-string convention, so the type
// stays a faithful codec in both directions and a device record round-trips unchanged.
func (a customAttributes) MarshalJSON() ([]byte, error) {
	if len(a) == 0 {
		return json.Marshal("")
	}
	document, err := json.Marshal([]MosyleCustomAttribute(a))
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(document))
}

// MosyleCustomAttribute models a single Custom Device Attribute.
//
// Mosyle names the identifier differently depending on the endpoint: POST /v1/devices
// returns CustomAttributeUniqueID and omits the bookkeeping fields, while the custom
// attribute endpoints return UniqueID alongside LastUpdate, Source, OS and IsDeleted. Both
// are modelled so an attribute reads the same whichever endpoint produced it.
type MosyleCustomAttribute struct {
	Name                    string   `json:"Name"`
	CustomAttributeUniqueID string   `json:"CustomAttributeUniqueID"`
	UniqueID                string   `json:"UniqueID"`
	Value                   string   `json:"Value"`
	LastUpdate              string   `json:"LastUpdate"`
	Source                  string   `json:"Source"`
	OS                      string   `json:"OS"`
	IsDeleted               flexBool `json:"IsDeleted"`
}

// ID returns the attribute's unique identifier - the name used by Mosyle's %custom_...%
// profile variables - from whichever of the two field names carried it.
func (a MosyleCustomAttribute) ID() string {
	if a.CustomAttributeUniqueID != "" {
		return a.CustomAttributeUniqueID
	}
	return a.UniqueID
}

// flexBool is a bool that tolerates the several shapes Mosyle uses for its
// boolean fields. is_supervised and is_deleted come back as the strings "1" and
// "0" rather than JSON booleans, so decoding them straight into a Go bool fails.
// A missing, null or empty value decodes as false; anything unrecognised is an
// error, so a bad is_deleted denies the request rather than failing open.
type flexBool bool

// UnmarshalJSON accepts JSON booleans (true), strings ("1", "0", "true",
// "false", "") and numbers (1, 0).
func (b *flexBool) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "null" {
		*b = false
		return nil
	}
	// Unquote the string forms ("1"/"0") down to their bare value.
	if unquoted, err := strconv.Unquote(raw); err == nil {
		raw = strings.TrimSpace(unquoted)
	}
	if raw == "" {
		*b = false
		return nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fmt.Errorf("cannot interpret %s as a boolean", data)
	}
	*b = flexBool(value)
	return nil
}

// handlerModeToOS maps step-ca webhook mode values to Mosyle API os values.
var handlerModeToOS = map[string]string{
	"mobiledevice": "ios",
	"computer":     "mac",
	"tvos":         "tvos",
	"visionos":     "visionos",
}

var client Client
var validate *validator.Validate
var config map[string]interface{}
var complianceTags []string
var enrichEnabled bool
var scepStaticChallenge string
var scepChallengeKey string

// Bootstrap sets up and validates the provider before the webhook server starts.
func (p Provider) Bootstrap() error {
	validate = validator.New(validator.WithRequiredStructEnabled())
	config = map[string]interface{}{
		"MOSYLE_BASE_URL":           os.Getenv("MOSYLE_BASE_URL"),
		"MOSYLE_ACCESS_TOKEN":       os.Getenv("MOSYLE_ACCESS_TOKEN"),
		"MOSYLE_EMAIL":              os.Getenv("MOSYLE_EMAIL"),
		"MOSYLE_PASSWORD":           os.Getenv("MOSYLE_PASSWORD"),
		"MOSYLE_TAGS":               os.Getenv("MOSYLE_TAGS"),
		"MOSYLE_ENRICH":             os.Getenv("MOSYLE_ENRICH"),
		"MOSYLE_SCEP_CHALLENGE":     os.Getenv("MOSYLE_SCEP_CHALLENGE"),
		"MOSYLE_SCEP_CHALLENGE_KEY": os.Getenv("MOSYLE_SCEP_CHALLENGE_KEY"),
		"TIMEOUT":                   os.Getenv("TIMEOUT"),
	}
	rules := map[string]interface{}{
		"MOSYLE_BASE_URL":           "required,url",
		"MOSYLE_ACCESS_TOKEN":       "required,min=10",
		"MOSYLE_EMAIL":              "required,email",
		"MOSYLE_PASSWORD":           "required,min=1",
		"MOSYLE_TAGS":               "omitempty",
		"MOSYLE_ENRICH":             "omitempty,oneof=0 1",
		"MOSYLE_SCEP_CHALLENGE":     "omitempty",
		"MOSYLE_SCEP_CHALLENGE_KEY": "omitempty",
		"TIMEOUT":                   "omitempty,number,max=2",
	}
	errs := validate.ValidateMap(config, rules)
	if len(errs) > 0 {
		return fmt.Errorf("Mosyle failed to bootstrap due to invalid config: %s", errs)
	}
	scepStaticChallenge = config["MOSYLE_SCEP_CHALLENGE"].(string)
	scepChallengeKey = strings.Trim(config["MOSYLE_SCEP_CHALLENGE_KEY"].(string), "%")
	if scepStaticChallenge != "" && scepChallengeKey != "" {
		return fmt.Errorf("MOSYLE_SCEP_CHALLENGE and MOSYLE_SCEP_CHALLENGE_KEY cannot both be set")
	}

	var timeout time.Duration
	timeoutConfig, timeoutErr := strconv.ParseInt(config["TIMEOUT"].(string), 10, 32)
	if timeoutErr != nil {
		timeout = time.Duration(10)
	} else {
		timeout = time.Duration(timeoutConfig)
	}
	shared.WriteLog(fmt.Sprintf("Mosyle timeout set as %d second", timeout), 1, 0)

	client = Client{
		baseUrl:     config["MOSYLE_BASE_URL"].(string),
		accessToken: config["MOSYLE_ACCESS_TOKEN"].(string),
		email:       config["MOSYLE_EMAIL"].(string),
		password:    config["MOSYLE_PASSWORD"].(string),
		timeout:     timeout,
	}

	// Parse compliance tags
	rawTags := config["MOSYLE_TAGS"].(string)
	if rawTags != "" {
		for _, t := range strings.Split(rawTags, ",") {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				complianceTags = append(complianceTags, trimmed)
			}
		}
		shared.WriteLog(fmt.Sprintf("Mosyle compliance tags configured: %v", complianceTags), 1, 0)
	}

	enrichEnabled, _ = strconv.ParseBool(config["MOSYLE_ENRICH"].(string))

	if err := client.login(); err != nil {
		return fmt.Errorf("failed to authenticate with Mosyle during bootstrap: %s", err)
	}

	// Sanity-check: a real API call that should return an empty result set rather than an auth error.
	_, err := client.listDevices("BOOTSTRAPTEST00", "ios")
	if err != nil {
		// "device not found" is expected and acceptable; any other error blocks startup.
		if err.Error() != "device not found" {
			return fmt.Errorf("failed to reach Mosyle API during bootstrap: %s", err)
		}
	}

	shared.WriteLog("Mosyle successfully bootstrapped and ready", 0, 0)
	return nil
}

// Handler handles an incoming webhook attestation request.
// handlerMode maps to the Mosyle os parameter:
//   - "" or "mobiledevice" → ios
//   - "computer"           → mac
//   - "tvos"               → tvos
//   - "visionos"           → visionos
func (p Provider) Handler(handlerMode string, stepInputData webhook.RequestBody) (webhook.ResponseBody, error) {
	if handlerMode == "" {
		handlerMode = "mobiledevice"
	}
	mosyleOS, ok := handlerModeToOS[handlerMode]
	if !ok {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("invalid handler mode %q: must be one of mobiledevice, computer, tvos, visionos", handlerMode)
	}

	if err := validateAttestData(stepInputData); err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}

	serial := stepInputData.AttestationData.PermanentIdentifier
	device, err := resolveDevice(serial, mosyleOS)
	if err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}

	if enrichEnabled {
		return webhook.ResponseBody{Allow: true, Data: buildEnrichData(device)}, nil
	}
	return webhook.ResponseBody{Allow: true}, nil
}

// SCEPHandler is a public function that is implemented as part of the Provider interface
// It is responsible for handling an individual SCEP challenge validation webhook request.
// It resolves the device serial number from the CSR subject, applies the same compliance
// checks as Handler (found, not deleted, MDM profile installed, compliance tag), and then
// checks the presented SCEP challenge against either the configured static challenge or the
// value stored against that device under MOSYLE_SCEP_CHALLENGE_KEY.
func (p Provider) SCEPHandler(handlerMode string, stepInputData webhook.RequestBody) (webhook.ResponseBody, error) {
	if handlerMode == "" {
		handlerMode = "mobiledevice"
	}
	mosyleOS, ok := handlerModeToOS[handlerMode]
	if !ok {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("invalid handler mode %q: must be one of mobiledevice, computer, tvos, visionos", handlerMode)
	}
	if stepInputData.X509CertificateRequest == nil || stepInputData.X509CertificateRequest.CertificateRequest == nil {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("received a SCEP request without a usable x509CertificateRequest")
	}
	serial, err := shared.ExtractSCEPSerial(stepInputData.X509CertificateRequest.Subject.SerialNumber, stepInputData.X509CertificateRequest.Subject.CommonName)
	if err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}

	if err := shared.ValidateSerial(serial); err != nil {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("serial number did not pass validation: %s", err)
	}

	device, err := resolveDevice(serial, mosyleOS)
	if err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}

	expected, err := expectedChallenge(device)
	if err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}
	if !shared.CompareChallenge(stepInputData.SCEPChallenge, expected) {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("SCEP challenge mismatch for serial %s", serial)
	}

	if enrichEnabled {
		return webhook.ResponseBody{Allow: true, Data: buildEnrichData(device)}, nil
	}
	return webhook.ResponseBody{Allow: true}, nil
}

// resolveDevice is a private function shared by Handler and SCEPHandler. It looks up a
// device by serial number and applies the compliance checks common to both flows: the
// device must be found, not deleted, have its MDM profile installed, and (if configured)
// carry one of the required compliance tags.
func resolveDevice(serial, mosyleOS string) (*MosyleDevice, error) {
	device, err := client.listDevices(serial, mosyleOS)
	if err != nil {
		if err.Error() == "device not found" {
			return nil, fmt.Errorf("serial number not found/enrolled in Mosyle (%s)", serial)
		}
		return nil, fmt.Errorf("error whilst communicating with Mosyle API: %s", err)
	}

	shared.WriteLog(fmt.Sprintf("Device record %s has been matched for serial number %s", device.UDID, serial), 1, 0)

	// Reject deleted devices
	if device.IsDeleted {
		return nil, fmt.Errorf("device %s is marked as deleted in Mosyle", serial)
	}

	// Reject devices whose MDM profile is not installed
	if device.Status != "INSTALLED" {
		return nil, fmt.Errorf("device %s status %q is not INSTALLED", serial, device.Status)
	}

	// Compliance tag check
	if len(complianceTags) > 0 {
		matched := ""
		for _, required := range complianceTags {
			for _, deviceTag := range device.Tags {
				if deviceTag == required {
					matched = required
					break
				}
			}
			if matched != "" {
				break
			}
		}
		if matched == "" {
			return nil, fmt.Errorf("%s does not carry any of compliance tags %v", serial, complianceTags)
		}
		shared.WriteLog(fmt.Sprintf("Device record %s carries compliance tag \"%s\"", device.UDID, matched), 1, 0)
	}

	return device, nil
}

// buildEnrichData is a private function shared by Handler and SCEPHandler that builds the
// enrichment data map returned to step-ca when enrichment is enabled.
func buildEnrichData(device *MosyleDevice) map[string]interface{} {
	return map[string]interface{}{
		"device": map[string]interface{}{
			"udid":            device.UDID,
			"serial_number":   device.Serial,
			"name":            device.DeviceName,
			"model":           device.DeviceModel,
			"os":              device.OS,
			"os_version":      device.OSVersion,
			"is_supervised":   bool(device.IsSupervised),
			"enrollment_type": device.EnrollmentType,
		},
		"user": map[string]interface{}{
			"userid": device.UserID,
		},
		"tags": device.Tags,
	}
}

// expectedChallenge is a private function that resolves the SCEP challenge expected for a
// device, either from the configured static challenge or from the device's Extra fields
// under the configured dynamic key.
func expectedChallenge(device *MosyleDevice) (string, error) {
	if scepStaticChallenge != "" {
		return scepStaticChallenge, nil
	}
	if scepChallengeKey != "" {
		for i := range device.CustomAttributes {
			attribute := device.CustomAttributes[i]
			if attribute.IsDeleted {
				continue
			}
			if attribute.ID() != scepChallengeKey && attribute.Name != scepChallengeKey {
				continue
			}
			if attribute.Value == "" {
				return "", fmt.Errorf("device %s has an empty value for custom device attribute %q", device.Serial, scepChallengeKey)
			}
			return attribute.Value, nil
		}
		// diagnostic listing of what the device does carry - identifiers only, never values
		available := make([]string, 0, len(device.CustomAttributes))
		for i := range device.CustomAttributes {
			available = append(available, fmt.Sprintf("%s (%s)", device.CustomAttributes[i].ID(), device.CustomAttributes[i].Name))
		}
		shared.WriteLog(fmt.Sprintf("SCEP challenge key %q not found on device %s; available custom device attributes: %v", scepChallengeKey, device.Serial, available), 1, 0)
		return "", fmt.Errorf("device %s has no value for MOSYLE_SCEP_CHALLENGE_KEY %q", device.Serial, scepChallengeKey)
	}
	return "", fmt.Errorf("SCEP challenge validation is not configured")
}

// listDevices calls POST /v1/devices and returns the first device matching the serial number.
func (c *Client) listDevices(serial, mosyleOS string) (*MosyleDevice, error) {
	if err := c.ensureToken(); err != nil {
		return nil, err
	}
	shared.WriteLog(fmt.Sprintf("Querying Mosyle for serial number %s (os=%s)", serial, mosyleOS), 2, 0)

	payload := map[string]interface{}{
		"operation": "list",
		"options": map[string]interface{}{
			"os":             mosyleOS,
			"serial_numbers": []string{serial},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %s", err)
	}

	httpClient := &http.Client{
		Timeout: time.Second * c.timeout,
	}
	request, err := http.NewRequest("POST", c.baseUrl+"/devices", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("accept", "application/json")
	request.Header.Set("accessToken", c.accessToken)
	request.Header.Set("Authorization", "Bearer "+c.bearerToken)

	response, err := httpClient.Do(request)
	shared.WriteLog(fmt.Sprintf("Response from %s/devices: %+v", c.baseUrl, response), 2, 0)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("authentication failed (%d) — check MOSYLE_ACCESS_TOKEN", response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d on POST %s/devices", response.StatusCode, c.baseUrl)
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %s", err)
	}

	var result mosyleListDevicesResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Mosyle response: %s", err)
	}

	if result.Status != "OK" {
		return nil, fmt.Errorf("Mosyle API returned non-OK status: %q", result.Status)
	}

	// The API may not support serial_numbers filtering; match client-side as a fallback.
	for i := range result.Response {
		for j := range result.Response[i].Devices {
			if result.Response[i].Devices[j].Serial == serial {
				d := result.Response[i].Devices[j]
				return &d, nil
			}
		}
	}

	return nil, fmt.Errorf("device not found")
}

// login authenticates against POST /v1/login and stores the bearer token from the
// Authorization response header. The token is valid for 24 hours; this connector
// refreshes it proactively after 23 hours.
func (c *Client) login() error {
	shared.WriteLog("Logging in to Mosyle API to acquire bearer token", 1, 0)

	payload := map[string]string{
		"email":    c.email,
		"password": c.password,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal login request: %s", err)
	}

	httpClient := &http.Client{Timeout: time.Second * c.timeout}
	request, err := http.NewRequest("POST", c.baseUrl+"/login", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to build login request: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("accessToken", c.accessToken)

	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to reach Mosyle login endpoint: %s", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication failed (%d) — check MOSYLE_ACCESS_TOKEN, MOSYLE_EMAIL and MOSYLE_PASSWORD", response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%d on POST %s/login", response.StatusCode, c.baseUrl)
	}

	authHeader := response.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("Mosyle login response missing Authorization header")
	}
	bearer := strings.TrimPrefix(authHeader, "Bearer ")
	if bearer == authHeader || bearer == "" {
		return fmt.Errorf("Mosyle login returned invalid Bearer token in Authorization header")
	}

	c.bearerToken = bearer
	c.tokenExpiry = time.Now().Add(23 * time.Hour)
	shared.WriteLog("Successfully acquired Mosyle bearer token", 1, 0)
	return nil
}

// ensureToken calls login if the bearer token is absent or has expired.
func (c *Client) ensureToken() error {
	if c.bearerToken == "" || time.Now().After(c.tokenExpiry) {
		return c.login()
	}
	return nil
}

// validateAttestData checks the serial number format before hitting the API.
func validateAttestData(stepInputData webhook.RequestBody) error {
	if stepInputData.AttestationData == nil {
		return fmt.Errorf("received a request without any attestationData")
	}
	if err := shared.ValidateSerial(stepInputData.AttestationData.PermanentIdentifier); err != nil {
		return fmt.Errorf("serial number did not pass validation: %s", err)
	}
	return nil
}
