package jamf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/jedda/step-posture-connector/internal/shared"
	"github.com/smallstep/certificates/webhook"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Provider struct {
}

// Client defines a basic struct used by the provider to store it's API config, token & expiry time
type Client struct {
	baseUrl, clientId, clientSecret string
	timeout                         time.Duration
	token                           JamfAPIAuthToken
	tokenExpiry                     *time.Time
}

// JamfAPIAuthToken defines the JSON format returned from /api/oauth/token (Jamf API)
type JamfAPIAuthToken struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// JamfExtensionAttribute defines a single extension attribute entry, as returned by the Jamf
// Classic API for both mobile devices and computers. It is how a dynamic SCEP challenge (or
// any other custom field) is located on a device record - by attribute name.
type JamfExtensionAttribute struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// JamfClassicMobileDevice defines the JSON format returned from /JSSResource/mobiledevices/serialnumber/%s (Jamf API)
type JamfClassicMobileDevice struct {
	MobileDevice struct {
		General struct {
			UDID         string `json:"udid"`
			Name         string `json:"device_name"`
			SerialNumber string `json:"serial_number"`
		} `json:"general"`
		Location struct {
			Username     string `json:"username"`
			RealName     string `json:"realname"`
			EmailAddress string `json:"email_address"`
			Position     string `json:"position"`
			Department   string `json:"department"`
		} `json:"location"`
		MobileDeviceGroups []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"mobile_device_groups"`
		ExtensionAttributes []JamfExtensionAttribute `json:"extension_attributes"`
	} `json:"mobile_device"`
}

// JamfClassicComputer defines the JSON format returned from /JSSResource/computers/serialnumber/%s (Jamf API)
type JamfClassicComputer struct {
	Computer struct {
		General struct {
			UDID         string `json:"udid"`
			Name         string `json:"name"`
			SerialNumber string `json:"serial_number"`
		} `json:"general"`
		Location struct {
			Username     string `json:"username"`
			RealName     string `json:"realname"`
			EmailAddress string `json:"email_address"`
			Position     string `json:"position"`
			Department   string `json:"department"`
		} `json:"location"`
		GroupsAccounts struct {
			ComputerGroupMemberships []string `json:"computer_group_memberships"`
		} `json:"groups_accounts"`
		ExtensionAttributes []JamfExtensionAttribute `json:"extension_attributes"`
	} `json:"computer"`
}

// resolvedDevice normalises the fields shared by Jamf's mobile device and computer records,
// so that Handler and SCEPHandler (and their shared helpers) don't need to branch on
// handlerMode past the initial API lookup.
type resolvedDevice struct {
	UDID                string
	Name                string
	SerialNumber        string
	Username            string
	RealName            string
	EmailAddress        string
	Position            string
	Department          string
	Groups              []string
	ExtensionAttributes []JamfExtensionAttribute
}

var client Client
var validate *validator.Validate
var config map[string]interface{}
var scepStaticChallenge string
var scepChallengeKey string

// Bootstrap is a public function that is implemented as part of the Provider interface
// It is responsible for setting up and testing the provider then letting the main package
// know about any errors or issues that have stopped a provider bootstrapping correctly
func (p Provider) Bootstrap() error {
	validate = validator.New(validator.WithRequiredStructEnabled())
	config = map[string]interface{}{
		"JAMF_BASE_URL":           os.Getenv("JAMF_BASE_URL"),
		"JAMF_CLIENT_ID":          os.Getenv("JAMF_CLIENT_ID"),
		"JAMF_CLIENT_SECRET":      os.Getenv("JAMF_CLIENT_SECRET"),
		"JAMF_DEVICE_GROUP":       os.Getenv("JAMF_DEVICE_GROUP"),
		"JAMF_COMPUTER_GROUP":     os.Getenv("JAMF_COMPUTER_GROUP"),
		"JAMF_DEVICE_ENRICH":      os.Getenv("JAMF_DEVICE_ENRICH"),
		"JAMF_COMPUTER_ENRICH":    os.Getenv("JAMF_COMPUTER_ENRICH"),
		"JAMF_SCEP_CHALLENGE":     os.Getenv("JAMF_SCEP_CHALLENGE"),
		"JAMF_SCEP_CHALLENGE_KEY": os.Getenv("JAMF_SCEP_CHALLENGE_KEY"),
		"TIMEOUT":                 os.Getenv("TIMEOUT"),
	}
	rules := map[string]interface{}{
		"JAMF_BASE_URL":           "required,url",
		"JAMF_CLIENT_ID":          "required,uuid",
		"JAMF_CLIENT_SECRET":      "required",
		"JAMF_DEVICE_GROUP":       "omitempty",
		"JAMF_COMPUTER_GROUP":     "omitempty",
		"JAMF_DEVICE_ENRICH":      "omitempty,oneof=0 1",
		"JAMF_COMPUTER_ENRICH":    "omitempty,oneof=0 1",
		"JAMF_SCEP_CHALLENGE":     "omitempty",
		"JAMF_SCEP_CHALLENGE_KEY": "omitempty",
		"TIMEOUT":                 "omitempty,number,max=2",
	}
	errs := validate.ValidateMap(config, rules)
	if len(errs) > 0 {
		return fmt.Errorf("Jamf failed to bootstrap due to invalid config: %s", errs)
	}
	scepStaticChallenge = config["JAMF_SCEP_CHALLENGE"].(string)
	scepChallengeKey = strings.Trim(config["JAMF_SCEP_CHALLENGE_KEY"].(string), "%")
	if scepStaticChallenge != "" && scepChallengeKey != "" {
		return fmt.Errorf("JAMF_SCEP_CHALLENGE and JAMF_SCEP_CHALLENGE_KEY cannot both be set")
	}
	var timeout time.Duration
	timeoutConfig, timeoutErr := strconv.ParseInt(config["TIMEOUT"].(string), 10, 32)
	if timeoutErr != nil {
		timeout = time.Duration(10)
	} else {
		timeout = time.Duration(timeoutConfig)
	}
	shared.WriteLog(fmt.Sprintf("Jamf timeout set as %d second", timeout), 1, 0)
	// instantiate Client
	client = Client{
		baseUrl:      config["JAMF_BASE_URL"].(string),
		clientId:     config["JAMF_CLIENT_ID"].(string),
		clientSecret: config["JAMF_CLIENT_SECRET"].(string),
		timeout:      timeout,
	}
	if err := client.refreshAuthToken(); err != nil {
		return fmt.Errorf("failed to authenticate to Jamf API: %s", err)
	}
	shared.WriteLog("Jamf successfully bootstrapped and ready", 0, 0)
	return nil
}

// Handler is a public function that is implemented as part of the Provider interface
// It is responsible for handling an individual webhook request and returning a webhook.ResponseBody
func (p Provider) Handler(handlerMode string, stepInputData webhook.RequestBody) (webhook.ResponseBody, error) {

	// for Jamf, we have two device types
	// - Mobile Devices (iOS/iPad/iPhone)
	// - Computers (Macs)
	// we need to know the device type coming in as they have different API endpoints
	// thus, the handlerMode string on this method as either "mobiledevice" or "computer"

	deviceEnrich, _ := strconv.ParseBool(config["JAMF_DEVICE_ENRICH"].(string))
	computerEnrich, _ := strconv.ParseBool(config["JAMF_COMPUTER_ENRICH"].(string))

	// default handlerMode to mobiledevice
	if handlerMode == "" {
		handlerMode = "mobiledevice"
	}
	err := validate.Var(handlerMode, "required,oneof=computer mobiledevice")
	if err != nil {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("invalid handler type: %s", err)
	}

	// validate our attestation data
	validateErr := validateAttestData(stepInputData)
	if validateErr != nil {
		return webhook.ResponseBody{Allow: false}, validateErr
	}

	resolved, err := resolveDevice(handlerMode, stepInputData.AttestationData.PermanentIdentifier)
	if err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}

	enrich := (handlerMode == "mobiledevice" && deviceEnrich) || (handlerMode == "computer" && computerEnrich)
	if enrich {
		return webhook.ResponseBody{Allow: true, Data: buildEnrichData(resolved)}, nil
	}
	return webhook.ResponseBody{Allow: true}, nil
}

// SCEPHandler is a public function that is implemented as part of the Provider interface
// It is responsible for handling an individual SCEP challenge validation webhook request.
// It resolves the device serial number from the CSR subject, applies the same lookup and
// compliance group check as Handler, and then checks the presented SCEP challenge against
// either the configured static challenge or the value of the extension attribute named by
// JAMF_SCEP_CHALLENGE_KEY.
func (p Provider) SCEPHandler(handlerMode string, stepInputData webhook.RequestBody) (webhook.ResponseBody, error) {
	deviceEnrich, _ := strconv.ParseBool(config["JAMF_DEVICE_ENRICH"].(string))
	computerEnrich, _ := strconv.ParseBool(config["JAMF_COMPUTER_ENRICH"].(string))

	if handlerMode == "" {
		handlerMode = "mobiledevice"
	}
	if err := validate.Var(handlerMode, "required,oneof=computer mobiledevice"); err != nil {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("invalid handler type: %s", err)
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

	resolved, err := resolveDevice(handlerMode, serial)
	if err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}

	expected, err := expectedChallenge(resolved)
	if err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}
	if !shared.CompareChallenge(stepInputData.SCEPChallenge, expected) {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("SCEP challenge mismatch for serial %s", serial)
	}

	enrich := (handlerMode == "mobiledevice" && deviceEnrich) || (handlerMode == "computer" && computerEnrich)
	if enrich {
		return webhook.ResponseBody{Allow: true, Data: buildEnrichData(resolved)}, nil
	}
	return webhook.ResponseBody{Allow: true}, nil
}

// resolveDevice is a private function shared by Handler and SCEPHandler. It looks up a
// device by serial number for the given handlerMode ("mobiledevice" or "computer"),
// normalises the response into a resolvedDevice, and enforces the optional compliance
// group membership check.
func resolveDevice(handlerMode, serial string) (*resolvedDevice, error) {
	deviceGroup, _ := config["JAMF_DEVICE_GROUP"].(string)
	computerGroup, _ := config["JAMF_COMPUTER_GROUP"].(string)

	response, err := client.doGet(fmt.Sprintf("/JSSResource/%ss/serialnumber/%s", handlerMode, serial))
	if err != nil {
		if err.Error() == "404" {
			return nil, fmt.Errorf("serial number not found/enrolled (404 on \"/JSSResource/%ss/serialnumber/%s\")", handlerMode, serial)
		}
		return nil, fmt.Errorf("error whilst communicating with Jamf API: %s", err)
	}

	resolved := &resolvedDevice{}
	var groupMatch bool

	if handlerMode == "mobiledevice" {
		var mobileDevice JamfClassicMobileDevice
		if err := json.Unmarshal(response, &mobileDevice); err != nil {
			return nil, fmt.Errorf("error fwhen unmarsalling Jamf API JSON: %s", err)
		}
		shared.WriteLog(fmt.Sprintf("Mobile device record %s has been matched for serial number %s", mobileDevice.MobileDevice.General.UDID, serial), 1, 0)
		resolved.UDID = mobileDevice.MobileDevice.General.UDID
		resolved.Name = mobileDevice.MobileDevice.General.Name
		resolved.SerialNumber = mobileDevice.MobileDevice.General.SerialNumber
		resolved.Username = mobileDevice.MobileDevice.Location.Username
		resolved.RealName = mobileDevice.MobileDevice.Location.RealName
		resolved.EmailAddress = mobileDevice.MobileDevice.Location.EmailAddress
		resolved.Position = mobileDevice.MobileDevice.Location.Position
		resolved.Department = mobileDevice.MobileDevice.Location.Department
		resolved.ExtensionAttributes = mobileDevice.MobileDevice.ExtensionAttributes
		for i := range mobileDevice.MobileDevice.MobileDeviceGroups {
			name := mobileDevice.MobileDevice.MobileDeviceGroups[i].Name
			resolved.Groups = append(resolved.Groups, name)
			if deviceGroup != "" && name == deviceGroup {
				groupMatch = true
				shared.WriteLog(fmt.Sprintf("Mobile device record %s is a member of \"%s\"", resolved.UDID, deviceGroup), 1, 0)
			}
		}
		if deviceGroup != "" && !groupMatch {
			return nil, fmt.Errorf("%s is not a member of supplied compliance group \"%s\"", serial, deviceGroup)
		}
	} else if handlerMode == "computer" {
		var computer JamfClassicComputer
		if err := json.Unmarshal(response, &computer); err != nil {
			return nil, fmt.Errorf("error fwhen unmarsalling Jamf API JSON: %s", err)
		}
		shared.WriteLog(fmt.Sprintf("Computer record %s has been matched for serial number %s", computer.Computer.General.UDID, serial), 1, 0)
		resolved.UDID = computer.Computer.General.UDID
		resolved.Name = computer.Computer.General.Name
		resolved.SerialNumber = computer.Computer.General.SerialNumber
		resolved.Username = computer.Computer.Location.Username
		resolved.RealName = computer.Computer.Location.RealName
		resolved.EmailAddress = computer.Computer.Location.EmailAddress
		resolved.Position = computer.Computer.Location.Position
		resolved.Department = computer.Computer.Location.Department
		resolved.ExtensionAttributes = computer.Computer.ExtensionAttributes
		for i := range computer.Computer.GroupsAccounts.ComputerGroupMemberships {
			name := computer.Computer.GroupsAccounts.ComputerGroupMemberships[i]
			resolved.Groups = append(resolved.Groups, name)
			if computerGroup != "" && name == computerGroup {
				groupMatch = true
				shared.WriteLog(fmt.Sprintf("Computer device record %s is a member of \"%s\"", resolved.UDID, computerGroup), 1, 0)
			}
		}
		if computerGroup != "" && !groupMatch {
			return nil, fmt.Errorf("%s is not a member of supplied compliance group \"%s\"", serial, computerGroup)
		}
	}

	return resolved, nil
}

// buildEnrichData is a private function shared by Handler and SCEPHandler that builds the
// enrichment data map returned to step-ca when enrichment is enabled.
func buildEnrichData(resolved *resolvedDevice) map[string]interface{} {
	return map[string]interface{}{
		"device": map[string]interface{}{
			"udid":          resolved.UDID,
			"serial_number": resolved.SerialNumber,
			"name":          resolved.Name,
		},
		"user": map[string]interface{}{
			"username":      resolved.Username,
			"realname":      resolved.RealName,
			"email_address": resolved.EmailAddress,
			"position":      resolved.Position,
			"department":    resolved.Department,
		},
		"groups": resolved.Groups,
	}
}

// expectedChallenge is a private function that resolves the SCEP challenge expected for a
// device, either from the configured static challenge or from the value of the extension
// attribute named by JAMF_SCEP_CHALLENGE_KEY.
func expectedChallenge(resolved *resolvedDevice) (string, error) {
	if scepStaticChallenge != "" {
		return scepStaticChallenge, nil
	}
	if scepChallengeKey != "" {
		for _, attr := range resolved.ExtensionAttributes {
			if attr.Name == scepChallengeKey {
				if attr.Value == "" {
					return "", fmt.Errorf("extension attribute %q is empty for device %s", scepChallengeKey, resolved.SerialNumber)
				}
				return attr.Value, nil
			}
		}
		names := make([]string, 0, len(resolved.ExtensionAttributes))
		for _, attr := range resolved.ExtensionAttributes {
			names = append(names, attr.Name)
		}
		shared.WriteLog(fmt.Sprintf("SCEP challenge extension attribute %q not found on device %s; available extension attribute names: %v", scepChallengeKey, resolved.SerialNumber, names), 1, 0)
		return "", fmt.Errorf("device %s has no extension attribute named by JAMF_SCEP_CHALLENGE_KEY %q", resolved.SerialNumber, scepChallengeKey)
	}
	return "", fmt.Errorf("SCEP challenge validation is not configured")
}

// refreshAuthToken is a private function that is responsible for handling check & refresh
// of the bearer token to be used with Jamf Pro's API. If an error is found it is returned
// and this will chain back up to a webhook deny response.
func (client *Client) refreshAuthToken() error {
	// check if we have a current token and it's validity window is open
	if client.tokenExpiry != nil && client.tokenExpiry.After(time.Now()) {
		// token should be valid
		shared.WriteLog(fmt.Sprintf("Jamf auth token is valid until %s - no need to refresh", client.tokenExpiry), 1, 0)
		return nil
	}
	// setup the auth form and POST to Jamf API
	httpClient := &http.Client{
		Timeout: time.Second * client.timeout,
	}
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.clientId},
		"client_secret": {client.clientSecret},
	}
	request, err := http.NewRequest("POST", fmt.Sprintf("%s/api/oauth/token", client.baseUrl), bytes.NewBufferString(data.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request)
	shared.WriteLog(fmt.Sprintf("Response from %s/api/oauth/token %+v", client.baseUrl, response), 2, 0)

	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("%s", body)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err.Error())
	}
	var authToken JamfAPIAuthToken
	unmarshalErr := json.Unmarshal(body, &authToken)
	if unmarshalErr != nil {
		return fmt.Errorf("error fwhen unmarsalling json: %s", unmarshalErr)
	}

	// need to do more error checking here
	expiry := time.Now().Add(time.Duration(authToken.ExpiresIn) * time.Second)
	client.tokenExpiry = &expiry
	client.token = authToken
	shared.WriteLog(fmt.Sprintf("Successfully refreshed Jamf API token. Will expire %s", expiry), 1, 0)
	return nil
}

// refreshAuthToken is a private function that is responsible for handling a HTTP GET
// from Jamf Pro's API. If an error is found it is returned and this will chain back up
// to a webhook deny response.
func (client *Client) doGet(uri string) ([]byte, error) {
	// TODO implement https://pkg.go.dev/net/http/httptrace as a debug thing
	shared.WriteLog(fmt.Sprintf("Have been asked to GET %s/%s", client.baseUrl, uri), 2, 0)
	// refresh token if required
	err := client.refreshAuthToken()
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Timeout: time.Second * client.timeout,
	}
	request, err := http.NewRequest("GET", client.baseUrl+uri, nil)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	request.Header.Add("accept", "application/json")
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", client.token.AccessToken))
	response, err := httpClient.Do(request)
	shared.WriteLog(fmt.Sprintf("Response from %s/api/oauth/token %+v", client.baseUrl, response), 2, 0)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	if response.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("404")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d on GET (%s)", response.StatusCode, client.baseUrl+uri)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s", err.Error())
	}
	return body, nil
}

// validateAttestData is a private function that is responsible for any additional
// validation prior to asking Jamf. Currently it ensures a device serial number can be
// validated against known formats. If an error is found it is returned and this will
// chain back up to a webhook deny response.
func validateAttestData(stepInputData webhook.RequestBody) error {
	if stepInputData.AttestationData == nil {
		return fmt.Errorf("received a request without any attestationData")
	}
	if err := shared.ValidateSerial(stepInputData.AttestationData.PermanentIdentifier); err != nil {
		return fmt.Errorf("serial number did not pass validation: %s", err)
	}
	return nil
}
