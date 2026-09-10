package file

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/jedda/step-posture-connector/internal/shared"
	"github.com/smallstep/certificates/webhook"
	"io"
	"os"
	"strings"
)

type Provider struct {
}

// Data defines a holding struct for device data parsed from a file
type Data struct {
	Devices []Device `json:"devices"`
}

// Device defines an individual device struct parsed from a file
type Device struct {
	Identifier string                 `json:"identifier"`
	Data       map[string]interface{} `json:"data"`
}

var validate *validator.Validate
var config map[string]interface{}
var data Data
var scepStaticChallenge string
var scepChallengeKey string

// Bootstrap is a public function that is implemented as part of the Provider interface
// It is responsible for setting up and testing the provider then letting the main package
// know about any errors or issues that have stopped a provider bootstrapping correctly
func (p Provider) Bootstrap() error {
	validate = validator.New(validator.WithRequiredStructEnabled())
	config = map[string]interface{}{
		"FILE_PATH":               os.Getenv("FILE_PATH"),
		"FILE_TYPE":               os.Getenv("FILE_TYPE"),
		"FILE_SCEP_CHALLENGE":     os.Getenv("FILE_SCEP_CHALLENGE"),
		"FILE_SCEP_CHALLENGE_KEY": os.Getenv("FILE_SCEP_CHALLENGE_KEY"),
	}
	rules := map[string]interface{}{
		"FILE_PATH":               "required,file",
		"FILE_TYPE":               "required,oneof=json csv",
		"FILE_SCEP_CHALLENGE":     "omitempty",
		"FILE_SCEP_CHALLENGE_KEY": "omitempty",
	}
	errs := validate.ValidateMap(config, rules)
	if len(errs) > 0 {
		return fmt.Errorf("JSON provider could not bootstrap due to invalid config: %s", errs)
	}
	scepStaticChallenge = config["FILE_SCEP_CHALLENGE"].(string)
	scepChallengeKey = strings.Trim(config["FILE_SCEP_CHALLENGE_KEY"].(string), "%")
	if scepStaticChallenge != "" && scepChallengeKey != "" {
		return fmt.Errorf("FILE_SCEP_CHALLENGE and FILE_SCEP_CHALLENGE_KEY cannot both be set")
	}
	file, err := os.Open(config["FILE_PATH"].(string))
	if err != nil {
		return fmt.Errorf("could not open %s for read: %s", config["FILE_PATH"].(string), err)
	}
	defer func() { _ = file.Close() }()
	if config["FILE_TYPE"] == "json" {
		jsonBytes, _ := io.ReadAll(file)
		err := parseJSON(jsonBytes)
		if err != nil {
			return err
		}
	} else if config["FILE_TYPE"] == "csv" {
		csvBytes, _ := io.ReadAll(file)
		err := parseCSV(csvBytes)
		if err != nil {
			return err
		}
	}
	shared.WriteLog(fmt.Sprintf("%d devices loaded from %s.", len(data.Devices), config["FILE_PATH"].(string)), 1, 0)
	shared.WriteLog("File provider successfully bootstrapped and ready.", 0, 0)
	return nil
}

// Handler is a public function that is implemented as part of the Provider interface
// It is responsible for handling an individual webhook request and returning a webhook.ResponseBody
func (p Provider) Handler(handlerMode string, stepInputData webhook.RequestBody) (webhook.ResponseBody, error) {
	if stepInputData.AttestationData == nil {
		return webhook.ResponseBody{Allow: false}, fmt.Errorf("received a request without any attestationData")
	}
	device, err := findDevice(stepInputData.AttestationData.PermanentIdentifier)
	if err != nil {
		return webhook.ResponseBody{Allow: false}, err
	}
	// Data is an any on webhook.ResponseBody, so an unpopulated map would
	// still read as non-nil downstream - only set it when the device has data
	if len(device.Data) > 0 {
		return webhook.ResponseBody{Allow: true, Data: device.Data}, nil
	}
	return webhook.ResponseBody{Allow: true}, nil
}

// SCEPHandler is a public function that is implemented as part of the Provider interface
// It is responsible for handling an individual SCEP challenge validation webhook request.
// It checks that the device serial number extracted from the CSR subject is registered in
// the file, and that the presented SCEP challenge matches either the configured static
// challenge, or the value stored against that device under FILE_SCEP_CHALLENGE_KEY.
func (p Provider) SCEPHandler(handlerMode string, stepInputData webhook.RequestBody) (webhook.ResponseBody, error) {
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
	device, err := findDevice(serial)
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
	if len(device.Data) > 0 {
		return webhook.ResponseBody{Allow: true, Data: device.Data}, nil
	}
	return webhook.ResponseBody{Allow: true}, nil
}

// findDevice is a private function that looks up a device by identifier (serial number),
// shared by both Handler and SCEPHandler.
func findDevice(identifier string) (*Device, error) {
	for i := range data.Devices {
		if data.Devices[i].Identifier == identifier {
			return &data.Devices[i], nil
		}
	}
	return nil, fmt.Errorf("device identifier (%s) not matched in file", identifier)
}

// expectedChallenge is a private function that resolves the SCEP challenge expected for a
// device, either from the configured static challenge or from the device's own data under
// the configured dynamic key.
func expectedChallenge(device *Device) (string, error) {
	if scepStaticChallenge != "" {
		return scepStaticChallenge, nil
	}
	if scepChallengeKey != "" {
		value, ok := device.Data[scepChallengeKey]
		if !ok {
			shared.WriteLog(fmt.Sprintf("SCEP challenge key %q not found on device %s; available keys: %v", scepChallengeKey, device.Identifier, dataKeys(device.Data)), 1, 0)
			return "", fmt.Errorf("device %s has no value for FILE_SCEP_CHALLENGE_KEY %q", device.Identifier, scepChallengeKey)
		}
		str, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("device %s value for FILE_SCEP_CHALLENGE_KEY %q is not a string", device.Identifier, scepChallengeKey)
		}
		return str, nil
	}
	return "", fmt.Errorf("SCEP challenge validation is not configured")
}

// dataKeys is a private function that returns the field names present in a device's data map,
// used only for diagnostic logging - never the values themselves.
func dataKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// parseJSON is a private function that unmarshals a JSON byte slice
// and stores it in our data variable.
// it returns an error if one is encountered
func parseJSON(jsonBytes []byte) error {
	err := json.Unmarshal(jsonBytes, &data)
	if err != nil {
		return err
	}
	return nil
}

// parseCSV is a private function that reads in a CSV byte slice
// then processes headers and rows into storage in our data variable.
// it returns an error if one is encountered
func parseCSV(csvBytes []byte) error {
	csvReader := csv.NewReader(bytes.NewBuffer(csvBytes))
	csvData, err := csvReader.ReadAll()
	if err != nil {
		return err
	}
	// check for headers
	headers := csvData[0]
	if len(headers) == 0 || strings.Compare(headers[0], "Identifier") != 0 {
		return fmt.Errorf("first csv header must be Identifier: found %s", headers[0])
	}
	shared.WriteLog(fmt.Sprintf("Loaded fields from file: %+v", headers), 2, 0)
	for i := range csvData {
		if i > 0 {
			var enrichData = map[string]interface{}{}
			for o := range csvData[i] {
				if o > 0 {
					enrichData[headers[o]] = csvData[i][o]
				}
			}
			shared.WriteLog(fmt.Sprintf("Loaded device from file: %s, %+v", csvData[i][0], enrichData), 2, 0)
			data.Devices = append(data.Devices, Device{Identifier: csvData[i][0], Data: enrichData})
		}
	}
	return nil
}
