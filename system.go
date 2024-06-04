package CxSASTClientGo

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func (c SASTClient) GetVersionSOAP() (ApplicationVersion, error) {
	response, err := c.sendSOAPRequest("GetVersionNumber", "<sessionID></sessionID>")
	if err != nil {
		return ApplicationVersion{}, err
	}

	var xmlResponse struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			XMLName  xml.Name `xml:"Body"`
			Response struct {
				XMLName xml.Name `xml:"GetVersionNumberResponse"`
				Result  struct {
					XMLName            xml.Name `xml:"GetVersionNumberResult"`
					IsSuccesfull       bool     `xml:"IsSuccesfull"`
					ErrorMessage       string
					Version            string `xml:"Version"`
					ApplicationVersion string `xml:"ApplicationVersion"`
					EnginePackVersion  string `xml:"EnginePackVersion"`
				}
			}
		}
	}

	err = xml.Unmarshal(response, &xmlResponse)
	if err != nil {
		return ApplicationVersion{}, err
	}

	result := xmlResponse.Body.Response.Result
	if !result.IsSuccesfull {
		return ApplicationVersion{}, fmt.Errorf("failed to get version: %v", result.ErrorMessage)
	}

	var version ApplicationVersion
	version.ApplicationVersion = result.ApplicationVersion
	version.EnginePack = result.EnginePackVersion

	if index := strings.Index(result.Version, "HF"); index >= 0 {
		version.HotFix, _ = strconv.Atoi(result.Version[index+2:])
	}

	return version, nil
}

func (c SASTClient) GetCustomFields() ([]ProjectCustomField, error) {
	var fields []ProjectCustomField
	response, err := c.sendRequest(http.MethodGet, "/customFields", nil, nil)
	if err != nil {
		return fields, err
	}

	err = json.Unmarshal(response, &fields)
	return fields, err
}
