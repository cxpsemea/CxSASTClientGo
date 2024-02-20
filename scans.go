package CxSASTClientGo

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	"github.com/pkg/errors"
)

func (c SASTClient) GetScan(scanid uint64) (Scan, error) {
	c.depwarn("GetScan", "GetScanByID")
	return c.GetScanByID(scanid)
}

func (c SASTClient) GetScanByID(scanid uint64) (Scan, error) {
	c.logger.Debugf("Get SAST scan %d", scanid)
	var scan Scan

	response, err := c.get(fmt.Sprintf("/sast/scans/%d", scanid))
	if err != nil {
		return scan, err
	}

	err = json.Unmarshal(response, &scan)
	return scan, err
}

func (c SASTClient) GetLastScan(projectid uint64) (Scan, error) {
	c.depwarn("GetLastScan", "GetLastScanByID")
	return c.GetLastScanByID(projectid)
}
func (c SASTClient) GetLastScanByID(projectid uint64) (Scan, error) {
	var scans []Scan
	response, err := c.get(fmt.Sprintf("/sast/scans?projectId=%d&scanStatus=Finished&last=1", projectid))
	if err != nil {
		return Scan{}, err
	}

	err = json.Unmarshal(response, &scans)
	if err != nil {
		return Scan{}, err
	}

	if len(scans) == 0 {
		return Scan{}, errors.New(fmt.Sprintf("No scans found in project %d", projectid))
	}

	return scans[0], nil
}

func (c SASTClient) GetEngineConfigurations() ([]EngineConfiguration, error) {
	var confs []EngineConfiguration
	response, err := c.get("/sast/engineConfigurations")
	if err != nil {
		return confs, err
	}

	err = json.Unmarshal(response, &confs)
	return confs, err
}

func (c SASTClient) GetEngineConfigurationsSOAP() ([]EngineConfiguration, error) {
	var confs []EngineConfiguration

	response, err := c.sendSOAPRequest("GetConfigurationSetList", "<SessionID></SessionID>")
	if err != nil {
		return confs, err
	}

	var xmlResponse struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			XMLName  xml.Name `xml:"Body"`
			Response struct {
				XMLName xml.Name `xml:"GetConfigurationSetListResponse"`
				Result  struct {
					XMLName      xml.Name `xml:"GetConfigurationSetListResult"`
					IsSuccesfull bool     `xml:"IsSuccesfull"`
					ErrorMessage string

					ConfigSetList struct {
						XMLName    xml.Name `xml:"ConfigSetList"`
						ConfigSets []struct {
							ConfigSetName string
							ID            uint
						} `xml:"ConfigurationSet"`
					}
				}
			}
		}
	}

	err = xml.Unmarshal(response, &xmlResponse)
	if err != nil {
		c.logger.Errorf("Failed to parse SOAP response: %s", err)
		c.logger.Tracef("Parsed from: %v", string(response))
		return confs, err
	}

	if !xmlResponse.Body.Response.Result.IsSuccesfull {
		return confs, fmt.Errorf("failed to get engine configurations: %v", xmlResponse.Body.Response.Result.ErrorMessage)
	}

	confs = make([]EngineConfiguration, len(xmlResponse.Body.Response.Result.ConfigSetList.ConfigSets))
	for id, conf := range xmlResponse.Body.Response.Result.ConfigSetList.ConfigSets {
		confs[id] = EngineConfiguration{
			ID:   conf.ID,
			Name: conf.ConfigSetName,
		}
	}

	return confs, err
}
