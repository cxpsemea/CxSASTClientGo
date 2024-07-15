package CxSASTClientGo

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
)

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
							ID            uint64
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

func (c SASTClient) GetProjectLastFullScanIDODATA(project *Project) (uint64, error) {
	response, err := c.sendODATARequest(fmt.Sprintf("v1/Scans?$filter=IsIncremental%%20eq%%20false%%20and%%20ScanType%%20eq%%201%%20and%%20ProjectId%%20eq%%20%d&$select=Id&$orderby=EngineFinishedOn%%20desc&$top=1", project.ProjectID))
	if err != nil {
		return 0, err
	}

	type responseStruct struct {
		Value []struct {
			Id uint64 `json:"Id"`
		} `json:"value"`
	}

	var rs responseStruct

	err = json.Unmarshal(response, &rs)
	if err != nil {
		return 0, err
	}

	if len(rs.Value) != 1 {
		return 0, fmt.Errorf("no last full scan available")
	}

	return rs.Value[0].Id, nil

}

func (c SASTClient) GetScanSourceCodeByIDSOAP(scanId uint64) ([]byte, error) {
	var zipfile []byte
	type Envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Text    string   `xml:",chardata"`
		Soap    string   `xml:"soap,attr"`
		Xsi     string   `xml:"xsi,attr"`
		Xsd     string   `xml:"xsd,attr"`
		Body    struct {
			Text                         string `xml:",chardata"`
			GetSourceCodeForScanResponse struct {
				Text                       string `xml:",chardata"`
				Xmlns                      string `xml:"xmlns,attr"`
				GetSourceCodeForScanResult struct {
					Text                string `xml:",chardata"`
					IsSuccesfull        string `xml:"IsSuccesfull"`
					SourceCodeContainer struct {
						Text       string `xml:",chardata"`
						ZippedFile string `xml:"ZippedFile"`
						FileName   string `xml:"FileName"`
					} `xml:"sourceCodeContainer"`
				} `xml:"GetSourceCodeForScanResult"`
			} `xml:"GetSourceCodeForScanResponse"`
		} `xml:"Body"`
	}

	response, err := c.sendSOAPRequestAudit_v7("GetSourceCodeForScan", fmt.Sprintf("<sessionID></sessionID><scanId>%v</scanId>", scanId))
	if err != nil {
		return zipfile, err
	}

	var env Envelope
	if err = xml.Unmarshal(response, &env); err != nil {
		return zipfile, err
	}

	return base64.StdEncoding.DecodeString(env.Body.GetSourceCodeForScanResponse.GetSourceCodeForScanResult.SourceCodeContainer.ZippedFile)
}

func (c SASTClient) GetSourcesByScanIDSOAP(scanId uint64, files []string) ([]SourceFile, error) {
	sourceFiles := make([]SourceFile, 0)
	type Envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Text    string   `xml:",chardata"`
		Soap    string   `xml:"soap,attr"`
		Xsi     string   `xml:"xsi,attr"`
		Xsd     string   `xml:"xsd,attr"`
		Body    struct {
			Text                       string `xml:",chardata"`
			GetSourcesByScanIDResponse struct {
				Text                     string `xml:",chardata"`
				Xmlns                    string `xml:"xmlns,attr"`
				GetSourcesByScanIDResult struct {
					Text                       string `xml:",chardata"`
					IsSuccesfull               string `xml:"IsSuccesfull"`
					CxWSResponseSourcesContent struct {
						Text                      string `xml:",chardata"`
						CxWSResponseSourceContent []struct {
							Text         string `xml:",chardata"`
							IsSuccesfull string `xml:"IsSuccesfull"`
							Source       string `xml:"Source"`
						} `xml:"CxWSResponseSourceContent"`
					} `xml:"cxWSResponseSourcesContent"`
					Encode string `xml:"Encode"`
				} `xml:"GetSourcesByScanIDResult"`
			} `xml:"GetSourcesByScanIDResponse"`
		} `xml:"Body"`
	}

	normalizedFiles := []string{}
	for _, file := range files {
		if file[0] != '/' && file[0] != '\\' {
			normalizedFiles = append(normalizedFiles, "/"+file)
		} else {
			normalizedFiles = append(normalizedFiles, file)
		}
	}

	//c.logger.Tracef("Download scan %d files: %v", scanId, strings.Join(normalizedFiles, ", "))

	response, err := c.sendSOAPRequest("GetSourcesByScanID", fmt.Sprintf("<sessionID></sessionID><scanID>%v</scanID><filesToRetreive><string>%v</string></filesToRetreive>", scanId, strings.Join(normalizedFiles, "</string><string>")))
	if err != nil {
		return sourceFiles, err
	}

	var env Envelope
	if err = xml.Unmarshal(response, &env); err != nil {
		return sourceFiles, err
	}

	for id, f := range env.Body.GetSourcesByScanIDResponse.GetSourcesByScanIDResult.CxWSResponseSourcesContent.CxWSResponseSourceContent {
		sourceFiles = append(sourceFiles, SourceFile{
			Filename: files[id],
			Source:   f.Source,
		})
	}

	return sourceFiles, nil
}

func (c SASTClient) GetScanSettingsByIDSOAP(scanId uint64) (ScanSettingsSOAP, error) {
	type Envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Text    string   `xml:",chardata"`
		Soap    string   `xml:"soap,attr"`
		Xsi     string   `xml:"xsi,attr"`
		Xsd     string   `xml:"xsd,attr"`
		Body    struct {
			Text                   string `xml:",chardata"`
			GetScanSummaryResponse struct {
				Text                 string           `xml:",chardata"`
				Xmlns                string           `xml:"xmlns,attr"`
				GetScanSummaryResult ScanSettingsSOAP `xml:"GetScanSummaryResult"`
			} `xml:"GetScanSummaryResponse"`
		} `xml:"Body"`
	}

	response, err := c.sendSOAPRequest("GetScanSummary", fmt.Sprintf("<i_SessionID></i_SessionID><i_ScanID>%v</i_ScanID>", scanId))
	if err != nil {
		return ScanSettingsSOAP{}, err
	}

	var env Envelope
	if err = xml.Unmarshal(response, &env); err != nil {
		return ScanSettingsSOAP{}, err
	}

	return env.Body.GetScanSummaryResponse.GetScanSummaryResult, nil
}

func (s *Scan) String() string {
	return fmt.Sprintf("Scan %d - Project %d, %d LOC: %v %v", s.ScanID, s.Project.ID, s.ScanState.LOC, s.Status.Name, s.DateAndTime.FinishedOn.Format(time.RFC3339))
}

func (c SASTClient) GetAllPathResultInfos(scanId uint64) ([]PathResultInfo, error) {
	var pris []PathResultInfo

	results, err := c.GetResultsForScanSOAP(scanId)
	if err != nil {
		return pris, err
	}

	sourceFiles := []string{}
	for _, r := range results {
		if len(r.Nodes) > 0 {
			if !slices.Contains(sourceFiles, r.Nodes[0].FileName) {
				sourceFiles = append(sourceFiles, r.Nodes[0].FileName)
			}
			if !slices.Contains(sourceFiles, r.Nodes[len(r.Nodes)-1].FileName) {
				sourceFiles = append(sourceFiles, r.Nodes[len(r.Nodes)-1].FileName)
			}
		}
	}

	//c.logger.Tracef("Expecting to get %d files", len(sourceFiles))
	code := make(map[string][]string)

	batchSize := 10
	for start := 0; start < len(sourceFiles); start += batchSize {
		end := start + batchSize
		if end > len(sourceFiles) {
			end = len(sourceFiles)
		}
		//c.logger.Tracef("Downloading files: %v", strings.Join(sourceFiles[start:end], ", "))
		files, err := c.GetSourcesByScanIDSOAP(scanId, sourceFiles[start:end])
		if err != nil {
			return pris, err
		}

		for _, sf := range files {
			code[sf.Filename] = regexp.MustCompile("\r?\n").Split(sf.Source, -1)
			//c.logger.Tracef("Saved source for %v", sf.Filename)
		}
	}

	for _, r := range results {
		if len(r.Nodes) > 0 {
			lastnode := len(r.Nodes) - 1

			pris = append(pris, PathResultInfo{
				Source1:           code[r.Nodes[0].FileName],
				AbsoluteFileName1: r.Nodes[0].FileName,
				Line1:             r.Nodes[0].Line,
				Column1:           r.Nodes[0].Column,
				MethodLine1:       r.Nodes[0].MethodLine,
				Source2:           code[r.Nodes[lastnode].FileName],
				AbsoluteFileName2: r.Nodes[lastnode].FileName,
				Line2:             r.Nodes[lastnode].Line,
				Column2:           r.Nodes[lastnode].Column,
				MethodLine2:       r.Nodes[lastnode].MethodLine,
				QueryID:           r.QueryID,
				State:             r.State,
				PathID:            r.PathID,
				Severity:          r.Severity,
				SimilarityID:      r.SimilarityID,
				Comment:           r.Comment,
			})
		}
	}

	return pris, nil
}
