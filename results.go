package CxSASTClientGo

import (
	"encoding/xml"
	"fmt"
	"strconv"

	"github.com/pkg/errors"
)

func (c SASTClient) GetResultsFromXML(xmlReportData []byte) ([]ScanResult, error) {
	results := make([]ScanResult, 0)
	/*
	   Based on the Checkmarx step built into Project-Piper.io
	*/

	var xmlResult struct {
		XMLName                  xml.Name `xml:"CxXMLResults"`
		InitiatorName            string   `xml:"InitiatorName,attr"`
		ScanID                   string   `xml:"ScanId,attr"`
		Owner                    string   `xml:"Owner,attr"`
		ProjectID                string   `xml:"ProjectId,attr"`
		ProjectName              string   `xml:"ProjectName,attr"`
		TeamFullPathOnReportDate string   `xml:"TeamFullPathOnReportDate,attr"`
		DeepLink                 string   `xml:"DeepLink,attr"`
		ScanStart                string   `xml:"ScanStart,attr"`
		Preset                   string   `xml:"Preset,attr"`
		ScanTime                 string   `xml:"ScanTime,attr"`
		LinesOfCodeScanned       uint64   `xml:"LinesOfCodeScanned,attr"`
		FilesScanned             uint64   `xml:"FilesScanned,attr"`
		ReportCreationTime       string   `xml:"ReportCreationTime,attr"`
		Team                     string   `xml:"Team,attr"`
		CheckmarxVersion         string   `xml:"CheckmarxVersion,attr"`
		ScanType                 string   `xml:"ScanType,attr"`
		SourceOrigin             string   `xml:"SourceOrigin,attr"`
		Visibility               string   `xml:"Visibility,attr"`
		Queries                  []struct {
			XMLName  xml.Name `xml:"Query"`
			Id       uint64   `xml:"id,attr"`
			Name     string   `xml:"name,attr"`
			Group    string   `xml:"group,attr"`
			Language string   `xml:"Language,attr"`
			Results  []struct {
				XMLName       xml.Name `xml:"Result"`
				State         string   `xml:"state,attr"`
				Status        string   `xml:"Status,attr"`
				Filename      string   `xml:"FileName,attr"`
				Line          uint64   `xml:"Line,attr"`
				Column        uint64   `xml:"Column,attr"`
				DeepLink      string   `xml:"DeepLink,attr"`
				DetectionDate string   `xml:"DetectionDate,attr"`
				Severity      string   `xml:"Severity,attr"`
				FalsePositive string   `xml:"FalsePositive,attr"`
				Comment       string   `xml:"Remark,attr"`

				Path struct {
					PathID            uint64     `xml:"PathId,attr"`
					SourceMethod      string     `xml:"SourceMethod,attr"`
					DestinationMethod string     `xml:"DestinationMethod,attr"`
					SimilarityID      int64      `xml:"SimilarityId,attr"`
					Nodes             []PathNode `xml:"PathNode"`
				} `xml:"Path"`
			} `xml:"Result"`
		} `xml:"Query"`
	}

	err := xml.Unmarshal(xmlReportData, &xmlResult)
	if err != nil {
		return results, errors.Wrap(err, "failed to unmarshal XML report")
	}

	for _, query := range xmlResult.Queries {
		for _, result := range query.Results {

			stateInt, _ := strconv.Atoi(result.State)

			auditState := StateToString(int64(stateInt))

			results = append(results, ScanResult{
				QueryName:         query.Name,
				QueryID:           query.Id,
				PathID:            result.Path.PathID,
				Line:              result.Line,
				Column:            result.Column,
				DetectionDate:     result.DetectionDate,
				Filename:          result.Filename,
				DeepLink:          result.DeepLink,
				Status:            result.Status,
				Severity:          result.Severity,
				State:             auditState,
				SimilarityID:      result.Path.SimilarityID,
				SourceMethod:      result.Path.SourceMethod,
				DestinationMethod: result.Path.DestinationMethod,
				Group:             query.Group,
				Language:          query.Language,
				Comment:           result.Comment,
				Nodes:             result.Path.Nodes,
			})
		}
	}
	return results, nil
}

func (r ScanResult) String() string {
	return fmt.Sprintf("%v (%d) - %v to %v - in file %v:%d", r.QueryName, r.SimilarityID, r.Nodes[0].Name, r.Nodes[len(r.Nodes)-1].Name, r.Filename, r.Line)
}

func addResultStatus(summary *ScanResultStatusSummary, result *ScanResult) {
	switch result.State {
	case "CONFIRMED":
		summary.Confirmed++
	case "URGENT":
		summary.Urgent++
	case "PROPOSED_NOT_EXPLOITABLE":
		summary.ProposedNotExploitable++
	case "NOT_EXPLOITABLE":
		summary.NotExploitable++
	default:
		summary.ToVerify++
	}
}

func (c SASTClient) GetScanResultSummary(results []ScanResult) ScanResultSummary {
	summary := ScanResultSummary{}

	for _, result := range results {
		switch result.Severity {
		case "High":
			addResultStatus(&(summary.High), &result)
		case "Medium":
			addResultStatus(&(summary.Medium), &result)
		case "Low":
			addResultStatus(&(summary.Low), &result)
		default:
			addResultStatus(&(summary.Information), &result)
		}
	}

	return summary
}

func (c SASTClient) GetScanResultPathNodes(scanId, pathId uint64) ([]PathNode, error) {
	type Envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Text    string   `xml:",chardata"`
		Soap    string   `xml:"soap,attr"`
		Xsi     string   `xml:"xsi,attr"`
		Xsd     string   `xml:"xsd,attr"`
		Body    struct {
			Text                  string `xml:",chardata"`
			GetResultPathResponse struct {
				Text                string `xml:",chardata"`
				Xmlns               string `xml:"xmlns,attr"`
				GetResultPathResult struct {
					Text         string `xml:",chardata"`
					IsSuccesfull string `xml:"IsSuccesfull"`
					Path         struct {
						Text         string `xml:",chardata"`
						SimilarityId string `xml:"SimilarityId"`
						PathId       string `xml:"PathId"`
						Comment      string `xml:"Comment"`
						State        string `xml:"State"`
						Severity     string `xml:"Severity"`
						AssignedUser string `xml:"AssignedUser"`
						Nodes        struct {
							Text         string `xml:",chardata"`
							CxWSPathNode []struct {
								Text       string `xml:",chardata"`
								Column     uint64 `xml:"Column"`
								FullName   string `xml:"FullName"`
								FileName   string `xml:"FileName"`
								Length     uint64 `xml:"Length"`
								Line       uint64 `xml:"Line"`
								Name       string `xml:"Name"`
								DOMID      string `xml:"DOM_Id"`
								MethodLine uint64 `xml:"MethodLine"`
								PathNodeId uint64 `xml:"PathNodeId"`
							} `xml:"CxWSPathNode"`
						} `xml:"Nodes"`
					} `xml:"Path"`
				} `xml:"GetResultPathResult"`
			} `xml:"GetResultPathResponse"`
		} `xml:"Body"`
	}

	var pathResponse Envelope
	results := []PathNode{}
	response, err := c.sendSOAPRequest("GetResultPath", fmt.Sprintf("<sessionId></sessionId><scanId>%d</scanId><pathId>%d</pathId>", scanId, pathId))
	if err != nil {
		return results, err
	}

	if err = xml.Unmarshal(response, &pathResponse); err != nil {
		return results, err
	}

	for _, n := range pathResponse.Body.GetResultPathResponse.GetResultPathResult.Path.Nodes.CxWSPathNode {
		pn := PathNode{
			FileName:   n.FileName,
			Line:       n.Line,
			Column:     n.Column,
			Name:       n.Name,
			Length:     n.Length,
			MethodLine: n.MethodLine,
			NodeId:     n.PathNodeId,
		}

		results = append(results, pn)
	}

	return results, nil
}

func (c SASTClient) GetResultsForScanSOAP(scanId uint64) ([]ScanResult, error) {
	type Envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Text    string   `xml:",chardata"`
		Soap    string   `xml:"soap,attr"`
		Xsi     string   `xml:"xsi,attr"`
		Xsd     string   `xml:"xsd,attr"`
		Body    struct {
			Text                      string `xml:",chardata"`
			GetResultsForScanResponse struct {
				Text                    string `xml:",chardata"`
				Xmlns                   string `xml:"xmlns,attr"`
				GetResultsForScanResult struct {
					Text         string `xml:",chardata"`
					IsSuccesfull string `xml:"IsSuccesfull"`
					Results      struct {
						Text                 string `xml:",chardata"`
						CxWSSingleResultData []struct {
							Text             string `xml:",chardata"`
							QueryId          uint64 `xml:"QueryId"`
							PathId           uint64 `xml:"PathId"`
							SourceFolder     string `xml:"SourceFolder"`
							SourceFile       string `xml:"SourceFile"`
							SourceLine       uint64 `xml:"SourceLine"`
							SourceObject     string `xml:"SourceObject"`
							DestFolder       string `xml:"DestFolder"`
							DestFile         string `xml:"DestFile"`
							DestLine         uint64 `xml:"DestLine"`
							NumberOfNodes    uint64 `xml:"NumberOfNodes"`
							DestObject       string `xml:"DestObject"`
							Comment          string `xml:"Comment"`
							State            int64  `xml:"State"`
							Severity         int64  `xml:"Severity"`
							AssignedUser     string `xml:"AssignedUser"`
							ConfidenceLevel  string `xml:"ConfidenceLevel"`
							ResultStatus     string `xml:"ResultStatus"`
							IssueTicketID    string `xml:"IssueTicketID"`
							QueryVersionCode uint64 `xml:"QueryVersionCode"`
							SimilarityID     int64  `xml:"SimilarityID"`
						} `xml:"CxWSSingleResultData"`
					} `xml:"Results"`
				} `xml:"GetResultsForScanResult"`
			} `xml:"GetResultsForScanResponse"`
		} `xml:"Body"`
	}

	var resultsResponse Envelope
	results := []ScanResult{}
	response, err := c.sendSOAPRequest("GetResultsForScan", fmt.Sprintf("<sessionId></sessionId><scanId>%d</scanId>", scanId))
	if err != nil {
		return results, err
	}

	if err = xml.Unmarshal(response, &resultsResponse); err != nil {
		return results, err
	}

	for _, r := range resultsResponse.Body.GetResultsForScanResponse.GetResultsForScanResult.Results.CxWSSingleResultData {
		sr := ScanResult{
			QueryName:         "",
			QueryID:           r.QueryId,
			PathID:            r.PathId,
			Line:              r.DestLine,
			Column:            0,
			DetectionDate:     "",
			Filename:          r.DestFile,
			DeepLink:          "",
			Status:            r.ResultStatus,
			Severity:          SeverityToString(r.Severity), // todo from: r.Severity
			State:             StateToString(r.State),       // todo from: r.State,
			SimilarityID:      r.SimilarityID,
			SourceMethod:      "",
			DestinationMethod: "",
			Group:             "",
			Language:          "",
			Comment:           r.Comment,
			Nodes:             []PathNode{},
		}

		nodes, err := c.GetScanResultPathNodes(scanId, sr.PathID)
		if err != nil {
			c.logger.Errorf("Failed to get nodes for scan %d path %d", scanId, sr.PathID)
		} else {
			sr.Nodes = nodes
		}

		results = append(results, sr)
	}

	return results, nil
}

func StateToString(state int64) string {
	switch state {
	case 1:
		return "NOT_EXPLOITABLE"
	case 2:
		return "CONFIRMED"
	case 3:
		return "URGENT"
	case 4:
		return "PROPOSED_NOT_EXPLOITABLE"
	default:
		return "TO_VERIFY"
	}
}

func SeverityToString(sev int64) string {
	switch sev {
	case 0:
		return "Information"
	case 1:
		return "Low"
	case 2:
		return "Medium"
	case 3:
		return "High"
	case 4:
		return "Critical"
	default:
		return "Unknown"
	}
}

func (c SASTClient) GetResultStateListSOAP() ([]ResultState, error) {
	response, err := c.sendSOAPRequest("GetResultStateList", "<sessionID></sessionID>")
	if err != nil {
		return []ResultState{}, err
	}

	var xmlResponse struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			XMLName  xml.Name `xml:"Body"`
			Response struct {
				XMLName xml.Name `xml:"GetResultStateListResponse"`
				Result  struct {
					XMLName         xml.Name `xml:"GetResultStateListResult"`
					IsSuccesfull    bool     `xml:"IsSuccesfull"`
					ErrorMessage    string
					ResultStateList struct {
						XMLName      xml.Name      `xml:"ResultStateList"`
						ResultStates []ResultState `xml:"ResultState"`
					}
				}
			}
		}
	}

	err = xml.Unmarshal(response, &xmlResponse)
	if err != nil {
		return []ResultState{}, err
	}

	if !xmlResponse.Body.Response.Result.IsSuccesfull {
		return []ResultState{}, fmt.Errorf("soap error: %v", xmlResponse.Body.Response.Result.ErrorMessage)
	}

	resultStates := xmlResponse.Body.Response.Result.ResultStateList.ResultStates
	default_states := []string{"To Verify", "Not Exploitable", "Confirmed", "Urgent", "Proposed Not Exploitable"}
	for id := range resultStates {
		if resultStates[id].ID < uint(len(default_states)) {
			if resultStates[id].Name != default_states[resultStates[id].ID] {
				resultStates[id].IsCustom = true
			}
		} else {
			resultStates[id].IsCustom = true
		}
	}

	return xmlResponse.Body.Response.Result.ResultStateList.ResultStates, err
}

func (s ScanResultStatusSummary) Total() uint64 {
	return s.ToVerify + s.Confirmed + s.Urgent + s.ProposedNotExploitable + s.NotExploitable
}
func (s ScanResultStatusSummary) String() string {
	return fmt.Sprintf("To Verify: %d, Confirmed: %d, Urgent: %d, Proposed NE: %d, NE: %d", s.ToVerify, s.Confirmed, s.Urgent, s.ProposedNotExploitable, s.NotExploitable)
}
func (s ScanResultSummary) String() string {
	return fmt.Sprintf("%v\n%v\n%v", fmt.Sprintf("\tHigh: %v\n\tMedium: %v\n\tLow: %v\n\tInfo: %v", s.High.String(), s.Medium.String(), s.Low.String(), s.Information.String()),
		fmt.Sprintf("\tTotal High: %d, Medium: %d, Low: %d, Info: %d", s.High.Total(), s.Medium.Total(), s.Low.Total(), s.Information.Total()),
		fmt.Sprintf("\tTotal ToVerify: %d, Confirmed: %d, Urgent: %d, Proposed NE: %d, NE: %d",
			s.High.ToVerify+s.Medium.ToVerify+s.Low.ToVerify+s.Information.ToVerify,
			s.High.Confirmed+s.Medium.Confirmed+s.Low.Confirmed+s.Information.Confirmed,
			s.High.Urgent+s.Medium.Urgent+s.Low.Urgent+s.Information.Urgent,
			s.High.ProposedNotExploitable+s.Medium.ProposedNotExploitable+s.Low.ProposedNotExploitable+s.Information.ProposedNotExploitable,
			s.High.NotExploitable+s.Medium.NotExploitable+s.Low.NotExploitable+s.Information.NotExploitable))
}
