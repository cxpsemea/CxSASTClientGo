package CxSASTClientGo

import (
	"encoding/xml"
	"fmt"

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

			auditState := "TO_VERIFY"
			switch result.State {
			case "1":
				auditState = "NOT_EXPLOITABLE"
			case "2":
				auditState = "CONFIRMED"
			case "3":
				auditState = "URGENT"
			case "4":
				auditState = "PROPOSED_NOT_EXPLOITABLE"
			default:
				auditState = "TO_VERIFY"
			}

			results = append(results, ScanResult{
				query.Name,
				result.Path.PathID,
				result.Line,
				result.Column,
				result.DetectionDate,
				result.Filename,
				result.DeepLink,
				result.Status,
				result.Severity,
				auditState,
				result.Path.SimilarityID,
				result.Path.SourceMethod,
				result.Path.DestinationMethod,
				query.Group,
				query.Language,
				result.Path.Nodes,
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
