package CxSASTClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

func (c *SASTClient) RequestNewReport(scanID uint64, reportType string) (Report, error) {
	report := Report{}
	jsonData := map[string]interface{}{
		"scanId":     scanID,
		"reportType": reportType,
		"comment":    "Scan report triggered by CxSASTClientGo",
	}

	jsonValue, _ := json.Marshal(jsonData)

	header := http.Header{}
	header.Set("cxOrigin", "GolangScript")
	header.Set("Content-Type", "application/json")
	data, err := c.sendRequest(http.MethodPost, "/reports/sastScan", bytes.NewReader(jsonValue), header)
	if err != nil {
		return report, errors.Wrapf(err, "Failed to trigger report generation for scan %d", scanID)
	}

	err = json.Unmarshal(data, &report)
	return report, err
}

func (c *SASTClient) GetReportStatus(reportID uint64) (ReportStatusResponse, error) {
	var response ReportStatusResponse

	header := http.Header{}
	header.Set("Accept", "application/json")
	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/reports/sastScan/%d/status", reportID), nil, header)
	if err != nil {
		c.logger.Errorf("Failed to fetch report status for reportID %d: %s", reportID, err)
		return response, errors.Wrapf(err, "failed to fetch report status for reportID %d", reportID)
	}

	json.Unmarshal(data, &response)
	return response, nil
}

func (c *SASTClient) DownloadReport(reportID uint64) ([]byte, error) {
	header := http.Header{}
	header.Set("Accept", "application/json")
	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/reports/sastScan/%d", reportID), nil, header)
	if err != nil {
		return []byte{}, errors.Wrapf(err, "failed to download report with reportID %d", reportID)
	}
	return data, nil
}

// convenience function
func (c *SASTClient) GenerateAndDownloadReport(scanID uint64, reportType string) ([]byte, error) {
	var reportBytes []byte
	report, err := c.RequestNewReport(scanID, reportType)

	if err != nil {
		c.logger.Error("Error requesting report: " + err.Error())
		return reportBytes, err
	}

	finalStatus := 1
	for {
		reportStatus, err := c.GetReportStatus(report.ReportID)
		if err != nil {
			c.logger.Error("Error generating report: " + err.Error())
			return reportBytes, err
		}
		finalStatus = reportStatus.Status.ID
		if finalStatus != 1 {
			break
		}
		time.Sleep(10 * time.Second)
	}

	if finalStatus == 2 {
		reportBytes, err = c.DownloadReport(report.ReportID)
		if err != nil {
			c.logger.Error("Error downloading report: " + err.Error())
			return reportBytes, err
		}

	} else {
		c.logger.Info("Failure during report generation")
		return reportBytes, errors.New("Failed during report generation")
	}

	return reportBytes, nil
}
