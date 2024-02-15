package CxSASTClientGo

import (
	"encoding/json"
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
