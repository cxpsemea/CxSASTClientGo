package CxSASTClientGo

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

func (c SASTClient) GetScanPresetSOAP(scanid uint64) (Preset, error) {
	var xmlResponse struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			XMLName                xml.Name `xml:"Body"`
			GetScanSummaryResponse struct {
				XMLName              xml.Name `xml:"GetScanSummaryResponse"`
				GetScanSummaryResult struct {
					XMLName      xml.Name `xml:"GetScanSummaryResult"`
					IsSuccesfull bool     `xml:"IsSuccesfull"`
					Preset       string
					ErrorMessage string
					LOC          uint64
				}
			}
		}
	}

	c.logger.Debug("Get SAST Scan Preset SOAP")
	response, err := c.sendSOAPRequest("GetScanSummary", fmt.Sprintf("<i_SessionID></i_SessionID><i_ScanID>%d</i_ScanID><auditEvent>0</auditEvent>", scanid))
	if err != nil {
		return Preset{}, err
	}

	err = xml.Unmarshal(response, &xmlResponse)
	if err != nil {
		c.logger.Errorf("Failed to parse SOAP response: %s", err)
		c.logger.Tracef("Parsed from: %v", string(response))
		return Preset{}, err
	}

	result := xmlResponse.Body.GetScanSummaryResponse.GetScanSummaryResult

	if !result.IsSuccesfull {
		c.logger.Errorf("SOAP request error: %v", result.ErrorMessage)
		c.logger.Tracef("Full response: %v", string(response))
		if result.ErrorMessage == "Invalid_Token" {
			c.logger.Errorf(" - SOAP Token is not valid")
		}
		return Preset{}, errors.New(fmt.Sprintf("SOAP request failed: %v", result.ErrorMessage))
	}

	presets, err := c.GetPresets()
	if err != nil {
		c.logger.Errorf("Failed to retrieve list of presets: %s", err)
		return Preset{}, err
	}

	for _, p := range presets {
		if p.Name == result.Preset {
			return p, nil
		}
	}

	return Preset{}, nil //errors.New( fmt.Sprintf( "Unable to find scan's preset %v: preset no longer exists?", result.Preset ) )
}

// Presets
func (p *Preset) String() string {
	return fmt.Sprintf("[%d] %v", p.PresetID, p.Name)
}

func (c SASTClient) GetPresets() ([]Preset, error) {
	c.logger.Debug("Get SAST Presets")
	var presets []Preset
	response, err := c.get("/sast/presets")
	if err != nil {
		return presets, err
	}

	err = json.Unmarshal(response, &presets)
	return presets, err
}

func (c SASTClient) GetPresetByID(presetID uint64) (Preset, error) {
	c.logger.Debugf("Get SAST Preset by ID %d", presetID)
	var preset Preset
	response, err := c.get(fmt.Sprintf("/sast/presets/%d", presetID))
	if err != nil {
		return preset, err
	}

	err = json.Unmarshal(response, &preset)
	return preset, err
}

func (c SASTClient) GetPresetByName(name string) (Preset, error) {
	c.logger.Debugf("Get preset by name %v", name)
	var preset Preset
	var presets []Preset
	presets, err := c.GetPresets()
	if err != nil {
		return preset, err
	}

	for _, p := range presets {
		if p.Name == name {
			return p, nil
		}
	}
	return preset, errors.New("No such preset found")
}

func (c SASTClient) GetPresetContents(p *Preset, queries *QueryCollection) error {
	c.logger.Debugf("Fetching contents for preset %v", p.PresetID)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/sast/presets/%d", p.PresetID), nil, nil)
	if err != nil {
		return err
	}

	var PresetContents struct {
		ID       uint64
		Name     string
		Owner    string
		QueryIDs []uint64
	}

	err = json.Unmarshal(response, &PresetContents)
	if err != nil {
		return errors.Wrap(err, "Failed to parse preset contents")
	}

	p.QueryIDs = PresetContents.QueryIDs

	c.logger.Tracef("Parsed preset %v with %d queries", PresetContents.Name, len(PresetContents.QueryIDs))

	if queries != nil {
		p.LinkQueries(queries)
	}

	return nil
}

func (p *Preset) LinkQueries(queries *QueryCollection) {
	p.Queries = make([]Query, len(p.QueryIDs))
	for id, qid := range p.QueryIDs {
		q := queries.GetQueryByID(qid)
		if q != nil {
			p.Queries[id] = *q
		}
	}

	p.Filled = true
}

func (c SASTClient) PresetLink(p *Preset) string {
	return fmt.Sprintf("%v/CxWebClient/Presets.aspx?id=%d", c.baseUrl, p.PresetID)
}
