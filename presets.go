package CxSASTClientGo

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

func (c *SASTClient) GetScanPresetSOAP(scanid uint64) (Preset, error) {
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
			c.logger.Errorf(" - SOAP Token %v is not valid?", ShortenGUID(c.soapToken))
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

func (c *SASTClient) GetPresets() ([]Preset, error) {
	c.logger.Debug("Get SAST Presets")
	var presets []Preset
	response, err := c.get("/sast/presets")
	if err != nil {
		return presets, err
	}

	err = json.Unmarshal(response, &presets)
	return presets, err
}

func (c *SASTClient) GetPresetContents(p *Preset, queries *[]Query) error {
	c.logger.Debugf("Fetching contents for preset %v", p.PresetID)

	if len(*queries) == 0 {
		return errors.New("Queries list is empty")
	}

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

	c.logger.Tracef("Parsed preset %v with %d queries", PresetContents.Name, len(PresetContents.QueryIDs))

	p.Queries = make([]Query, 0)
	for _, qid := range PresetContents.QueryIDs {
		q := c.GetQueryByID(qid, queries)
		if q != nil {
			p.Queries = append(p.Queries, *q)
			c.logger.Tracef(" - linked query: %v", q.String())
		}
	}

	p.Filled = true
	return nil
}

func (c *SASTClient) PresetLink(p *Preset) string {
	return fmt.Sprintf("%v/CxWebClient/Presets.aspx?id=%d", c.baseUrl, p.PresetID)
}
