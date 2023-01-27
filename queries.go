package CxSASTClientGo

import (
	"encoding/xml"
	"fmt"

	"github.com/pkg/errors"
)

func (c *SASTClient) GetQueriesSOAP() ([]QueryGroup, []Query, error) {
	var xmlResponse struct {
		XMLName xml.Name `xml:"Envelope"`
		Body    struct {
			XMLName  xml.Name `xml:"Body"`
			Response struct {
				XMLName xml.Name `xml:"GetQueryCollectionResponse"`
				Result  struct {
					XMLName         xml.Name `xml:"GetQueryCollectionResult"`
					IsSuccesfull    bool     `xml:"IsSuccesfull"`
					ErrorMessage    string
					QueryGroupsList struct {
						XMLName     xml.Name `xml:"QueryGroups"`
						QueryGroups []struct {
							Name        string
							PackageId   uint64
							QueriesList struct {
								XMLName xml.Name
								Queries []Query `xml:"CxWSQuery"`
							} `xml:"Queries"`
							LanguageName    string
							PackageTypeName string
							ProjectID       uint64
							OwningTeam      uint64
						} `xml:"CxWSQueryGroup"`
					}
				}
			}
		}
	}

	Queries := make([]Query, 0)
	QueryGroups := make([]QueryGroup, 0)

	c.logger.Debug("Get SAST Query Collection SOAP")
	response, err := c.sendSOAPRequest("GetQueryCollection", "<i_SessionID></i_SessionID>")
	if err != nil {
		return QueryGroups, Queries, err
	}

	err = xml.Unmarshal(response, &xmlResponse)
	if err != nil {
		c.logger.Errorf("Failed to parse SOAP response: %s", err)
		c.logger.Tracef("Parsed from: %v", string(response))
		return QueryGroups, Queries, err
	}

	if !xmlResponse.Body.Response.Result.IsSuccesfull {
		c.logger.Errorf("SOAP request error: %v", xmlResponse.Body.Response.Result.ErrorMessage)
		c.logger.Infof("Full response: %v", string(response))
		return QueryGroups, Queries, errors.New(fmt.Sprintf("SOAP request failed: %v", xmlResponse.Body.Response.Result.ErrorMessage))
	}

	for _, g := range xmlResponse.Body.Response.Result.QueryGroupsList.QueryGroups {
		for _, q := range g.QueriesList.Queries {
			q.Language = g.LanguageName
			q.Group = g.Name
			Queries = append(Queries, q)
		}
	}
	c.logger.Debugf("Parsed %d queries", len(Queries))

	for _, g := range xmlResponse.Body.Response.Result.QueryGroupsList.QueryGroups {
		qlist := make([]*Query, 0)
		for _, q := range g.QueriesList.Queries {
			cq := c.GetQueryByID(q.QueryID, &Queries)
			qlist = append(qlist, cq)
		}

		QueryGroups = append(QueryGroups, QueryGroup{g.Name, g.PackageId, qlist, g.LanguageName, g.ProjectID, g.PackageTypeName, g.OwningTeam})
	}
	c.logger.Debugf("Parsed %d query groups", len(QueryGroups))

	return QueryGroups, Queries, nil //errors.New( fmt.Sprintf( "Unable to find scan's preset %v: preset no longer exists?", result.Preset ) )
}

func (c *SASTClient) GetQueryByID(qid uint64, queries *[]Query) *Query {
	for id, q := range *queries {
		if q.QueryID == qid {
			return &(*queries)[id]
		}
	}
	return nil
}
func (q *Query) String() string {
	return fmt.Sprintf("[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
}
