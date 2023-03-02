package CxSASTClientGo

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

func (c *SASTClient) GetQueriesSOAP() (QueryCollection, error) {
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
							Language        uint64
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

	qc := QueryCollection{
		QueryLanguages: make([]QueryLanguage, 0),
	}

	c.logger.Debug("Get SAST Query Collection SOAP")
	response, err := c.sendSOAPRequest("GetQueryCollection", "<i_SessionID></i_SessionID>")
	if err != nil {
		return qc, err
	}

	err = xml.Unmarshal(response, &xmlResponse)
	if err != nil {
		c.logger.Errorf("Failed to parse SOAP response: %s", err)
		c.logger.Tracef("Parsed from: %v", string(response))
		return qc, err
	}

	if !xmlResponse.Body.Response.Result.IsSuccesfull {
		c.logger.Errorf("SOAP request error: %v", xmlResponse.Body.Response.Result.ErrorMessage)
		c.logger.Infof("Full response: %v", string(response))
		return qc, errors.New(fmt.Sprintf("SOAP request failed: %v", xmlResponse.Body.Response.Result.ErrorMessage))
	}

	languageIDs := map[string]uint64{}

	for _, g := range xmlResponse.Body.Response.Result.QueryGroupsList.QueryGroups {
		for _, q := range g.QueriesList.Queries {
			q.Language = g.LanguageName
			ql := qc.GetQueryLanguage(q.Language)
			if ql == nil {
				qc.QueryLanguages = append(qc.QueryLanguages, QueryLanguage{g.LanguageName, g.Language, []QueryGroup{}})
				ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
			}

			q.Group = g.Name
			qg := ql.GetQueryGroup(q.Group)
			if qg == nil {
				ql.QueryGroups = append(ql.QueryGroups, QueryGroup{g.Name, g.PackageId, []Query{}, g.LanguageName, g.ProjectID, g.PackageTypeName, g.OwningTeam})
				qg = &ql.QueryGroups[len(ql.QueryGroups)-1]
			}

			qg.Queries = append(qg.Queries, q)

		}

		languageIDs[g.LanguageName] = g.Language
	}
	return qc, nil //errors.New( fmt.Sprintf( "Unable to find scan's preset %v: preset no longer exists?", result.Preset ) )
}

func (qc *QueryCollection) GetQueryLanguage(language string) *QueryLanguage {
	for id := range qc.QueryLanguages {
		if qc.QueryLanguages[id].Name == language {
			return &qc.QueryLanguages[id]
		}
	}
	return nil
}
func (qc *QueryCollection) AddQuery(l *QueryLanguage, g *QueryGroup, q *Query) {
	ql := qc.GetQueryLanguage(q.Language)
	if ql == nil {
		qc.QueryLanguages = append(qc.QueryLanguages, QueryLanguage{Name: l.Name, LanguageID: l.LanguageID, QueryGroups: []QueryGroup{}})
		ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
	}

	qg := ql.GetQueryGroup(g.Name)
	if qg == nil {
		ql.QueryGroups = append(ql.QueryGroups, QueryGroup{Name: g.Name, PackageID: g.PackageID, Queries: []Query{}, Language: g.Language, OwningProjectID: g.OwningProjectID, PackageType: g.PackageType, OwningTeamID: g.OwningTeamID})
		qg = &ql.QueryGroups[len(ql.QueryGroups)-1]
	}

	qg.Queries = append(qg.Queries, *q)
}

func (ql *QueryLanguage) GetQueryGroup(group string) *QueryGroup {
	for id := range ql.QueryGroups {
		if ql.QueryGroups[id].Name == group {
			return &ql.QueryGroups[id]
		}
	}
	return nil
}

func (qg *QueryGroup) GetQuery(name string) *Query {
	for id, q := range qg.Queries {
		if strings.EqualFold(q.Name, name) {
			return &qg.Queries[id]
		}
	}
	return nil
}
func (qc *QueryCollection) GetQuery(language, group, query string) *Query {
	ql := qc.GetQueryLanguage(language)
	if ql == nil {
		return nil
	}
	qg := ql.GetQueryGroup(group)
	if qg == nil {
		return nil
	}
	return qg.GetQuery(query)
}

func (qc *QueryCollection) GetQueryByID(qid uint64) *Query {
	for _, ql := range qc.QueryLanguages {
		for _, qg := range ql.QueryGroups {
			for id, q := range qg.Queries {
				if q.QueryID == qid {
					return &qg.Queries[id]
				}
			}
		}
	}
	return nil
}
func (qc *QueryCollection) GetCustomQueryCollection() QueryCollection {
	var cqc QueryCollection

	for _, ql := range qc.QueryLanguages {
		for _, qg := range ql.QueryGroups {
			for _, qq := range qg.Queries {
				if qq.IsCustom() {
					cqc.AddQuery(&ql, &qg, &qq)
				}
			}
		}
	}

	return cqc
}

func (c *SASTClient) GetQueryByID(qid uint64, queries *[]Query) *Query {
	for id, q := range *queries {
		if q.QueryID == qid {
			return &(*queries)[id]
		}
	}
	return nil
}

func (q *Query) IsCustom() bool {
	return q.QueryID >= 100000
}
func (q *QueryGroup) IsCustom() bool {
	return q.PackageID >= 100000
}

func (q *Query) String() string {
	return fmt.Sprintf("[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
}
func (q *QueryGroup) String() string {
	return fmt.Sprintf("[%d] %v -> %v", q.PackageID, q.Language, q.Name)
}
func (q *QueryLanguage) String() string {
	return q.Name
}

func (c *SASTClient) QueryLink(q *Query) string {
	return fmt.Sprintf("%v/CxWebClient/QueriesExplorer.aspx?queryid=%d", c.baseUrl, q.QueryID)
}

func (c *SASTClient) QueryGroupLink(q *QueryGroup) string {
	return fmt.Sprintf("%v/CxWebClient/QueriesExplorer.aspx?language=%v&group=%v", c.baseUrl, q.Language, q.Name)
}

func (c *SASTClient) QueryLanguageLink(q *QueryLanguage) string {
	return fmt.Sprintf("%v/CxWebClient/QueriesExplorer.aspx?language=%v", c.baseUrl, q.Name)
}
