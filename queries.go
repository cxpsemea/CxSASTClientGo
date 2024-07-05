package CxSASTClientGo

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/pkg/errors"
)

const (
	CORP_QUERY    = "Corporate"
	PRODUCT_QUERY = "Cx"
	TEAM_QUERY    = "Team"
	PROJECT_QUERY = "Project"
)

func (c SASTClient) GetQueriesSOAP() (QueryCollection, error) {
	qc := QueryCollection{
		QueryLanguages: make([]QueryLanguage, 0),
	}

	c.logger.Debug("Get SAST Query Collection SOAP")
	response, err := c.sendSOAPRequest("GetQueryCollection", "<i_SessionID></i_SessionID>")
	if err != nil {
		return qc, err
	}

	err = qc.FromXML(response)
	return qc, err
}

func (c SASTClient) GetQueriesSOAPRaw() ([]byte, error) {
	c.logger.Debug("Get SAST Query Collection SOAP - Raw XML")
	return c.sendSOAPRequest("GetQueryCollection", "<i_SessionID></i_SessionID>")
}

func (qc *QueryCollection) FromXML(response []byte) error {
	qc.QueryLanguages = make([]QueryLanguage, 0)

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
							PackageType     string
							ProjectId       int64
							OwningTeam      int64
						} `xml:"CxWSQueryGroup"`
					}
				}
			}
		}
	}

	err := xml.Unmarshal(response, &xmlResponse)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to parse SOAP response: %s", err))
	}

	if !xmlResponse.Body.Response.Result.IsSuccesfull {
		return errors.New(fmt.Sprintf("SOAP request failed: %v", xmlResponse.Body.Response.Result.ErrorMessage))
	}

	for _, g := range xmlResponse.Body.Response.Result.QueryGroupsList.QueryGroups {
		for _, q := range g.QueriesList.Queries {
			q.Language = g.LanguageName
			ql := qc.GetQueryLanguage(q.Language)
			if ql == nil {
				qc.QueryLanguages = append(qc.QueryLanguages, QueryLanguage{g.LanguageName, g.Language, []QueryGroup{}})
				ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
			}

			q.Group = g.Name
			qg := ql.GetQueryGroupByID(q.PackageID)

			if qg == nil {
				ql.QueryGroups = append(ql.QueryGroups, QueryGroup{
					g.Name, g.PackageId, []Query{}, g.LanguageName, uint64(g.ProjectId), g.PackageType, uint64(g.OwningTeam),
				})
				qg = &ql.QueryGroups[len(ql.QueryGroups)-1]
			}

			qg.Queries = append(qg.Queries, q)
			q.OwningGroup = qg
		}
	}

	qc.LinkGroups()
	qc.GetQueryCount()

	return nil
}

func (c SASTClient) GetResultPathsForQuerySOAP(scanID, queryID uint64) ([]ScanResult, error) {
	type Envelope struct {
		XMLName xml.Name `xml:"Envelope"`
		Text    string   `xml:",chardata"`
		Soap    string   `xml:"soap,attr"`
		Xsi     string   `xml:"xsi,attr"`
		Xsd     string   `xml:"xsd,attr"`
		Body    struct {
			Text                           string `xml:",chardata"`
			GetResultPathsForQueryResponse struct {
				Text                         string `xml:",chardata"`
				Xmlns                        string `xml:"xmlns,attr"`
				GetResultPathsForQueryResult struct {
					Text         string `xml:",chardata"`
					IsSuccesfull string `xml:"IsSuccesfull"`
					Paths        struct {
						Text           string `xml:",chardata"`
						CxWSResultPath []struct {
							Text         string `xml:",chardata"`
							SimilarityId int64  `xml:"SimilarityId"`
							PathId       uint64 `xml:"PathId"`
							Comment      string `xml:"Comment"`
							State        uint64 `xml:"State"`
							Severity     int64  `xml:"Severity"`
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
						} `xml:"CxWSResultPath"`
					} `xml:"Paths"`
				} `xml:"GetResultPathsForQueryResult"`
			} `xml:"GetResultPathsForQueryResponse"`
		} `xml:"Body"`
	}

	var paths []ScanResult
	var env Envelope

	response, err := c.sendSOAPRequest("GetResultPathsForQuery", fmt.Sprintf("<sessionId></sessionId><scanId>%d</scanId><queryId>%d</queryId>", scanID, queryID))
	if err != nil {
		return paths, err
	}

	if err = xml.Unmarshal(response, &env); err != nil {
		return paths, err
	}

	for _, p := range env.Body.GetResultPathsForQueryResponse.GetResultPathsForQueryResult.Paths.CxWSResultPath {
		sr := ScanResult{
			QueryName:         "",
			QueryID:           queryID,
			PathID:            p.PathId,
			Line:              0,
			Column:            0,
			DetectionDate:     "",
			Filename:          "",
			DeepLink:          "",
			Status:            "",
			Severity:          "",
			State:             "",
			SimilarityID:      p.SimilarityId,
			SourceMethod:      "",
			DestinationMethod: "",
			Group:             "",
			Language:          "",
			Nodes:             []PathNode{},
		}

		for _, n := range p.Nodes.CxWSPathNode {
			sr.Nodes = append(
				sr.Nodes,
				PathNode{
					FileName:   n.FileName,
					Line:       n.Line,
					Column:     n.Column,
					Name:       n.Name,
					Length:     n.Length,
					MethodLine: n.MethodLine,
					NodeId:     n.PathNodeId,
				},
			)
		}

		paths = append(paths, sr)
	}
	return paths, nil
}

func (qc *QueryCollection) LinkGroups() {
	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			for qid := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
				qc.QueryLanguages[lid].QueryGroups[gid].Queries[qid].OwningGroup = &qc.QueryLanguages[lid].QueryGroups[gid]
			}
		}
	}
}

func (qc *QueryCollection) GetQueryCount() uint {
	var total uint = 0
	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			total += uint(len(qc.QueryLanguages[lid].QueryGroups[gid].Queries))
		}
	}
	qc.QueryCount = total
	return total
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

	qg := ql.GetQueryGroupByID(g.PackageID)
	if qg == nil {
		ql.QueryGroups = append(ql.QueryGroups, QueryGroup{
			Name:            g.Name,
			PackageID:       g.PackageID,
			Queries:         []Query{},
			Language:        g.Language,
			OwningProjectID: g.OwningProjectID,
			PackageType:     g.PackageType,
			OwningTeamID:    g.OwningTeamID,
		})
		qg = &ql.QueryGroups[len(ql.QueryGroups)-1]
	}

	qg.Queries = append(qg.Queries, *q)
	q.OwningGroup = qg
}

func (qc *QueryCollection) LinkBaseQueries(teamsByID *map[uint64]*Team, projectsByID *map[uint64]*Project) {
	productQueries := make(map[string]uint64)
	teamQueries := make(map[uint64]map[string]uint64)
	teamQueries[0] = make(map[string]uint64)
	projectQueries := make(map[uint64]map[string]uint64)
	queriesById := make(map[uint64]*Query)

	// make a map of queries by id
	for lid, lang := range qc.QueryLanguages {
		for gid, group := range lang.QueryGroups {
			for qid, query := range group.Queries {
				queriesById[query.QueryID] = &(qc.QueryLanguages[lid].QueryGroups[gid].Queries[qid])
				nicename := fmt.Sprintf("%v.%v.%v", lang.Name, group.Name, query.Name)

				switch group.PackageType {
				case PRODUCT_QUERY:
					productQueries[nicename] = query.QueryID
					queriesById[query.QueryID].BaseQueryID = query.QueryID
				case CORP_QUERY:
					teamQueries[0][nicename] = query.QueryID
				case TEAM_QUERY:
					if _, ok := teamQueries[group.OwningTeamID]; !ok {
						teamQueries[group.OwningTeamID] = make(map[string]uint64)
					}
					teamQueries[group.OwningTeamID][nicename] = query.QueryID
				case PROJECT_QUERY:
					if _, ok := projectQueries[group.OwningProjectID]; !ok {
						projectQueries[group.OwningProjectID] = make(map[string]uint64)
					}
					projectQueries[group.OwningProjectID][nicename] = query.QueryID
				}
			}
		}
	}

	// link queries
	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			switch qc.QueryLanguages[lid].QueryGroups[gid].PackageType {
			case CORP_QUERY:
				for _, query := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
					nicename := fmt.Sprintf("%v.%v.%v", query.Language, query.Group, query.Name)
					if val, ok := productQueries[nicename]; ok {
						queriesById[query.QueryID].BaseQueryID = val
					} else {
						queriesById[query.QueryID].BaseQueryID = query.QueryID
					}
				}
			case TEAM_QUERY:
				for _, query := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
					nicename := fmt.Sprintf("%v.%v.%v", query.Language, query.Group, query.Name)
					baseID := uint64(0)
					if team, ok := (*teamsByID)[qc.QueryLanguages[lid].QueryGroups[gid].OwningTeamID]; ok && team != nil { // team exists
						baseID = findBaseQueryID(nicename, team.ParentID, &teamQueries, teamsByID)
					}

					if baseID == 0 {
						if val, ok := productQueries[nicename]; ok {
							queriesById[query.QueryID].BaseQueryID = val // base query is product-default query
						} else {
							queriesById[query.QueryID].BaseQueryID = query.QueryID // no base query, base query is self
						}
					} else {
						queriesById[query.QueryID].BaseQueryID = baseID
					}
				}
			case PROJECT_QUERY:
				for _, query := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
					nicename := fmt.Sprintf("%v.%v.%v", query.Language, query.Group, query.Name)
					baseID := uint64(0)
					if proj, ok := (*projectsByID)[qc.QueryLanguages[lid].QueryGroups[gid].OwningProjectID]; ok && proj != nil { // team exists
						baseID = findBaseQueryID(nicename, proj.TeamID, &teamQueries, teamsByID)
					} else {
						//fmt.Printf("Search for query %v (%v) base invalid, no owning project\n", nicename, query.StringDetailed())
						continue
					}

					if baseID == 0 {
						if val, ok := productQueries[nicename]; ok {
							queriesById[query.QueryID].BaseQueryID = val // base query is product-default query
						} else {
							queriesById[query.QueryID].BaseQueryID = query.QueryID // no base query, base query is self
						}
					} else {
						queriesById[query.QueryID].BaseQueryID = baseID
					}
				}
			}
		}
	}

	// generate query hierarchy for each query
	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			for qid := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
				qc.GenerateHierarchy(&qc.QueryLanguages[lid].QueryGroups[gid].Queries[qid])

			}
		}
	}
}

func findBaseQueryID(nicename string, parentTeamID uint64, teamQueries *map[uint64]map[string]uint64, teamsByID *map[uint64]*Team) uint64 {
	if _, ok := (*teamQueries)[parentTeamID]; ok { // team with parentTeamID has custom queries
		if queryId, ok := (*teamQueries)[parentTeamID][nicename]; ok { // team with parentTeamID has a query named nicename
			return queryId
		}
	}

	if parentTeam, ok := (*teamsByID)[parentTeamID]; ok { // team with parentTeamID exists
		return findBaseQueryID(nicename, parentTeam.ParentID, teamQueries, teamsByID)
	}
	return 0
}

func (ql *QueryLanguage) GetQueryGroup(group string) *QueryGroup {
	for id := range ql.QueryGroups {
		if ql.QueryGroups[id].Name == group {
			return &ql.QueryGroups[id]
		}
	}
	return nil
}
func (ql *QueryLanguage) GetQueryGroupByID(packageId uint64) *QueryGroup {
	for id := range ql.QueryGroups {
		if ql.QueryGroups[id].PackageID == packageId {
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

func (qc *QueryCollection) GenerateHierarchy(query *Query) {
	hierarchy := []uint64{}

	if query.BaseQueryID != query.QueryID {
		for q := query; q != nil && q.BaseQueryID != q.QueryID; q = qc.GetQueryByID(q.BaseQueryID) {
			hierarchy = append(hierarchy, q.BaseQueryID)
		}
	}
	query.Hierarchy = hierarchy
}

func (qc *QueryCollection) DetectDependencies(teamsByID *map[uint64]*Team, projectsByID *map[uint64]*Project) {
	/*projectOpenCalls := make(map[uint64][]string)
	projectBaseCalls := make(map[uint64][]string)

	teamOpenCalls := make(map[uint64][]string)
	teamBaseCalls := make(map[uint64][]string)*/

	open_call := regexp.MustCompile(`[^a-zA-Z0-9_.]([a-zA-Z_0-9]+)\(\)`)
	base_call := regexp.MustCompile(`base\.([a-zA-Z_0-9]+)\(\)`)

	/*for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			for qid := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
				qc.GenerateHierarchy(&qc.QueryLanguages[lid].QueryGroups[gid].Queries[qid])
			}
		}
	}*/

	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			qg := &qc.QueryLanguages[lid].QueryGroups[gid]
			for qid := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
				qq := &qc.QueryLanguages[lid].QueryGroups[gid].Queries[qid]

				if !qq.IsCustom() {
					qq.IsValid = true
				} else {
					if qg.OwningTeamID > 0 {
						if _, ok := (*teamsByID)[qg.OwningTeamID]; !ok {
							qq.IsValid = false // team doesn't exist
							continue
						}
					} else if qg.OwningProjectID > 0 {
						if _, ok := (*projectsByID)[qg.OwningProjectID]; !ok {
							qq.IsValid = false // project doesn't exist
							continue
						}
					}

					qq.IsValid = true

					open_calls := open_call.FindAllStringSubmatch(qq.Source, -1)
					base_calls := base_call.FindAllStringSubmatch(qq.Source, -1)
					hierarchy := qc.QueryHierarchy(qq.QueryID)

					if len(open_calls) > 0 {
						//fmt.Printf("%v Open calls:\n", qq.StringDetailed())
						for _, matches := range open_calls {
							var q *Query = nil
							var err error

							if qg.OwningTeamID > 0 {
								q, err = qc.FindTeamBaseQueryInTree(qq.Language, matches[1], qg.OwningTeamID, teamsByID)
							} else if qg.OwningProjectID > 0 {
								q, err = qc.FindProjectBaseQueryInTree(qq.Language, matches[1], qg.OwningProjectID, teamsByID, projectsByID)
							} else {
								q = qc.FindCorpBaseQuery(qq.Language, matches[1])
							}

							if q != nil {
								//fmt.Printf(" - %v -> query %v\n", matches[1], q.StringDetailed())
								if !slices.Contains(qq.Dependencies, q.QueryID) && !slices.Contains(hierarchy, q.QueryID) {
									if !q.IsCustom() {
										if !slices.Contains(qq.Dependencies, q.QueryID) {
											qq.Dependencies = append(qq.Dependencies, q.QueryID)
										}
									} else {
										if !slices.Contains(qq.CustomDependencies, q.QueryID) {
											qq.CustomDependencies = append(qq.CustomDependencies, q.QueryID)
										}
									}
								}
							} else {
								//fmt.Printf(" - %v -> unknown open call %v: %s\n", qq.StringDetailed(), matches[1], err)
								if err == nil && !slices.Contains(qq.UnknownCalls, matches[1]) {
									qq.UnknownCalls = append(qq.UnknownCalls, matches[1])
								}
							}

						}
					}
					if len(base_calls) > 0 {
						//fmt.Printf("%v Base calls:\n", qq.StringDetailed())
						for _, matches := range base_calls {
							var q *Query = nil
							var err error

							if qg.OwningTeamID > 0 {
								if team, ok := (*teamsByID)[qg.OwningTeamID]; ok {
									q, err = qc.FindTeamBaseQueryInTree(qq.Language, matches[1], team.ParentID, teamsByID)
								} else {
									err = fmt.Errorf("no team found with ID %d", qg.OwningTeamID)
								}
							} else if qg.OwningProjectID > 0 {
								if proj, ok := (*projectsByID)[qg.OwningProjectID]; ok {
									q, err = qc.FindTeamBaseQueryInTree(qq.Language, matches[1], proj.TeamID, teamsByID)
								} else {
									err = fmt.Errorf("no project found with ID %d", qg.OwningProjectID)
								}
							} else {
								q = qc.FindProductQuery(qq.Language, matches[1])
							}

							if q != nil {
								//fmt.Printf(" - %v -> query %v\n", matches[1], q.StringDetailed())
								if !slices.Contains(hierarchy, q.QueryID) {
									if !q.IsCustom() {
										if !slices.Contains(qq.Dependencies, q.QueryID) {
											qq.Dependencies = append(qq.Dependencies, q.QueryID)
										}
									} else {
										if !slices.Contains(qq.CustomDependencies, q.QueryID) {
											qq.CustomDependencies = append(qq.CustomDependencies, q.QueryID)
										}
									}
								}
							} else {
								//fmt.Printf(" - %v -> unknown base call %v: %s\n", qq.StringDetailed(), matches[1], err)
								if err == nil && !slices.Contains(qq.UnknownCalls, matches[1]) {
									qq.UnknownCalls = append(qq.UnknownCalls, matches[1])
								}
							}
						}
					}

				}
			}
		}
	}
}

func (qc *QueryCollection) FindProjectBaseQueryInTree(language, query string, projectId uint64, teamsByID *map[uint64]*Team, projectsByID *map[uint64]*Project) (*Query, error) {
	if ql := qc.GetQueryLanguage(language); ql != nil {
		for _, qg := range ql.QueryGroups {
			if qg.PackageType == PROJECT_QUERY && qg.OwningProjectID == projectId {
				if q := qg.GetQuery(query); q != nil {
					return q, nil
				}
			}
		}
	}

	if proj, ok := (*projectsByID)[projectId]; ok {
		return qc.FindTeamBaseQueryInTree(language, query, proj.TeamID, teamsByID)
	} else {
		return nil, fmt.Errorf("unknown project with id %d", projectId) // unknown project
	}
}

func (qc *QueryCollection) FindTeamBaseQueryInTree(language, query string, teamId uint64, teamsByID *map[uint64]*Team) (*Query, error) {
	if ql := qc.GetQueryLanguage(language); ql != nil {
		for _, qg := range ql.QueryGroups {
			if qg.PackageType == TEAM_QUERY && qg.OwningTeamID == teamId {
				if q := qg.GetQuery(query); q != nil {
					return q, nil
				}
			}
		}
	}

	if team, ok := (*teamsByID)[teamId]; ok {
		if team.ParentID == 0 {
			return qc.FindCorpBaseQuery(language, query), nil
		} else {
			return qc.FindTeamBaseQueryInTree(language, query, team.ParentID, teamsByID)
		}
	} else {
		return nil, fmt.Errorf("unknown team with id %d", teamId)
	}
}

func (qc *QueryCollection) FindCorpBaseQuery(language, query string) *Query {
	if ql := qc.GetQueryLanguage(language); ql != nil {
		for _, qg := range ql.QueryGroups {
			if qg.PackageType == CORP_QUERY {
				if q := qg.GetQuery(query); q != nil {
					return q
				}
			}
		}
	}
	return qc.FindProductQuery(language, query)
}

func (qc *QueryCollection) FindProductQuery(language, query string) *Query {
	if ql := qc.GetQueryLanguage(language); ql != nil {
		for _, qg := range ql.QueryGroups {
			if qg.PackageType == PRODUCT_QUERY {
				if q := qg.GetQuery(query); q != nil {
					return q
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

	cqc.GetQueryCount()

	return cqc
}

func (qc *QueryCollection) String() string {
	languages := len(qc.QueryLanguages)
	groups := 0
	queries := 0

	for _, ql := range qc.QueryLanguages {
		groups += len(ql.QueryGroups)
		for _, qg := range ql.QueryGroups {
			queries += len(qg.Queries)
		}
	}

	return fmt.Sprintf("Query collection with %d languages, %d groups, and %d queries", languages, groups, queries)
}

func (c SASTClient) GetQueryByID(qid uint64, queries *[]Query) *Query {
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

/*
This function returns some information about a query which may explain failure to migrate to CheckmarxOne
- query depends on other queries that may not exist (may need to be migrated first)
- query belongs to a non-existent project or team (has nowhere to migrate to)
- returns an empty array for product-default queries
*/
func (qc *QueryCollection) GetQueryDependencies(q *Query) []string {
	ret := []string{}
	if !q.IsCustom() {
		return ret
	}

	for _, id := range q.Dependencies {
		qq := qc.GetQueryByID(id)
		if qq != nil && qq.IsCustom() {
			ret = append(ret, fmt.Sprintf(" - depends on product query outside of the inheritance hierarchy: %v", qq.StringDetailed()))
		}
	}

	for _, id := range q.CustomDependencies {
		qq := qc.GetQueryByID(id)
		if qq != nil && qq.IsCustom() {
			ret = append(ret, fmt.Sprintf(" - depends on custom query outside of the inheritance hierarchy: %v", qq.StringDetailed()))
		}
	}

	if len(q.UnknownCalls) > 0 {
		ret = append(ret, fmt.Sprintf(" - calls the following unknown functions: %v", strings.Join(q.UnknownCalls, ", ")))
	}

	return ret
}

func (qc *QueryCollection) GetProjectQueries(project *Project) []*Query {
	queries := []*Query{}

	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			if qc.QueryLanguages[lid].QueryGroups[gid].OwningProjectID == project.ProjectID {
				for qid := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
					queries = append(queries, &qc.QueryLanguages[lid].QueryGroups[gid].Queries[qid])
				}
			}
		}
	}

	//queries = append(queries, qc.GetTeamQueries(project.TeamID)...)
	return queries
}

func (qc *QueryCollection) GetTeamQueries(teamId uint64) []*Query {
	queries := []*Query{}

	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			if qc.QueryLanguages[lid].QueryGroups[gid].OwningTeamID == teamId {
				for qid := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
					queries = append(queries, &qc.QueryLanguages[lid].QueryGroups[gid].Queries[qid])
				}
			}
		}
	}
	return queries
}

func (qc *QueryCollection) GetCorpQueries() []*Query {
	queries := []*Query{}

	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			if qc.QueryLanguages[lid].QueryGroups[gid].PackageType == CORP_QUERY {
				for qid := range qc.QueryLanguages[lid].QueryGroups[gid].Queries {
					queries = append(queries, &qc.QueryLanguages[lid].QueryGroups[gid].Queries[qid])
				}
			}
		}
	}
	return queries
}

func (q *Query) String() string {
	return fmt.Sprintf("[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
}

func (qc *QueryCollection) GetRootQueryID(queryId uint64) uint64 {
	var q *Query
	for q = qc.GetQueryByID(queryId); q != nil && q.BaseQueryID != q.QueryID; q = qc.GetQueryByID(q.BaseQueryID) {
		// nothing here, just crawl up the hierarchy
	}
	if q == nil {
		return 0
	}
	return q.QueryID
}

func (q *Query) StringDetailed() string {
	if q.IsCustom() {
		switch q.OwningGroup.PackageType {
		case CORP_QUERY:
			return fmt.Sprintf("Corp override [%d] %v -> %v -> %v, base query %d", q.QueryID, q.Language, q.Group, q.Name, q.BaseQueryID)
		case TEAM_QUERY:
			return fmt.Sprintf("Team %d override [%d] %v -> %v -> %v, base query %d", q.OwningGroup.OwningTeamID, q.QueryID, q.Language, q.Group, q.Name, q.BaseQueryID)
		case PROJECT_QUERY:
			return fmt.Sprintf("Project %d override [%d] %v -> %v -> %v, base query %d", q.OwningGroup.OwningProjectID, q.QueryID, q.Language, q.Group, q.Name, q.BaseQueryID)
		}
		return fmt.Sprintf("?? override [%d] %v -> %v -> %v, base query %d", q.QueryID, q.Language, q.Group, q.Name, q.BaseQueryID)
	} else {
		return fmt.Sprintf("Product default query [%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
	}
}

func (q *QueryGroup) String() string {
	typeStr := "Cx Default"
	if q.PackageType == TEAM_QUERY {
		typeStr = fmt.Sprintf("Team %d override", q.OwningTeamID)
	} else if q.PackageType == PROJECT_QUERY {
		typeStr = fmt.Sprintf("Project %d override", q.OwningProjectID)
	} else if q.PackageType == CORP_QUERY {
		typeStr = "Corp override"
	}
	return fmt.Sprintf("%v group [%d] %v -> %v", typeStr, q.PackageID, q.Language, q.Name)
}
func (q *QueryLanguage) String() string {
	return q.Name
}

func (c SASTClient) QueryLink(q *Query) string {
	return fmt.Sprintf("%v/CxWebClient/QueriesExplorer.aspx?queryid=%d", c.baseUrl, q.QueryID)
}

func (c SASTClient) QueryGroupLink(q *QueryGroup) string {
	return fmt.Sprintf("%v/CxWebClient/QueriesExplorer.aspx?language=%v&group=%v", c.baseUrl, q.Language, q.Name)
}

func (c SASTClient) QueryLanguageLink(q *QueryLanguage) string {
	return fmt.Sprintf("%v/CxWebClient/QueriesExplorer.aspx?language=%v", c.baseUrl, q.Name)
}

// convenience function for debugging (get this query's inheritance chain as strings)
func (qc *QueryCollection) QueryHierarchyString(queryId uint64) []string {
	path := []string{}

	pre := ""
	for q := qc.GetQueryByID(queryId); q != nil; q = qc.GetQueryByID(q.BaseQueryID) {
		path = append(path, fmt.Sprintf("%v%v", pre, q.StringDetailed()))
		pre = pre + " -> "
		if q.QueryID == q.BaseQueryID {
			break
		}
	}

	return path
}

// convenience function for debugging (get this query's inheritance chain as ints)
func (qc *QueryCollection) QueryHierarchy(queryId uint64) []uint64 {
	queries := []uint64{}
	query := qc.GetQueryByID(queryId)
	if query.BaseQueryID != query.QueryID {
		for q := qc.GetQueryByID(queryId); q != nil; q = qc.GetQueryByID(q.BaseQueryID) {
			queries = append(queries, q.QueryID)
			if q.BaseQueryID == q.QueryID {
				break
			}
		}
	}
	return queries
}
