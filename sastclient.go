package CxSASTClientGo

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"

	//"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func init() {

}

type User struct {
	UserID        uint64 `json:"id"`
	FirstName     string
	LastName      string
	UserName      string
	LastLoginDate string
	Email         string
	RoleIDs       []uint64
	TeamIDs       []uint64
}

type Role struct {
	RoleID        uint64 `json:"id"`
	IsSystemRole  bool
	Name          string
	Description   string
	PermissionIDs []uint64
}

type Links struct {
	Report Link `json:"report"`
	Status Link `json:"status"`
}

type Link struct {
	Rel string `json:"rel"`
	URI string `json:"uri"`
}

type SASTClient struct {
	httpClient  *http.Client
	authToken   string
	soapToken   string
	baseUrl     string
	logger      *logrus.Logger
	CurrentUser *User
}

type Project struct {
	ProjectID uint64 `json:"id"`
	TeamID    uint64
	Name      string
	Settings  *ProjectSettings
}

type ProjectSettings struct {
	ProjectID             uint64
	PresetID              uint64
	EngineConfigurationID uint64
	PostScanAction        int64
	EmailNotifications    struct {
		FailedScan []string
		BeforeScan []string
		AfterScan  []string
	}
}

type Team struct {
	TeamID   uint64 `json:"id"`
	Name     string
	ParentID uint64
	Projects []Project
}

type Preset struct {
	PresetID uint64 `json:"id"`
	Name     string
	Filled   bool
	Queries  []Query
}

type Query struct {
	Name      string
	QueryID   uint64 `xml:"QueryId"`
	CWE       uint64 `xml:"Cwe"`
	Severity  int
	PackageID uint64 `xml:"PackageId"`
	Language  string
	Group     string
}

type QueryGroup struct {
	Name            string
	PackageID       uint64
	Queries         []*Query
	Language        string `xml:"languageName"`
	OwningProjectID uint64 `xml:"ProjectId"`
	PackageType     string `xml:"PackageTypeName"`
	OwningTeamID    uint64 `xml:"OwningTeam"`
}

type Report struct {
	ReportID uint64 `json:"reportId"`
	Links    Links  `json:"links"`
}

// ReportStatusResponse - ReportStatusResponse Structure
type ReportStatusResponse struct {
	Location    string       `json:"location"`
	ContentType string       `json:"contentType"`
	Status      ReportStatus `json:"status"`
}

// ReportStatus - ReportStatus Structure
type ReportStatus struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type Scan struct {
	ScanID  uint64 `json:"id"`
	Project struct {
		ID   uint64
		Name string
	}
	Status struct {
		ID   uint64
		Name string
	}
	FinishTime time.Time
}

type PathNode struct {
	FileName string
	Line     uint64
	Column   uint64
	Name     string
	Length   uint64
}

type ScanResult struct {
	QueryName         string
	PathID            uint64
	Line              uint64
	Column            uint64
	DetectionDate     string
	Filename          string
	DeepLink          string
	Status            string
	Severity          string
	State             string
	SimilarityID      int64
	SourceMethod      string
	DestinationMethod string
	Nodes             []PathNode
}

type ScanResultStatusSummary struct {
	ToVerify               uint64
	NotExploitable         uint64
	Confirmed              uint64
	ProposedNotExploitable uint64
	Urgent                 uint64
}

type ScanResultSummary struct {
	High        ScanResultStatusSummary
	Medium      ScanResultStatusSummary
	Low         ScanResultStatusSummary
	Information ScanResultStatusSummary
}

func (c *SASTClient) createRequest(method, url string, body io.Reader, header *http.Header, cookies []*http.Cookie) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}

	for name, headers := range *header {
		for _, h := range headers {
			request.Header.Add(name, h)
		}
	}

	if request.Header.Get("Authorization") == "" {
		request.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0")
	}

	return request, nil
}

func (c *SASTClient) sendRequestInternal(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	var bodyBytes []byte
	c.logger.Debugf("Sending request to URL %v", url)
	if body != nil {
		closer := io.NopCloser(body)
		bodyBytes, _ = io.ReadAll(closer)
		defer closer.Close()
	}

	request, err := c.createRequest(method, url, bytes.NewReader(bodyBytes), &header, nil)
	if err != nil {
		c.logger.Errorf("Unable to create request: %s", err)
		return []byte{}, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		resBody, _ := io.ReadAll(response.Body)
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		c.logger.Errorf("HTTP request failed with error: %s", err)
		return resBody, err
	}
	if response.StatusCode >= 400 {
		resBody, _ := io.ReadAll(response.Body)
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		c.logger.Errorf("HTTP response indicates error: %v", response.Status)
		return resBody, errors.New("HTTP Response: " + response.Status)
	}

	resBody, err := io.ReadAll(response.Body)

	if err != nil {
		if err.Error() == "remote error: tls: user canceled" {
			c.logger.Warnf("HTTP request encountered error: %s", err)
		} else {
			c.logger.Errorf("Error reading response body: %s", err)
		}
		c.logger.Tracef("Parsed: %v", string(resBody))
	}

	return resBody, nil
}

func (c *SASTClient) sendRequest(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	sasturl := fmt.Sprintf("%v/cxrestapi%v", c.baseUrl, url)
	return c.sendRequestInternal(method, sasturl, body, header)
}

func (c *SASTClient) sendSOAPRequest(method string, body string) ([]byte, error) {
	sasturl := fmt.Sprintf("%v/CxWebInterface/Portal/CxWebService.asmx", c.baseUrl)
	header := http.Header{}
	SOAPEnvOpen := "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>"
	SOAPEnvClose := "</soap:Body></soap:Envelope>"

	header.Set("Content-Type", "text/xml; charset=utf-8")
	header.Set("SOAPAction", fmt.Sprintf("%v/%v", "http://Checkmarx.com", method))
	header.Set("Authorization", "Bearer "+c.soapToken)

	soap_msg := fmt.Sprintf("%v<%v xmlns=\"http://Checkmarx.com\">%v</%v>%v", SOAPEnvOpen, method, body, method, SOAPEnvClose)
	return c.sendRequestInternal(http.MethodPost, sasturl, strings.NewReader(soap_msg), header)
}

func (c *SASTClient) recordRequestDetailsInErrorCase(requestBody []byte, responseBody []byte) {
	if len(requestBody) != 0 {
		c.logger.Errorf("Request body: %s", string(requestBody))
	}
	if len(responseBody) != 0 {
		c.logger.Errorf("Response body: %s", string(responseBody))
	}
}

// convenience function
func (c *SASTClient) getV(api string, version string) ([]byte, error) {
	header := http.Header{}
	header.Add("Accept", "application/json;version="+version)

	return c.sendRequest(http.MethodGet, api, nil, header)
}

func (c *SASTClient) get(api string) ([]byte, error) {
	return c.getV(api, "1.0")
}

func (s *Scan) String() string {
	return fmt.Sprintf("Scan ID: %d, Project ID: %d, Status: %v, Time: %v", s.ScanID, s.Project.ID, s.Status, s.FinishTime.Format(time.RFC3339))
}

func getUserToken(client *http.Client, base_url string, username string, password string, logger *logrus.Logger) (string, error) {
	logger.Trace("Generating user token")
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("grant_type", "password")
	data.Set("scope", "sast_rest_api access_control_api")
	data.Set("client_secret", "014DF517-39D1-4453-B7B3-9930C563627C")
	data.Set("client_id", "resource_owner_client")

	sast_req, err := http.NewRequest(http.MethodPost, base_url+"/cxrestapi/auth/identity/connect/token", strings.NewReader(data.Encode()))

	if err != nil {
		logger.Errorf("Error: %s", err.Error())
		return "", err
	}

	sast_req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(sast_req)

	if err != nil {
		logger.Errorf("Error: %s", err.Error())
		return "", err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		logger.Errorf("Error: %s", err.Error())
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal(resBody, &jsonBody)

	if err != nil {
		logger.Errorf("Error: Login failed: %s", err.Error())
		return "", err
	}

	if jsonBody["access_token"] == nil {
		logger.Errorf("Response does not contain access token: %v", string(resBody))
		return "", errors.New("Response does not contain access token")
	} else {
		return jsonBody["access_token"].(string), nil
	}
}

func getSOAPToken(client *http.Client, base_url string, username string, password string, logger *logrus.Logger) (string, error) {
	logger.Trace("Generating SOAP token")
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("grant_type", "password")
	data.Set("scope", "sast_api offline_access")
	data.Set("client_secret", "014DF517-39D1-4453-B7B3-9930C563627C")
	data.Set("client_id", "resource_owner_sast_client")

	sast_req, err := http.NewRequest(http.MethodPost, base_url+"/cxrestapi/auth/identity/connect/token", strings.NewReader(data.Encode()))

	if err != nil {
		logger.Errorf("Error: %s", err.Error())
		return "", err
	}

	sast_req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(sast_req)

	if err != nil {
		logger.Errorf("Error: %s", err.Error())
		return "", err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		logger.Errorf("Error: %s", err.Error())
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal(resBody, &jsonBody)

	if err != nil {
		logger.Errorf("Error: Login failed: %s", err.Error())
		return "", err
	}

	if jsonBody["access_token"] == nil {
		logger.Errorf("Response does not contain access token: %v", string(resBody))
		return "", errors.New("Response does not contain access token")
	} else {
		return jsonBody["access_token"].(string), nil
	}
}

func (p *Project) String() string {
	return fmt.Sprintf("[%d] %v", p.ProjectID, p.Name)
}

func (c *SASTClient) GetProject(id uint64) (Project, error) {
	projects, err := c.GetProjects()

	if err != nil {
		return Project{}, err
	}

	for _, p := range projects {
		if p.ProjectID == id {
			return p, nil
		}
	}
	return Project{}, errors.New("Project ID not found")
}

func (c *SASTClient) GetProjects() ([]Project, error) {
	c.logger.Debug("Get SAST Projects")
	var projects []Project
	response, err := c.get("/projects")
	if err != nil {
		return projects, err
	}

	err = json.Unmarshal(response, &projects)
	c.logger.Tracef("Retrieved %d projects", len(projects))
	return projects, err

}

func (c *SASTClient) GetProjectsInTeam(teamid uint64) ([]Project, error) {
	c.logger.Debug("Get SAST Projects in team")
	var projects []Project
	response, err := c.get(fmt.Sprintf("/projects?teamId=%d", teamid))
	if err != nil {
		return projects, err
	}

	err = json.Unmarshal(response, &projects)
	c.logger.Tracef("Retrieved %d projects", len(projects))
	return projects, err
}

func (c *SASTClient) GetProjectSettings(projectid uint64) (ProjectSettings, error) {
	var responseStruct struct {
		Project struct {
			ID uint64
		}
		Preset struct {
			ID uint64
		}
		EngineConfiguration struct {
			ID uint64
		}
		PostScanAction     interface{}
		EmailNotifications struct {
			FailedScan []string
			BeforeScan []string
			AfterScan  []string
		}
	}

	var settings ProjectSettings

	c.logger.Debug("Get Project Settings for project ", projectid)

	response, err := c.get(fmt.Sprintf("/sast/scanSettings/%d", projectid))
	if err != nil {
		return settings, err
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return settings, err
	}

	settings.ProjectID = responseStruct.Project.ID
	settings.PresetID = responseStruct.Preset.ID
	settings.EngineConfigurationID = responseStruct.EngineConfiguration.ID

	if responseStruct.PostScanAction == nil {
		settings.PostScanAction = -1
	} else {
		settings.PostScanAction = responseStruct.PostScanAction.(int64)
	}

	settings.EmailNotifications.FailedScan = responseStruct.EmailNotifications.FailedScan
	settings.EmailNotifications.BeforeScan = responseStruct.EmailNotifications.BeforeScan
	settings.EmailNotifications.AfterScan = responseStruct.EmailNotifications.AfterScan

	return settings, err
}

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
			c.logger.Errorf(" - SOAP Token %v is not valid?", shortenGUID(c.soapToken))
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

func (c *SASTClient) GetResultsFromXML(xmlReportData []byte) ([]ScanResult, error) {
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
			XMLName xml.Name `xml:"Query"`
			Name    string   `xml:"name,attr"`
			Results []struct {
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

func (c *SASTClient) GetScanResultSummary(results []ScanResult) ScanResultSummary {
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

func (c *SASTClient) GetScan(scanid uint64) (Scan, error) {
	c.logger.Debugf("Get SAST scan %d", scanid)
	var scan Scan

	response, err := c.get(fmt.Sprintf("/sast/scans/%d", scanid))
	if err != nil {
		return scan, err
	}

	err = json.Unmarshal(response, &scan)
	return scan, err
}

func (c *SASTClient) GetLastScan(projectid uint64) (Scan, error) {
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

func (t Team) HasProjects() bool {
	return len(t.Projects) > 0
}

// Teams
func (t *Team) String() string {
	return fmt.Sprintf("[%d] %v", t.TeamID, t.Name)
}

func (c *SASTClient) GetTeams() ([]Team, error) {
	c.logger.Debug("Get SAST Teams")
	var teams []Team
	response, err := c.get("/auth/teams")
	if err != nil {
		return teams, err
	}

	err = json.Unmarshal(response, &teams)
	return teams, err
}

// Users
func (u *User) String() string {
	return fmt.Sprintf("[%d] %v %v (%v)", u.UserID, u.FirstName, u.LastName, u.Email)
}

func (c *SASTClient) GetUsers() ([]User, error) {
	c.logger.Debug("Get SAST Users")
	var users []User
	response, err := c.get("/auth/users")
	if err != nil {
		return users, err
	}

	err = json.Unmarshal(response, &users)
	return users, err
}

func (c *SASTClient) GetCurrentUser() (User, error) {
	c.logger.Trace("Get SAST User Info")
	var user User
	response, err := c.get("/auth/MyProfile")
	if err != nil {
		return user, err
	}

	err = json.Unmarshal(response, &user)
	return user, err
	//c.logger.Warning( "Parsing input: " + strig(response) )
	/*
			if err == nil {
				return User {
					uint64(jsonBody["id"].(float64)),
					jsonBody["firstName"].(string),
					jsonBody["lastName"].(string),
		            jsonBody["userName"].(string),

				}, nil
			} else {
				c.logger.Error( "Login failed: " + err.Error() )
		        c.logger.Warning( "Failed while parsing response: " + string(response) )
		        return User{}, err
			}*/
}

// Roles
func (r *Role) String() string {
	return fmt.Sprintf("[%d] %v", r.RoleID, r.Name)
}

func (c *SASTClient) GetRoles() ([]Role, error) {
	c.logger.Debug("Get SAST Roles")
	var roles []Role
	response, err := c.get("/auth/roles")
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	return roles, err
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

// Links to objects in the portal
func (c *SASTClient) ProjectLink(p *Project) string {
	return fmt.Sprintf("%v/CxWebClient/ProjectScans.aspx?id=%d", c.baseUrl, p.ProjectID)
}

func (c *SASTClient) PresetLink(p *Preset) string {
	return fmt.Sprintf("%v/CxWebClient/Presets.aspx?id=%d", c.baseUrl, p.PresetID)
}

func (c *SASTClient) UserLink(u *User) string {
	return fmt.Sprintf("%v/CxRestAPI/auth/#/users?id=%d", c.baseUrl, u.UserID) // this link doesn't actually work, just takes you to the main page
}

func (c *SASTClient) RoleLink(r *Role) string {
	return fmt.Sprintf("%v/CxRestAPI/auth/#/roles/%d", c.baseUrl, r.RoleID)
}

func (c *SASTClient) TeamLink(t *Team) string {
	return fmt.Sprintf("%v/CxRestAPI/auth/#/teams/id=%d", c.baseUrl, t.TeamID) // this link doesn't actually work, just takes you to the main page
}

func (c *SASTClient) String() string {
	return c.baseUrl + " with token: " + shortenGUID(c.authToken)
}

func (c *SASTClient) GetToken() string {
	return c.authToken
}

func shortenGUID(guid string) string {
	return fmt.Sprintf("%v..%v", guid[:2], guid[len(guid)-2:])
}

func New(client *http.Client, base_url string, usertoken string, soaptoken string, logger *logrus.Logger) *SASTClient {
	cli := &SASTClient{client, usertoken, soaptoken, base_url, logger, nil}

	user, err := cli.GetCurrentUser()
	cli.CurrentUser = &user
	if err != nil {
		logger.Errorf("Error while fetching current user information: %s", err)
	}

	//	cli.RefreshCache()
	return cli
}

func NewTokenClient(client *http.Client, base_url string, username string, password string, logger *logrus.Logger) (*SASTClient, error) {
	usertoken, err := getUserToken(client, base_url, username, password, logger)
	if err != nil {
		logger.Fatal("Error initializing SAST client: " + err.Error())
		return nil, err
	}

	soaptoken, err := getSOAPToken(client, base_url, username, password, logger)
	if err != nil {
		logger.Fatal("Error initializing SAST client: " + err.Error())
		return nil, err
	}

	logger.Infof("Generated user token %v, soap token %v", shortenGUID(usertoken), shortenGUID(soaptoken))

	return New(client, base_url, usertoken, soaptoken, logger), nil
}
