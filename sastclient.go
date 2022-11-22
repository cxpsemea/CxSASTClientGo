package CxSASTClientGo

import (
    "fmt"
	"time"
    "net/http"
    "io"
	"io/ioutil"
	"encoding/json"
	"strconv"
	"net/url"
	"strings"
    "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func init() {
	
}

type User struct {
	UserID int64
	FirstName string
	LastName string
    UserName string
}

type SASTclient struct {
	httpClient *http.Client
	authToken string
	baseUrl string
    logger *logrus.Logger
//	UserInfo *User
/*	Projects []Project
	Teams []Team
	Users []User
	Queries []Query
	QueryGroups []QueryGroup // caching - to reconsider if needed
	Presets []Preset */
}

type Project struct {
	ProjectID int64
	TeamID int64
	Name string
}

type Team struct {
	TeamID int64
	Name string
    ParentID int64
//	Projects []Project
}

type Preset struct {
	PresetID int64
	Name string
}

type Query struct {
	QueryID int64
	QueryGroupID int64
	Name string
	Severity int
	UpdateTime time.Time
}

type QueryGroup struct {
	QueryGroupID int64
	Name string
	Language string
	Scope string
	OwningTeamID int64
	OwningProjectID int64
}

type Scan struct {
	ScanID int64
	ProjectID int64
	Status string
	FinishTime time.Time
}


func (c *SASTclient) createRequest(method, url string, body io.Reader, header *http.Header, cookies []*http.Cookie) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}

	if header != nil {
		for name, headers := range *header {
			for _, h := range headers {
				request.Header.Add(name, h)
			}
		}
	}


    header.Set( "Authorization", "Bearer " + c.authToken )
    if header.Get("User-Agent") == "" {
        header.Set( "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0" )
    }

	return request, nil
}

func (c *SASTclient) sendRequestInternal(method, url string, body io.Reader, header http.Header) ([]byte, error) {
    var bodyBytes []byte

    if body != nil {
        closer := ioutil.NopCloser(body)
        bodyBytes, _ = ioutil.ReadAll(closer)
        defer closer.Close()
    }

    request, err := c.createRequest( method, url, body, &header, nil )
    if err != nil {
        c.logger.Errorf("Unable to create request: %s", err )
        return []byte{}, err
    }


    response, err := c.httpClient.Do(request)
    defer response.Body.Close()
    if err != nil {
        resBody,err := ioutil.ReadAll( response.Body )
        c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
        c.logger.Errorf("HTTP request failed with error: %s", err)
        return []byte{}, err
    }

    resBody,err := ioutil.ReadAll( response.Body )

	if err != nil {
		c.logger.Error( "Error reading response body: %s", err )
		return []byte{}, err
	}


    return resBody, nil
}

func (c *SASTclient) sendRequest(method, url string, body io.Reader, header http.Header) ([]byte, error) {
    sasturl := fmt.Sprintf("%v/cxrestapi%v", c.baseUrl, url)
    return c.sendRequestInternal(method, sasturl, body, header )
}

func (c *SASTclient) recordRequestDetailsInErrorCase(requestBody []byte, responseBody []byte ) {
    if len(requestBody) != 0 {
        c.logger.Errorf("Request body: %s", string(requestBody) )
    }
    if len(responseBody) != 0 {
        c.logger.Errorf("Response body: %s", string(responseBody))
    }
}


// convenience function
func (c *SASTclient) getV( api string, version string ) ([]byte, error) {
    header := http.Header{}
    header.Add( "Accept", "application/json;version=" + version )

	return c.sendRequest( http.MethodGet, api, nil, header )
}


func (c *SASTclient) get( api string ) ([]byte,error) {
	return c.getV( api, "1.0" )
}


func (s Scan) ToString() string {
	return "Scan ID: " + strconv.FormatInt( s.ScanID, 10 ) + ", Project ID: " + strconv.FormatInt( s.ProjectID, 10 ) + ", Status: " + s.Status + ", Time: " + s.FinishTime.Format(time.RFC3339)
}

func getUserToken( client *http.Client, base_url string, username string, password string, logger *logrus.Logger ) (string, error) {
	data := url.Values{}
	data.Set( "username", username )
	data.Set( "password", password )
	data.Set( "grant_type", "password" )
	data.Set( "scope", "sast_rest_api access_control_api" )
	data.Set( "client_secret", "014DF517-39D1-4453-B7B3-9930C563627C" )
	data.Set( "client_id", "resource_owner_client" )
	
	sast_req, err := http.NewRequest("POST", base_url + "/cxrestapi/auth/identity/connect/token", strings.NewReader( data.Encode() ))
	
	if err != nil {
		logger.Errorf( "Error: %s", err.Error() )
		return "", err
	}

	sast_req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do( sast_req );
	

	if err != nil {
		logger.Errorf( "Error: %s", err.Error() )
		return "", err
	}
	defer res.Body.Close()

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		logger.Errorf( "Error: %s", err.Error() )
		return "", err
	}

	var jsonBody map[string]interface{}

	err = json.Unmarshal( resBody, &jsonBody)

	if err != nil {
        logger.Errorf( "Error: Login failed: %s", err.Error() )
	    return "", err
    }

    token := jsonBody["access_token"].(string)
    return token, nil
}

func (c *SASTclient) GetProject ( id int64 ) (Project, error) {
    projects, err := c.GetProjects()
    
    if err != nil {
        return Project{}, err
    }

	for _, p := range projects {
		if p.ProjectID == id {
			return p, nil
		}
	}
	return Project{}, errors.New( "Project ID not found" )
}

func (c *SASTclient) GetProjects () ([]Project, error) {
    response, err := c.get( "/cxrestapi/projects" )
    if err != nil {
        return []Project{},  err
    }
    return c.parseProjects( response )

}

func (c *SASTclient) GetProjectsInTeam ( teamid int64 ) ([]Project, error) {

    response, err := c.get( "/cxrestapi/projects?teamId=" + strconv.FormatInt( teamid, 10 ) )
    if err != nil {
        return []Project{}, err
    }
    return c.parseProjects( response )
}


func (c *SASTclient) GetScan( scanid int64 ) (Scan,error) {
	c.logger.Debug( "Get scan " + strconv.FormatInt( scanid, 10 ))
    response, err := c.get( "/cxrestapi/sast/scans/" + strconv.FormatInt( scanid, 10 ) )
    if err != nil {
        return Scan{}, err
    }

    return c.parseScan( response )
}

func (c *SASTclient) GetLastScan ( projectid int64 ) (Scan, error) {
    var scan Scan
    response, err := c.get( "/cxrestapi/sast/scans?projectId=" + strconv.FormatInt( projectid, 10 ) + "&scanStatus=Finished&last=1" )
    if err != nil {
        return scan, err
    }

	scans,err := c.parseScans( response )
	if err != nil {
		return scan, err
	}
	return scans[0], nil
}

func (c *SASTclient) parseScanFromInterface( single_scan *map[string]interface{} ) (Scan, error) {
	var scan Scan

	scan.ScanID = int64( (*single_scan)["id"].(float64))

	project := (*single_scan)["project"]
	scan.ProjectID = int64(project.(map[string]interface{})["id"].(float64))

	status := (*single_scan)["status"]
	scan.Status = status.(map[string]interface{})["name"].(string)

	dnt := (*single_scan)["dateAndTime"]

	var err error
	scan.FinishTime, err = time.Parse(time.RFC3339, dnt.(map[string]interface{})["finishedOn"].(string) + "Z" )
	if err != nil {
		c.logger.Error( "Error parsing date/time: " + err.Error() )		
	}

	return scan, err
}

func (c *SASTclient) parseScan( input []byte ) (Scan, error) {
    var scan Scan
	c.logger.Trace( "Parsing single scan from: " + string(input) )
	var single_scan map[string]interface{}
	err := json.Unmarshal( input, &single_scan )
	if err != nil {
		c.logger.Error("Error: " + err.Error() )
		c.logger.Error( "Input was: " + string(input) )
		return scan, err
	} else {		
		return c.parseScanFromInterface( &single_scan )
	}
}

func (c *SASTclient) parseScans( input []byte ) ([]Scan, error) {
	c.logger.Trace( "Parsing scans from: " + string(input) )

	var scans []map[string]interface{}

	var scanList []Scan

	err := json.Unmarshal( input, &scans )
	if err != nil {
		c.logger.Error("Error: " + err.Error() )
		c.logger.Error( "Input was: " + string(input) )
        return scanList, err
	} else {
		scanList = make([]Scan, len(scans) )
		//id := 0
		for id, scan := range scans {
			scanList[id], err = c.parseScanFromInterface( &scan )
		}
	}

	return scanList, nil
}

func (c *SASTclient) parseProjects( input []byte ) ([]Project, error) {
	var projects []interface{}

	var projectList []Project

	c.logger.Trace( "Parsing projects from: " + string(input) )
	err := json.Unmarshal( input, &projects )
	if err != nil {
		c.logger.Error("Error: " + err.Error() )
        return projectList, err
	} else {
		projectList = make([]Project, len(projects) )
		for id := range projects {
			projectList[id].ProjectID = int64(projects[id].(map[string]interface{})["id"].(float64))
			projectList[id].TeamID = int64(projects[id].(map[string]interface{})["teamId"].(float64))
			projectList[id].Name = projects[id].(map[string]interface{})["name"].(string)
		}
	}

	return projectList, nil
}

/*
func (t Team) HasProjects() bool {
	return len(t.Projects) > 0
}
*/

/*
func (c *SASTclient) matchTeamProjects() {
	for index := range c.Teams {
		c.logger.Trace( "Looking for projects belonging to team " + c.Teams[index].Name )
		for _, project := range c.Projects {
			if c.Teams[index].TeamID == project.TeamID {
				c.Teams[index].Projects = append( c.Teams[index].Projects, project )
			}
		}
	}
} */

func (c *SASTclient) GetTeams () ([]Team, error) {
    response, err := c.get( "/cxrestapi/auth/teams" )
    if err != nil {
        return []Team{}, err
    }

    return c.parseTeams( response )
}

func (c *SASTclient) parseTeams( input []byte ) ([]Team, error) {
	var teams []interface{}

	var teamList []Team

	c.logger.Trace( "Parsing teams from input: " + string(input) )
	err := json.Unmarshal( input, &teams )
	if err != nil {
		c.logger.Error("Error: " + err.Error() )
        return teamList, err
	} else {
		teamList = make([]Team, len(teams) )
		for id := range teams {
			teamList[id].TeamID = int64(teams[id].(map[string]interface{})["id"].(float64))
			teamList[id].Name = teams[id].(map[string]interface{})["fullName"].(string)
            teamList[id].ParentID = int64(teams[id].(map[string]interface{})["parentId"].(float64))
		}
	}

	return teamList, nil
}

func (c *SASTclient) GetUsers () ([]User, error) {
    response, err := c.get( "/cxrestapi/auth/users" )
    if err != nil {
        return []User{}, err
    }
    return c.parseUsers( response )
}

func (c *SASTclient) parseUserFromInterface( single_user *map[string]interface{} ) User {
	user := User{}
	user.UserID = int64( (*single_user)["id"].(float64) )
	user.FirstName = (*single_user)["firstName"].(string)
	user.LastName = (*single_user)["lastName"].(string)
    user.UserName = (*single_user)["userName"].(string)
	return user
}

func (c *SASTclient) parseUsers( input []byte ) ([]User, error) {
	var users []map[string]interface{}
	var userList []User

	c.logger.Trace( "Parsing users from input: " + string(input) )
	err := json.Unmarshal( input, &users )
	if err != nil {
		c.logger.Error("Error: " + err.Error() )
        return userList, err
	} else {
		userList = make([]User, len(users) )
		for id := range users {
			userList[id] = c.parseUserFromInterface( &(users[id]) )
		}
	}

	return userList, nil
}


func (c *SASTclient) getUserInfo () (User, error) {
	c.logger.Trace( "SAST Get User Info" )
	response, err := c.get( "/cxrestapi/auth/MyProfile" )
    if err != nil {
        return User{}, err
    }

	var jsonBody map[string]interface{}

	err = json.Unmarshal( []byte(response), &jsonBody)

    //c.logger.Warning( "Parsing input: " + strig(response) )
	if err == nil {
		return User {
			int64(jsonBody["id"].(float64)),
			jsonBody["firstName"].(string),
			jsonBody["lastName"].(string),
            jsonBody["userName"].(string),
		}, nil
	} else {
		c.logger.Error( "Login failed: " + err.Error() )
        return User{}, err
	}
}

func (c *SASTclient) parsePresetFromInterface( single_preset *map[string]interface{} ) Preset {
	preset := Preset{}
	preset.PresetID = int64( (*single_preset)["id"].(float64) )
	preset.Name = (*single_preset)["name"].(string)
	return preset
}

func (c *SASTclient) parsePresets( input []byte ) ([]Preset, error) {
	var presets []map[string]interface{}
	var presetList []Preset

	c.logger.Trace( "Parsing presets from input: " + string(input) )
	err := json.Unmarshal( input, &presets )
	if err != nil {
		c.logger.Error("Error: " + err.Error() )
        return presetList, err
	} else {
		presetList = make([]Preset, len(presets) )
		for id := range presets {
			presetList[id] = c.parsePresetFromInterface( &(presets[id]) )
		}
	}

	return presetList, nil
}

func (c *SASTclient) GetPresets () ([]Preset, error) {
    response, err := c.get( "/cxrestapi/sast/presets" )
    if err != nil {
        return []Preset{}, err
    }
    return c.parsePresets( response )
}

/* no rest endpoint for this?
func (c *SASTclient) GetQueries () *[]Query {
	if len( c.Queries ) == 0 {
		//c.Queries = c.parseQueries( c.get( "/cxrestapi/" )	)
	}

	return &c.Queries
}*/

/*
func (c *SASTclient) PresetSummary() string {

	return strconv.Itoa( len( c.Presets ) ) + " presets"
}
func (c *SASTclient) QuerySummary() string {
	
	return strconv.Itoa( len( c.Queries ) ) + " queries  in " + strconv.Itoa( len( c.QueryGroups ) ) + " groups"
}
func (c *SASTclient) UserSummary() string {
	
	return strconv.Itoa( len( c.Users ) ) + " users"
}
func (c *SASTclient) TeamSummary() string {
	
	return strconv.Itoa( len( c.Teams ) ) + " teams"
}
func (c *SASTclient) TeamTree() string {
    return ""
}
func (c *SASTclient) ProjectSummary() string {
	
	return strconv.Itoa( len( c.Projects ) ) + " projects"
} */

func (c *SASTclient) ToString() string {
	return c.baseUrl + " with token: " + c.authToken[:4] + "..." + c.authToken[ len(c.authToken) - 4:]
}

func (c *SASTclient) GetToken() string {
    return c.authToken
}

func New( client *http.Client, base_url string, token string, logger *logrus.Logger ) *SASTclient {
	cli := &SASTclient{ client, token, base_url, logger }
//	cli.getUserInfo()
//	cli.RefreshCache()
	return cli
}

func NewTokenClient( client *http.Client, base_url string, username string, password string, logger *logrus.Logger ) (*SASTclient, error) {
	token, err := getUserToken( client, base_url, username, password, logger )
    if err != nil {
        logger.Fatal( "Error initializing SAST client: " + err.Error() )
        return nil, err
    }

	return New( client, base_url, token, logger ), nil
}