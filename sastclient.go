package CxSASTClientGo

import (
    "fmt"
	"time"
    "net/http"
	"io/ioutil"
	"encoding/json"
	"strconv"
	"net/url"
	"strings"
    "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
	Projects []Project
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

func (c SASTclient) getV( api string, version string ) (string, error) {
	url := c.baseUrl + api
	log.Trace( "Attempting to fetch " + url )

	sast_req, err := http.NewRequest("GET", url, nil)
	sast_req.Header.Add( "Authorization", "Bearer " + c.authToken )
	sast_req.Header.Add( "Accept", "application/json;" + version )
	if err != nil {
		fmt.Printf( "Error: " + err.Error() )
		return "", err
	}

	
	res, err := c.httpClient.Do( sast_req );
	defer res.Body.Close()

	if err != nil {
		fmt.Printf( "Error: " + err.Error() )
		return "", err
	}

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		fmt.Printf( "Error: " + err.Error() )
		return "", err
	}


	return string(resBody), nil
}

func (s Scan) ToString() string {
	return "Scan ID: " + strconv.FormatInt( s.ScanID, 10 ) + ", Project ID: " + strconv.FormatInt( s.ProjectID, 10 ) + ", Status: " + s.Status + ", Time: " + s.FinishTime.Format(time.RFC3339)
}

func getUserToken( base_url string, username string, password string ) (string, error) {
	data := url.Values{}
	data.Set( "username", username )
	data.Set( "password", password )
	data.Set( "grant_type", "password" )
	data.Set( "scope", "sast_rest_api access_control_api" )
	data.Set( "client_secret", "014DF517-39D1-4453-B7B3-9930C563627C" )
	data.Set( "client_id", "resource_owner_client" )
	
	sast_req, err := http.NewRequest("POST", base_url + "/cxrestapi/auth/identity/connect/token", strings.NewReader( data.Encode() ))
	
	if err != nil {
		fmt.Printf( "Error: " + err.Error() )
		return "", err
	}

	sast_req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	res, err := client.Do( sast_req );
	

	if err != nil {
		fmt.Printf( "Error: " + err.Error() )
		return "", err
	}
	defer res.Body.Close()

	resBody,err := ioutil.ReadAll( res.Body )

	if err != nil {
		fmt.Printf( "Error: " + err.Error() )
		return "", err
	}

	//log.Trace( "Response: " + string(resBody) )

	var jsonBody map[string]interface{}

	err = json.Unmarshal( resBody, &jsonBody)

	if err == nil {
		token := jsonBody["access_token"].(string)
		return token, nil
	}

	log.Error( "Error: Login failed: " + err.Error() )
	return "", err
}

func (c SASTclient) get( api string ) (string,error) {
	return c.getV( api, "v=1.0" )
}

func (c *SASTclient) GetProject ( id int64 ) (Project, error) {
    projects, err := c.GetProjects()
    
	for _, p := range c.Projects {
		if p.ProjectID == id {
			return p, nil
		}
	}
	return Project{}, errors.New( "Project ID not found" )
}

func (c *SASTclient) GetProjects () ([]Project, error) {
	if len( c.Projects ) == 0 {
        response, err := c.get( "/cxrestapi/projects" )
        if err != nil {
            return c.Projects, err
        }
		c.Projects, err = parseProjects( response )
        return c.Projects, err
	}
	return c.Projects, nil
}

func (c *SASTclient) GetProjectsInTeam ( teamid int64 ) ([]Project, error) {
	if len( c.Projects ) == 0 {
        response, err := c.get( "/cxrestapi/projects?teamId=" + strconv.FormatInt( teamid, 10 ) )
        if err != nil {
            return c.Projects, err
        }

		c.Projects, err = parseProjects( response	)
        return c.Projects, err
	}
	return c.Projects, nil
}


func (c *SASTclient) GetScan( scanid int64 ) (Scan,error) {
	log.Debug( "Get scan " + strconv.FormatInt( scanid, 10 ))
    response, err := c.get( "/cxrestapi/sast/scans/" + strconv.FormatInt( scanid, 10 ) )
    if err != nil {
        return Scan{}, err
    }

    return parseScan( response )
}

func (c *SASTclient) GetLastScan ( projectid int64 ) (Scan, error) {
    var scan Scan
    response, err := c.get( "/cxrestapi/sast/scans?projectId=" + strconv.FormatInt( projectid, 10 ) + "&scanStatus=Finished&last=1" )
    if err != nil {
        return scan, err
    }

	scans,err := parseScans( response )
	if err != nil {
		return scan, err
	}
	return scans[0], nil
}

func parseScanFromInterface( single_scan *map[string]interface{} ) (Scan, error) {
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
		log.Error( "Error parsing date/time: " + err.Error() )		
	}

	return scan, err
}

func parseScan( input string ) (Scan, error) {
    var scan Scan
	log.Trace( "Parsing single scan from: " + input )
	var single_scan map[string]interface{}
	err := json.Unmarshal( []byte( input ), &single_scan )
	if err != nil {
		log.Error("Error: " + err.Error() )
		log.Error( "Input was: " + input )
		return scan, err
	} else {		
		return parseScanFromInterface( &single_scan )
	}
}

func parseScans( input string ) ([]Scan, error) {
	log.Trace( "Parsing scans from: " + input )

	var scans []map[string]interface{}

	var scanList []Scan

	err := json.Unmarshal( []byte( input ), &scans )
	if err != nil {
		log.Error("Error: " + err.Error() )
		log.Error( "Input was: " + input )
        return scanList, err
	} else {
		scanList = make([]Scan, len(scans) )
		//id := 0
		for id, scan := range scans {
			scanList[id], err = parseScanFromInterface( &scan )
		}
	}

	return scanList, nil
}

func parseProjects( input string ) ([]Project, error) {
	var projects []interface{}

	var projectList []Project

	log.Trace( "Parsing projects from: " + input )
	err := json.Unmarshal( []byte( input ), &projects )
	if err != nil {
		log.Error("Error: " + err.Error() )
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

func (t Team) HasProjects() bool {
	return len(t.Projects) > 0
}

func (c SASTclient) matchTeamProjects() {
	for index := range c.Teams {
		log.Trace( "Looking for projects belonging to team " + c.Teams[index].Name )
		for _, project := range c.Projects {
			if c.Teams[index].TeamID == project.TeamID {
				c.Teams[index].Projects = append( c.Teams[index].Projects, project )
			}
		}
	}
}

func (c *SASTclient) GetTeams () ([]Team, error) {
	if len( c.Teams ) == 0 {
        response, err := c.get( "/cxrestapi/auth/teams" )
        if err != nil {
            return c.Teams, err
        }

		c.Teams, err = parseTeams( response	)
        return c.Teams, err
	}

	return c.Teams, nil
}

func parseTeams( input string ) ([]Team, error) {
	var teams []interface{}

	var teamList []Team

	log.Trace( "Parsing teams from input: " + input )
	err := json.Unmarshal( []byte( input ), &teams )
	if err != nil {
		log.Error("Error: " + err.Error() )
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
	if len( c.Users ) == 0 {
        response, err := c.get( "/cxrestapi/auth/users" )
        if err != nil {
            return c.Users, err
        }

		c.Users, err = parseUsers( response)
        return c.Users, err
	}

	return c.Users, nil
}

func parseUserFromInterface( single_user *map[string]interface{} ) User {
	user := User{}
	user.UserID = int64( (*single_user)["id"].(float64) )
	user.FirstName = (*single_user)["firstName"].(string)
	user.LastName = (*single_user)["lastName"].(string)
    user.UserName = (*single_user)["userName"].(string)
	return user
}

func parseUsers( input string ) ([]User, error) {
	var users []map[string]interface{}
	var userList []User

	log.Trace( "Parsing users from input: " + input )
	err := json.Unmarshal( []byte( input ), &users )
	if err != nil {
		log.Error("Error: " + err.Error() )
        return userList, err
	} else {
		userList = make([]User, len(users) )
		for id := range users {
			userList[id] = parseUserFromInterface( &(users[id]) )
		}
	}

	return userList, nil
}

func (c *SASTclient) getUserInfo () error {
	log.Trace( "SAST Get User Info" )
	response, err := c.get( "/cxrestapi/auth/MyProfile" )
    if err != nil {
        return err
    }

	var jsonBody map[string]interface{}

	err = json.Unmarshal( []byte(response), &jsonBody)

    log.Warning( "Parsing input: " + response )
	if err == nil {
		c.UserInfo = &User {
			int64(jsonBody["id"].(float64)),
			jsonBody["firstName"].(string),
			jsonBody["lastName"].(string),
            jsonBody["userName"].(string),
		}
        return nil
	} else {
		log.Error( "Login failed: " + err.Error() )
        return err
	}
}

func parsePresetFromInterface( single_preset *map[string]interface{} ) Preset {
	preset := Preset{}
	preset.PresetID = int64( (*single_preset)["id"].(float64) )
	preset.Name = (*single_preset)["name"].(string)
	return preset
}

func parsePresets( input string ) ([]Preset, error) {
	var presets []map[string]interface{}
	var presetList []Preset

	log.Trace( "Parsing presets from input: " + input )
	err := json.Unmarshal( []byte( input ), &presets )
	if err != nil {
		log.Error("Error: " + err.Error() )
        return presetList, err
	} else {
		presetList = make([]Preset, len(presets) )
		for id := range presets {
			presetList[id] = parsePresetFromInterface( &(presets[id]) )
		}
	}

	return presetList, nil
}

func (c *SASTclient) GetPresets () ([]Preset, error) {
	if len( c.Presets ) == 0 {
        response, err := c.get( "/cxrestapi/sast/presets" )
        if err != nil {
            return c.Presets, err
        }

		c.Presets, err = parsePresets( response )
        return c.Presets, err
	}

	return c.Presets, nil
}

/* no rest endpoint for this?
func (c *SASTclient) GetQueries () *[]Query {
	if len( c.Queries ) == 0 {
		//c.Queries = parseQueries( c.get( "/cxrestapi/" )	)
	}

	return &c.Queries
}*/

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
}

func (c *SASTclient) ToString() string {
	return c.baseUrl + " with token: " + c.authToken[:4] + "..." + c.authToken[ len(c.authToken) - 4:]
}

func (c *SASTclient) GetToken() string {
    return c.authToken
}

func New( base_url string, token string ) *SASTclient {
	cli := &SASTclient{ &http.Client{}, token, base_url, nil, nil, nil, nil, nil, nil, nil }
//	cli.getUserInfo()
//	cli.RefreshCache()
	return cli
}

func NewTokenClient( base_url string, username string, password string ) (*SASTclient, error) {
	token, err := getUserToken( base_url, username, password )
    if err != nil {
        log.Fatal( "Error initializing SAST client: " + err.Error() )
        return nil, err
    }

	return New( base_url, token )
}