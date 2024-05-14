package CxSASTClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func (p *Project) String() string {
	return fmt.Sprintf("[%d] %v", p.ProjectID, p.Name)
}

func (pr *ProjectRepo) String() string {
	return fmt.Sprintf("%v - branch %v", pr.URL, pr.Branch)
}

func (c SASTClient) GetProject(id uint64) (Project, error) {
	c.depwarn("GetProject", "GetProjectByID")
	return c.GetProjectByID(id)
}

func (c SASTClient) GetProjectByID(id uint64) (Project, error) {
	return c.GetProjectByIDV(id, "1.0")
}

func (c SASTClient) GetProjectByIDV(id uint64, version string) (Project, error) {
	c.logger.Tracef("Get SAST Project with ID %d, api %v", id, version)
	var project Project

	response, err := c.getV(fmt.Sprintf("/projects/%d", id), version)
	if err != nil {
		c.logger.Errorf("Failed to retrieve project: %s", err)
		return project, err
	}

	var pp ProjectComplex
	err = json.Unmarshal(response, &pp)
	if err != nil {
		c.logger.Errorf("Failed to unmarshal project: %s", err)
		c.logger.Tracef("Response was: %v", string(response))
		return project, err
	}
	project = pp.ToProject()

	return project, nil
}

func (c SASTClient) GetProjectCustomFields(project *Project) error {
	response, err := c.getV(fmt.Sprintf("/projects/%d", project.ProjectID), "2.0")
	if err != nil {
		return err
	}

	var pp ProjectComplex
	err = json.Unmarshal(response, &pp)
	if err != nil {
		return err
	}

	project.CustomFields = pp.CustomFields
	return nil
}

func (c SASTClient) GetProjects() ([]Project, error) {
	c.logger.Debug("Get SAST Projects")
	var projects []Project
	response, err := c.get("/projects")
	if err != nil {
		return projects, err
	}

	var pps []ProjectComplex
	err = json.Unmarshal(response, &pps)
	c.logger.Tracef("Retrieved %d projects", len(pps))
	if err != nil {
		c.logger.Errorf("Failed to parse project response: %s", err)
		return projects, err
	}

	projects = ConvertProjects(&pps)

	return projects, err

}

func (c SASTClient) GetProjectsByName(name string) ([]Project, error) {
	c.logger.Debugf("Get SAST Projects matching %v", name)
	var projects []Project
	response, err := c.getV(fmt.Sprintf("/projects?projectName=%v", name), "2.1")
	if err != nil {
		return projects, err
	}

	var pps []ProjectComplex
	err = json.Unmarshal(response, &pps)
	c.logger.Tracef("Retrieved %d projects", len(pps))
	if err != nil {
		c.logger.Errorf("Failed to parse project response: %s", err)
		return projects, err
	}

	projects = ConvertProjects(&pps)

	return projects, err

}

func (c SASTClient) GetProjectsInTeam(teamid uint64) ([]Project, error) {
	c.depwarn("GetProjectsInTeam", "GetProjectsInTeamByID")
	return c.GetProjectsInTeamByID(teamid)
}

func (c SASTClient) GetProjectsInTeamByID(teamid uint64) ([]Project, error) {
	c.logger.Debug("Get SAST Projects in team")
	var projects []Project
	response, err := c.get(fmt.Sprintf("/projects?teamId=%d", teamid))
	if err != nil {
		return projects, err
	}

	var pps []ProjectComplex
	err = json.Unmarshal(response, &pps)
	c.logger.Tracef("Retrieved %d projects", len(pps))
	if err != nil {
		c.logger.Errorf("Failed to parse project response: %s", err)
		return projects, err
	}

	projects = ConvertProjects(&pps)
	return projects, err
}

func (c SASTClient) GetProjectSettings(project *Project) error {
	settings, err := c.GetProjectSettingsByID(project.ProjectID)
	if err != nil {
		return err
	}
	project.Settings = &settings

	if project.SourceType != "local" {
		c.GetProjectRepository(project)
	}
	c.GetProjectSourceFilters(project)
	return nil
}

func (c SASTClient) GetProjectSettingsByID(projectid uint64) (ProjectSettings, error) {
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

	preset, err := c.GetPresetByID(settings.PresetID)
	if err != nil {
		return settings, fmt.Errorf("failed to get preset for project: %s", err)
	}
	settings.PresetName = preset.Name

	return settings, err
}

func (c SASTClient) GetProjectRepository(project *Project) error {
	response, err := c.get(fmt.Sprintf("/projects/%d/sourceCode/remoteSettings/%v", project.ProjectID, project.SourceType))
	if err != nil {
		c.logger.Errorf("Failed to get source code settings for project %v: %s", project.String(), err)
		return err
	}

	var pr ProjectRepo
	err = json.Unmarshal(response, &pr)
	if err != nil {
		return err
	}

	project.Repo = &pr
	return nil
}

func (c SASTClient) GetProjectSourceFilters(project *Project) error {
	response, err := c.get(fmt.Sprintf("/projects/%d/sourceCode/excludeSettings", project.ProjectID))

	if err != nil && err.Error() == "HTTP Response: 501 Not Implemented" {
		response, err = c.getV(fmt.Sprintf("/projects/%d/sourceCode/pathFilter", project.ProjectID), "5.0")
	}
	if err != nil {
		c.logger.Errorf("Failed to get source filters for project %v: %s", project.String(), err)
		return err
	}

	var filters SourceFilters
	err = json.Unmarshal(response, &filters)
	if err != nil {
		return err
	}

	project.Filters = &filters
	return nil
}

func (c SASTClient) ScanProjectByID(projectID uint64, isIncremental, isPublic, forceScan bool, comment string) (uint64, error) {
	var body struct {
		ProjectID     uint64 `json:"projectId"`
		IsIncremental bool   `json:"isIncremental"`
		IsPublic      bool   `json:"isPublic"`
		ForceScan     bool   `json:"forceScan"`
		Comment       string `json:"comment"`
	}

	body.ProjectID = projectID
	body.IsIncremental = isIncremental
	body.IsPublic = isPublic
	body.ForceScan = forceScan
	body.Comment = comment

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}

	response, err := c.sendRequest(http.MethodPost, "/sast/scans", bytes.NewReader(jsonBody), http.Header{})
	if err != nil {
		return 0, err
	}

	var res struct {
		ID uint64 `json:"id"`
	}
	err = json.Unmarshal(response, &res)

	return res.ID, err
}

func (c SASTClient) ScanProjectWithSettingsByID(settings *ScanSettings) (uint64, error) {
	c.logger.Debugf("Start scan with settings for projectID %d", settings.ProjectID)

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if settings.ZippedSource != nil {
		fw, err := w.CreateFormFile("zippedSource", "source.zip")
		if err != nil {
			return 0, err
		}
		length, err := fw.Write(*settings.ZippedSource)
		if err != nil {
			return 0, err
		}
		if length != len(*settings.ZippedSource) {
			c.logger.Warnf("Failed to write entire file to multipart form")
		}
	}

	//w.CreateFormField("projectId")
	w.WriteField("projectId", strconv.FormatUint(settings.ProjectID, 10))
	//w.CreateFormField("isIncremental")
	w.WriteField("isIncremental", strconv.FormatBool(settings.IsIncremental))
	//w.CreateFormField("forceScan")
	w.WriteField("forceScan", strconv.FormatBool(settings.ForceScan))
	//w.CreateFormField("overrideProjectSetting")
	w.WriteField("overrideProjectSetting", strconv.FormatBool(settings.OverrideProjectSetting))
	//w.CreateFormField("comment")
	w.WriteField("comment", settings.Comment)
	//w.CreateFormField("presetId")
	w.WriteField("presetId", strconv.FormatUint(settings.PresetID, 10))
	//w.CreateFormField("engineConfigurationId")
	w.WriteField("engineConfigurationId", strconv.FormatUint(settings.EngineConfigurationID, 10))

	w.Close()

	header := http.Header{}
	header.Add("Content-Type", w.FormDataContentType())
	response, err := c.sendRequest(http.MethodPost, "/sast/scanWithSettings", bytes.NewReader(b.Bytes()), header)
	if err != nil {
		c.logger.Debugf("Failed to start scan with settings: %s", err)
		c.logger.Debugf("Response: %v", string(response))
		return 0, fmt.Errorf("failure uploading attachment: %s", err)
	}

	var res struct {
		ID uint64 `json:"id"`
	}
	err = json.Unmarshal(response, &res)

	return res.ID, err
}

func (c SASTClient) UploadFileForProjectByID(projectID uint64, filename string) error {
	c.logger.Tracef("Attaching file %v to project %d", filename, projectID)

	fileContents, err := os.ReadFile(filename)
	if err != nil {
		c.logger.Tracef("Failed to Read the File %v: %s", filename, err)
		return err
	}

	return c.UploadBytesForProjectByID(projectID, &fileContents)
}

func (c SASTClient) UploadBytesForProjectByID(projectID uint64, fileContents *[]byte) error {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	fw, err := w.CreateFormFile("zippedSource", "source.zip")
	if err != nil {
		return err
	}

	length, err := fw.Write(*fileContents)
	if err != nil {
		return err
	}
	if length != len(*fileContents) {
		c.logger.Warnf("Failed to write entire file to multipart form")
	}

	w.Close()

	header := http.Header{}
	header.Add("Content-Type", w.FormDataContentType())
	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/projects/%d/sourceCode/attachments", projectID), bytes.NewReader(b.Bytes()), header)
	if err != nil {
		c.logger.Debugf("Failed to upload attachment: %s", err)
		c.logger.Debugf("Response: %v", string(response))
		return fmt.Errorf("failure uploading attachment: %s", err)
	}

	return nil
}

func (f SourceFilters) HasFilters() bool {
	return f.FilesPattern != "" || f.FoldersPattern != "" || f.PathPattern != ""
}

func (f SourceFilters) ToGlob() string {
	glob := []string{}

	if g := f.filesToGlob(); g != "" {
		glob = append(glob, g)
	}

	if g := f.foldersToGlob(); g != "" {
		glob = append(glob, g)
	}

	if f.PathPattern != "" {
		glob = append(glob, f.PathPattern)
	}

	return strings.Join(glob, ",")
}

func (f SourceFilters) filesToGlob() string {
	if f.FilesPattern == "" {
		return ""
	}

	globs := []string{}
	for _, filter := range strings.Split(f.FilesPattern, ",") {
		f := strings.TrimSpace(filter)
		if f[0:1] == "!" {
			globs = append(globs, strings.ReplaceAll(f[1:], "\\", "/"))
		} else {
			globs = append(globs, "!"+strings.ReplaceAll(f, "\\", "/"))
		}
	}

	if len(globs) > 0 {
		return strings.Join(globs, ",")
	} else {
		return ""
	}
}

func (f SourceFilters) foldersToGlob() string {
	if f.FoldersPattern == "" {
		return ""
	}

	globs := []string{}
	for _, filter := range strings.Split(f.FoldersPattern, ",") {
		f := strings.TrimSpace(filter)
		if f[0:1] == "!" {
			globs = append(globs, "**/"+strings.ReplaceAll(f[1:], "\\", "/")+"/**")
		} else {
			globs = append(globs, "!**/"+strings.ReplaceAll(f, "\\", "/")+"/**")
		}
	}

	if len(globs) > 0 {
		return strings.Join(globs, ",")
	} else {
		return ""
	}
}

/*
func (c SASTClient) GetProjectConfigurationSOAP(projectId uint64) error {
	c.logger.Debug("Get SAST Scan Preset SOAP")
	response, err := c.sendSOAPRequest("GetProjectConfiguration", fmt.Sprintf("<sessionID></sessionID><projectID>%d</projectID>", projectId))
	if err != nil {
		return err
	}

	c.logger.Infof("Returned: %s", string(response))

	return nil
} */

// this type is used temporarily to convert into the 'simpler' format defined in types.go
type ProjectComplex struct {
	ProjectID          uint64 `json:"id"`
	TeamID             uint64
	Name               string
	IsPublic           bool
	SourceSettingsLink struct {
		Type string
		Rel  string
		Uri  string
	}
	CustomFields []ProjectCustomField
	Links        []map[string]string
}

func (pp ProjectComplex) ToProject() Project {
	var p Project
	p.ProjectID = pp.ProjectID
	p.TeamID = pp.TeamID
	p.Name = pp.Name
	p.IsPublic = pp.IsPublic

	for _, l := range pp.Links {
		if l["rel"] == "source" {
			p.SourceType = l["type"]
		}
	}

	if p.SourceType == "" {
		p.SourceType = pp.SourceSettingsLink.Type
	}

	p.CustomFields = pp.CustomFields

	return p
}

func ConvertProjects(pps *[]ProjectComplex) []Project {
	var projects []Project

	for _, p := range *pps {
		projects = append(projects, p.ToProject())
	}
	return projects
}

// Links to objects in the portal
func (c SASTClient) ProjectLink(p *Project) string {
	return fmt.Sprintf("%v/CxWebClient/ProjectScans.aspx?id=%d", c.baseUrl, p.ProjectID)
}
