package CxSASTClientGo

import (
	"encoding/json"
	"fmt"
)

func (p *Project) String() string {
	return fmt.Sprintf("[%d] %v", p.ProjectID, p.Name)
}

func (pr *ProjectRepo) String() string {
	return fmt.Sprintf("%v - branch %v", pr.URL, pr.Branch)
}

func (c *SASTClient) GetProject(id uint64) (Project, error) {
	c.logger.Tracef("Get SAST Project with ID %d", id)
	var project Project

	response, err := c.get(fmt.Sprintf("/projects/%d", id))
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

func (c *SASTClient) GetProjects() ([]Project, error) {
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

func (c *SASTClient) GetProjectsInTeam(teamid uint64) ([]Project, error) {
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

func (c *SASTClient) GetProjectRepository(project *Project) error {
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

/*
func (c *SASTClient) GetProjectConfigurationSOAP(projectId uint64) error {
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
	ProjectID uint64 `json:"id"`
	TeamID    uint64
	Name      string
	IsPublic  bool
	Links     []map[string]string
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
func (c *SASTClient) ProjectLink(p *Project) string {
	return fmt.Sprintf("%v/CxWebClient/ProjectScans.aspx?id=%d", c.baseUrl, p.ProjectID)
}
