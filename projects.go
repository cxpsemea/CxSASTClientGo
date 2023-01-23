package CxSASTClientGo

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

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

// Links to objects in the portal
func (c *SASTClient) ProjectLink(p *Project) string {
	return fmt.Sprintf("%v/CxWebClient/ProjectScans.aspx?id=%d", c.baseUrl, p.ProjectID)
}
