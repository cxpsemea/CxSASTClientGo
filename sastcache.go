package CxSASTClientGo

import (
	"fmt"
	"strconv"

	"github.com/pkg/errors"
)

type SASTCache struct {
	Projects []Project
	Teams    []Team
	Users    []User
	Queries  QueryCollection
	Presets  []Preset
	Roles    []Role
}

func (c *SASTCache) String() string {
	return fmt.Sprintf("%d Projects, %d Teams, %d Users, %d QueryLanguages, %d Presets, %d Roles", len(c.Projects), len(c.Teams), len(c.Users), len(c.Queries.QueryLanguages), len(c.Presets), len(c.Roles))
}

func (c *SASTCache) matchTeamProjects() {
	for index := range c.Teams {
		for _, project := range c.Projects {
			if c.Teams[index].TeamID == project.TeamID {
				c.Teams[index].Projects = append(c.Teams[index].Projects, project)
			}
		}
	}
}

func (c *SASTCache) PresetSummary() string {

	return strconv.Itoa(len(c.Presets)) + " presets"
}
func (c *SASTCache) QuerySummary() string {

	return fmt.Sprintf("%dquery languages", len(c.Queries.QueryLanguages))
}
func (c *SASTCache) UserSummary() string {

	return strconv.Itoa(len(c.Users)) + " users"
}
func (c *SASTCache) TeamSummary() string {

	return strconv.Itoa(len(c.Teams)) + " teams"
}
func (c *SASTCache) TeamTree() string {
	return ""
}
func (c *SASTCache) ProjectSummary() string {

	return strconv.Itoa(len(c.Projects)) + " projects"
}

func (c *SASTCache) RefreshProjects(client *SASTClient) error {
	var err error
	c.Projects, err = client.GetProjects()

	if err != nil {
		client.logger.Errorf("Failed while retrieving projects: %s", err)
		return fmt.Errorf("failed to retrieve presets: %s", err)
	} else {
		if len(c.Projects) > 0 {
			for id, p := range c.Projects {
				err := client.GetProjectSettings(&(c.Projects[id]))
				if err != nil {
					client.logger.Warnf("Failed while retrieving project settings for project %d: %s", p.ProjectID, err)
				}
			}
		}
	}

	return nil
}

func (c *SASTCache) RefreshTeams(client *SASTClient) error {
	var err error
	c.Teams, err = client.GetTeams()
	if err != nil {
		return fmt.Errorf("failed to retrieve teams: %s", err)
	}
	return nil
}

func (c *SASTCache) RefreshUsers(client *SASTClient) error {
	var err error
	c.Users, err = client.GetUsers()
	if err != nil {
		return fmt.Errorf("failed to retrieve users: %s", err)
	}
	return nil
}

func (c *SASTCache) RefreshQueries(client *SASTClient) error {
	_, soap := client.ClientsValid()
	var err error
	if soap {
		c.Queries, err = client.GetQueriesSOAP()
	}
	if err != nil {
		return fmt.Errorf("failed to retrieve queries: %s", err)
	}
	return nil
}

func (c *SASTCache) RefreshPresets(client *SASTClient) error {
	var err error
	c.Presets, err = client.GetPresets()
	if err != nil {
		client.logger.Errorf("Failed while retrieving presets: %s", err)
		return fmt.Errorf("failed to retrieve presets: %s", err)
	} else {
		if len(c.Queries.QueryLanguages) > 0 {
			for id := range c.Presets {
				err := client.GetPresetContents(&c.Presets[id], &c.Queries)
				if err != nil {
					client.logger.Errorf("Failed to retrieve preset contents for preset %v: %s", c.Presets[id].String(), err)
				}
			}
		}
	}
	return nil
}

func (c *SASTCache) RefreshRoles(client *SASTClient) error {
	var err error
	c.Roles, err = client.GetRoles()
	if err != nil {
		return fmt.Errorf("failed to retrieve presets: %s", err)
	}
	return nil
}

func (c *SASTCache) Refresh(client *SASTClient) []error {
	var errors []error
	var err error

	err = c.RefreshProjects(client)
	if err != nil {
		errors = append(errors, err)
	}

	err = c.RefreshTeams(client)
	if err != nil {
		errors = append(errors, err)
	}

	err = c.RefreshUsers(client)
	if err != nil {
		errors = append(errors, err)
	}

	//if client.soapToken != "" {
	err = c.RefreshQueries(client)
	if err != nil {
		errors = append(errors, err)
	}
	//}

	err = c.RefreshPresets(client)
	if err != nil {
		errors = append(errors, err)
	}

	err = c.RefreshRoles(client)
	if err != nil {
		errors = append(errors, err)
	}

	c.matchTeamProjects()

	return errors
}

func (c *SASTCache) GetTeam(teamID uint64) (*Team, error) {
	for id, t := range c.Teams {
		if t.TeamID == teamID {
			return &c.Teams[id], nil
		}
	}
	return nil, errors.New("No such team")
}
func (c *SASTCache) GetTeamByName(name string) (*Team, error) {
	for id, t := range c.Teams {
		if t.Name == name {
			return &c.Teams[id], nil
		}
	}
	return nil, errors.New("No such team")
}
func (c *SASTCache) GetTeamsByParentID(parentID uint64) []*Team {
	children := make([]*Team, 0)
	for id, t := range c.Teams {
		if t.ParentID == parentID {
			children = append(children, &(c.Teams[id]))
		}
	}
	return children
}

func (c *SASTCache) GetUser(userID uint64) (*User, error) {
	for id, g := range c.Users {
		if g.UserID == userID {
			return &c.Users[id], nil
		}
	}
	return nil, errors.New("No such user")
}
func (c *SASTCache) GetUserByEmail(email string) (*User, error) {
	for id, g := range c.Users {
		if g.Email == email {
			return &c.Users[id], nil
		}
	}
	return nil, errors.New("No such user")
}
func (c *SASTCache) GetUsersInTeam(teamID uint64) []*User {
	users := make([]*User, 0)

	for id, u := range c.Users {
		for _, tid := range u.TeamIDs {
			if tid == teamID {
				users = append(users, &c.Users[id])
			}
		}
	}

	return users
}

func (c *SASTCache) GetUsersInTeams(teams []Team) []*User {
	users := make([]*User, 0)

	for id, u := range c.Users {
		matched := false
		for _, tid := range u.TeamIDs {
			for _, teamID := range teams {
				if tid == teamID.TeamID && !matched {
					users = append(users, &c.Users[id])
					matched = true
				}
			}
		}
	}

	return users
}

func (c *SASTCache) GetProject(projectID uint64) (*Project, error) {
	for id, g := range c.Projects {
		if g.ProjectID == projectID {
			return &c.Projects[id], nil
		}
	}
	return nil, errors.New("No such project")
}
func (c *SASTCache) GetProjectByName(name string) (*Project, error) {
	for id, g := range c.Projects {
		if g.Name == name {
			return &c.Projects[id], nil
		}
	}
	return nil, errors.New("No such project")
}
func (c *SASTCache) GetProjectsByTeamID(teamID uint64) []*Project {
	projects := make([]*Project, 0)
	for id, p := range c.Projects {
		if p.TeamID == teamID {
			projects = append(projects, &(c.Projects[id]))
		}
	}
	return projects
}

func (c *SASTCache) GetPreset(presetID uint64) (*Preset, error) {
	for id, g := range c.Presets {
		if g.PresetID == presetID {
			return &c.Presets[id], nil
		}
	}
	return nil, errors.New("No such preset")
}
func (c *SASTCache) GetPresetByName(name string) (*Preset, error) {
	for id, g := range c.Presets {
		if g.Name == name {
			return &c.Presets[id], nil
		}
	}
	return nil, errors.New("No such preset")
}

func (c *SASTCache) GetRole(roleID uint64) (*Role, error) {
	for id, g := range c.Roles {
		if g.RoleID == roleID {
			return &c.Roles[id], nil
		}
	}
	return nil, errors.New("No such role")
}
func (c *SASTCache) GetRoleByName(name string) (*Role, error) {
	for id, g := range c.Roles {
		if g.Name == name {
			return &c.Roles[id], nil
		}
	}
	return nil, errors.New("No such role")
}

func (c *SASTCache) GetQuery(queryID uint64) (*Query, error) {
	q := c.Queries.GetQueryByID(queryID)
	if q != nil {
		return q, nil
	}
	return nil, errors.New("No such query")
}
func (c *SASTCache) GetQueryByNames(language, group, query string) (*Query, error) {
	/*for _, g := range c.Queries {
	      if g.QueryID == queryID {
	          return g, nil
	      }
	  }
	  return nil, errors.New( "No such query" )*/
	return nil, errors.New("Not implemented")
}
