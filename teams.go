package CxSASTClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func (t Team) HasProjects() bool {
	return len(t.Projects) > 0
}
func (t Team) HasUsers() bool {
	return len(t.Users) > 0
}
func (t Team) HasInheritedUsers() bool {
	return len(t.InheritedUsers) > 0
}

// Teams
func (t *Team) String() string {
	return fmt.Sprintf("[%d] %v", t.TeamID, t.Name)
}

func (c SASTClient) GetTeams() ([]Team, error) {
	c.logger.Debug("Get SAST Teams")
	var teams []Team
	response, err := c.get("/auth/teams")
	if err != nil {
		return teams, err
	}

	err = json.Unmarshal(response, &teams)
	return teams, err
}

func (c SASTClient) GetTeamByID(teamId uint64) (Team, error) {
	c.logger.Debugf("Get SAST Team with ID %d", teamId)
	var team Team
	response, err := c.get(fmt.Sprintf("/auth/teams/%d", teamId))
	if err != nil {
		return team, err
	}

	err = json.Unmarshal(response, &team)
	return team, err
}

func (c SASTClient) CreateTeam(name string, parentId uint64) (uint64, error) {
	var newTeam uint64
	body := map[string]interface{}{
		"name":     name,
		"parentId": parentId,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return newTeam, err
	}

	response, err := c.sendRequest(http.MethodPost, "/auth/teams", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return newTeam, err
	}

	err = json.Unmarshal(response, &newTeam)
	return newTeam, err
}

func (c SASTClient) DeleteTeam(teamId uint64) error {
	c.depwarn("DeleteTeam", "DeleteTeamByID")
	return c.DeleteTeamByID(teamId)
}

func (c SASTClient) DeleteTeamByID(teamId uint64) error {
	response, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/auth/teams/%d", teamId), nil, nil)
	if err != nil {
		return err
	}
	if response != nil && string(response) != "" {
		c.logger.Warningf("Deleted team but back-end replied: %v", string(response))
	}
	return nil
}

func (c SASTClient) TeamLink(t *Team) string {
	return fmt.Sprintf("%v/CxRestAPI/auth/#/teams/id=%d", c.baseUrl, t.TeamID) // this link doesn't actually work, just takes you to the main page
}

func (c SASTClient) GetTeamHierarchy(teamId uint64, teamMap *map[uint64]*Team) []*Team {
	hierarchy := []*Team{}

	team, ok := (*teamMap)[teamId]
	if !ok {
		return hierarchy
	}

	hierarchy = append(hierarchy, team)

	for team, ok := (*teamMap)[team.ParentID]; ok && team != nil; team, ok = (*teamMap)[team.ParentID] {
		hierarchy = append(hierarchy, team)
	}

	return hierarchy
}
