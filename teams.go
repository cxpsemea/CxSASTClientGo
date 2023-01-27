package CxSASTClientGo

import (
	"encoding/json"
	"fmt"
)

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

func (c *SASTClient) GetTeamByID(teamId uint64) (Team, error) {
	c.logger.Debugf("Get SAST Team with ID %d", teamId)
	var team Team
	response, err := c.get(fmt.Sprintf("/auth/teams/%d", teamId))
	if err != nil {
		return team, err
	}

	err = json.Unmarshal(response, &team)
	return team, err
}

func (c *SASTClient) TeamLink(t *Team) string {
	return fmt.Sprintf("%v/CxRestAPI/auth/#/teams/id=%d", c.baseUrl, t.TeamID) // this link doesn't actually work, just takes you to the main page
}
