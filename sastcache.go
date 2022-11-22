package CxSASTClientGo

import (
    "strconv"
)





type SASTCache struct {
    Projects []Project
	Teams []Team
	Users []User
	Queries []Query
	QueryGroups []QueryGroup // caching - to reconsider if needed
	Presets []Preset
}



func (c *SASTCache) matchTeamProjects() {
	for index := range c.Teams {
		for _, project := range c.Projects {
			if c.Teams[index].TeamID == project.TeamID {
				c.Teams[index].Projects = append( c.Teams[index].Projects, project )
			}
		}
	}
}

func (c *SASTCache) Refresh( client *SASTClient ) error {
    var err error
    c.Projects, err = client.GetProjects()
    if err != nil {
        return err
    }

    c.Teams, err = client.GetTeams()
    if err != nil {
        return err
    }

    c.Users, err = client.GetUsers()
    if err != nil {
        return err
    }

    c.Presets, err = client.GetPresets()
    if err != nil {
        return err
    }

    c.matchTeamProjects()

    return nil
}

func (c *SASTCache) PresetSummary() string {

	return strconv.Itoa( len( c.Presets ) ) + " presets"
}
func (c *SASTCache) QuerySummary() string {
	
	return strconv.Itoa( len( c.Queries ) ) + " queries  in " + strconv.Itoa( len( c.QueryGroups ) ) + " groups"
}
func (c *SASTCache) UserSummary() string {
	
	return strconv.Itoa( len( c.Users ) ) + " users"
}
func (c *SASTCache) TeamSummary() string {
	
	return strconv.Itoa( len( c.Teams ) ) + " teams"
}
func (c *SASTCache) TeamTree() string {
    return ""
}
func (c *SASTCache) ProjectSummary() string {
	
	return strconv.Itoa( len( c.Projects ) ) + " projects"
} 