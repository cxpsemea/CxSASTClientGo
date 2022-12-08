package CxSASTClientGo

import (
    "strconv"
    "github.com/pkg/errors"
)





type SASTCache struct {
    ProjectRefresh bool
    Projects []Project
    TeamRefresh bool
	Teams []Team
    UserRefresh bool
	Users []User
    QueryRefresh bool
	Queries []Query
	QueryGroupRefresh bool
    QueryGroups []QueryGroup // caching - to reconsider if needed
    PresetRefresh bool
	Presets []Preset
    RoleRefresh bool
    Roles []Role
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



func (c *SASTCache) RefreshProjects( client *SASTClient ) error {
    var err error
    if !c.ProjectRefresh {
        c.ProjectRefresh = true
        c.Projects, err = client.GetProjects()
        c.ProjectRefresh = false
    }
    return err
}

func (c *SASTCache) RefreshTeams( client *SASTClient ) error {
    var err error
    if !c.TeamRefresh {
        c.TeamRefresh = true
        c.Teams, err = client.GetTeams()
        c.TeamRefresh = false
    }
    return err
}

func (c *SASTCache) RefreshUsers( client *SASTClient ) error {
    var err error
    if !c.UserRefresh {
        c.UserRefresh = true
        c.Users, err = client.GetUsers()
        c.UserRefresh = false
    }
    return err
}

func (c *SASTCache) RefreshQueries( client *SASTClient ) error {
    var err error
    /*
    // todo - db or soap
    if !c.QueryRefresh {
        c.QueryRefresh = true
        c.Queries, err = client.GetQueries()
        c.QueryRefresh = false
    }*/
    return err
}

func (c *SASTCache) RefreshPresets( client *SASTClient ) error {
    var err error
    if !c.PresetRefresh {
        c.PresetRefresh = true
        c.Presets, err = client.GetPresets()
        c.PresetRefresh = false
    }
    return err
}

func (c *SASTCache) RefreshRoles( client *SASTClient ) error {
    var err error
    if !c.RoleRefresh {
        c.RoleRefresh = true
        c.Roles, err = client.GetRoles()
        c.RoleRefresh = false
    }
    return err
}




func (c *SASTCache) Refresh( client *SASTClient ) error {
    var err error

    err = c.RefreshProjects(client)
    if err != nil { return err }
    
    err = c.RefreshTeams(client)
    if err != nil { return err }

    err = c.RefreshUsers(client)
    if err != nil { return err }

    err = c.RefreshQueries(client)
    if err != nil { return err }

    err = c.RefreshPresets(client)
    if err != nil { return err }

    err = c.RefreshRoles(client)
    if err != nil { return err }

    c.matchTeamProjects()

    return nil
}





func (c *SASTCache) GetTeam( teamID uint64 ) (Team, error) {
    for _, t := range c.Teams {
        if t.TeamID == teamID {
            return t, nil
        }
    }
    return Team{}, errors.New( "No such team" )
}

func (c *SASTCache) GetUser( userID uint64 ) (User, error) {
    for _, g := range c.Users {
        if g.UserID == userID {
            return g, nil
        }
    }
    return User{}, errors.New( "No such user" )
}

func (c *SASTCache) GetProject( projectID uint64 ) (Project, error) {
    for _, g := range c.Projects {
        if g.ProjectID == projectID {
            return g, nil
        }
    }
    return Project{}, errors.New( "No such project" )
}

func (c *SASTCache) GetPreset( presetID uint64 ) (Preset, error) {
    for _, g := range c.Presets {
        if g.PresetID == presetID {
            return g, nil
        }
    }
    return Preset{}, errors.New( "No such preset" )
}

func (c *SASTCache) GetRole( roleID uint64 ) (Role, error) {
    for _, g := range c.Roles {
        if g.RoleID == roleID {
            return g, nil
        }
    }
    return Role{}, errors.New( "No such role" )
}