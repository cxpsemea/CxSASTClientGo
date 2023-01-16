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

        if err != nil {
            client.logger.Errorf( "Failed while retrieving projects: %s", err )
        } else {
            if len( c.Projects ) > 0 {
                for id, p := range c.Projects {
                    settings, err := client.GetProjectSettings( p.ProjectID )
                    if err != nil {
                        client.logger.Warnf( "Failed while retrieving project settings for project %d: %s", p.ProjectID, err )
                    } else {
                        c.Projects[id].Settings = &settings
                    }
                }
            }
        }
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
    if !c.QueryRefresh {
        c.QueryRefresh = true
        c.QueryGroups, c.Queries, err = client.GetQueriesSOAP()
        c.QueryRefresh = false
    }
    return err
}

func (c *SASTCache) RefreshPresets( client *SASTClient ) error {
    var err error
    if !c.PresetRefresh {
        c.PresetRefresh = true
        c.Presets, err = client.GetPresets()
        if err != nil {
            client.logger.Errorf( "Failed while retrieving presets: %s", err )
        } else {
            if len( c.Queries ) > 0 {
                for id, _ := range c.Presets {
                    err := client.GetPresetContents( &c.Presets[id], &c.Queries )
                    if err != nil {
                        client.logger.Errorf( "Failed to retrieve preset contents for preset %v: %s", c.Presets[id].String(), err )
                    }
                }
            }
        }
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

    if client.soapToken != "" {
        err = c.RefreshQueries(client)
        if err != nil { return err }
    }

    err = c.RefreshPresets(client)
    if err != nil { return err }

    err = c.RefreshRoles(client)
    if err != nil { return err }

    c.matchTeamProjects()

    return nil
}





func (c *SASTCache) GetTeam( teamID uint64 ) (*Team, error) {
    for id, t := range c.Teams {
        if t.TeamID == teamID {
            return &c.Teams[id], nil
        }
    }
    return nil, errors.New( "No such team" )
}
func (c *SASTCache) GetTeamByName( name string ) (*Team, error) {
    for id, t := range c.Teams {
        if t.Name == name {
            return &c.Teams[id], nil
        }
    }
    return nil, errors.New( "No such team" )
}

func (c *SASTCache) GetUser( userID uint64 ) (*User, error) {
    for id, g := range c.Users {
        if g.UserID == userID {
            return &c.Users[id], nil
        }
    }
    return nil, errors.New( "No such user" )
}
func (c *SASTCache) GetUserByEmail( email string ) (*User, error) {
    for id, g := range c.Users {
        if g.Email == email {
            return &c.Users[id], nil
        }
    }
    return nil, errors.New( "No such user" )
}

func (c *SASTCache) GetProject( projectID uint64 ) (*Project, error) {
    for id, g := range c.Projects {
        if g.ProjectID == projectID {
            return &c.Projects[id], nil
        }
    }
    return nil, errors.New( "No such project" )
}
func (c *SASTCache) GetProjectByName( name string ) (*Project, error) {
    for id, g := range c.Projects {
        if g.Name == name {
            return &c.Projects[id], nil
        }
    }
    return nil, errors.New( "No such project" )
}

func (c *SASTCache) GetPreset( presetID uint64 ) (*Preset, error) {
    for id, g := range c.Presets {
        if g.PresetID == presetID {
            return &c.Presets[id], nil
        }
    }
    return nil, errors.New( "No such preset" )
}
func (c *SASTCache) GetPresetByName( name string ) (*Preset, error) {
    for id, g := range c.Presets {
        if g.Name == name {
            return &c.Presets[id], nil
        }
    }
    return nil, errors.New( "No such preset" )
}

func (c *SASTCache) GetRole( roleID uint64 ) (*Role, error) {
    for id, g := range c.Roles {
        if g.RoleID == roleID {
            return &c.Roles[id], nil
        }
    }
    return nil, errors.New( "No such role" )
}
func (c *SASTCache) GetRoleByName( name string ) (*Role, error) {
    for id, g := range c.Roles {
        if g.Name == name {
            return &c.Roles[id], nil
        }
    }
    return nil, errors.New( "No such role" )
}

func (c *SASTCache) GetQuery( queryID uint64 ) (*Query, error) {
    for id, g := range c.Queries {
        if g.QueryID == queryID {
            return &c.Queries[id], nil
        }
    }
    return nil, errors.New( "No such query" )
}
func (c *SASTCache) GetQueryByNames( language, group, query string ) (*Query, error) {
    /*for _, g := range c.Queries {
        if g.QueryID == queryID {
            return g, nil
        }
    }
    return nil, errors.New( "No such query" )*/
    return nil, errors.New( "Not implemented" )
}