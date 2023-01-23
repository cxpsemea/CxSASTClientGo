package CxSASTClientGo

import (
	"encoding/json"
	"fmt"
)

// Users
func (u *User) String() string {
	return fmt.Sprintf("[%d] %v %v (%v)", u.UserID, u.FirstName, u.LastName, u.Email)
}

func (c *SASTClient) GetUsers() ([]User, error) {
	c.logger.Debug("Get SAST Users")
	var users []User
	response, err := c.get("/auth/users")
	if err != nil {
		return users, err
	}

	err = json.Unmarshal(response, &users)
	return users, err
}

func (c *SASTClient) GetCurrentUser() (User, error) {
	c.logger.Trace("Get SAST User Info")
	var user User
	response, err := c.get("/auth/MyProfile")
	if err != nil {
		return user, err
	}

	err = json.Unmarshal(response, &user)
	return user, err
	//c.logger.Warning( "Parsing input: " + strig(response) )
	/*
			if err == nil {
				return User {
					uint64(jsonBody["id"].(float64)),
					jsonBody["firstName"].(string),
					jsonBody["lastName"].(string),
		            jsonBody["userName"].(string),

				}, nil
			} else {
				c.logger.Error( "Login failed: " + err.Error() )
		        c.logger.Warning( "Failed while parsing response: " + string(response) )
		        return User{}, err
			}*/
}

func (c *SASTClient) UserLink(u *User) string {
	return fmt.Sprintf("%v/CxRestAPI/auth/#/users?id=%d", c.baseUrl, u.UserID) // this link doesn't actually work, just takes you to the main page
}
