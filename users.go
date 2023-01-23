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
}

func (c *SASTClient) UserLink(u *User) string {
	return fmt.Sprintf("%v/CxRestAPI/auth/#/users?id=%d", c.baseUrl, u.UserID) // this link doesn't actually work, just takes you to the main page
}
