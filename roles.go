package CxSASTClientGo

import (
	"encoding/json"
	"fmt"
)

// Roles
func (r *Role) String() string {
	return fmt.Sprintf("[%d] %v", r.RoleID, r.Name)
}

func (c *SASTClient) GetRoles() ([]Role, error) {
	c.logger.Debug("Get SAST Roles")
	var roles []Role
	response, err := c.get("/auth/roles")
	if err != nil {
		return roles, err
	}

	err = json.Unmarshal(response, &roles)
	return roles, err
}

func (c *SASTClient) RoleLink(r *Role) string {
	return fmt.Sprintf("%v/CxRestAPI/auth/#/roles/%d", c.baseUrl, r.RoleID)
}
