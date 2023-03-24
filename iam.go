package CxSASTClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

func (c SASTClient) GetAuthenticationProviders() ([]AuthenticationProvider, error) {
	c.logger.Trace("Fetching authentication providers")

	var providers []AuthenticationProvider

	response, err := c.get("/auth/AuthenticationProviders")

	if err != nil {
		c.logger.Errorf("Failed to get authentication providers: %s", err)
		return providers, err
	}

	err = json.Unmarshal(response, &providers)
	if err != nil {
		c.logger.Errorf("Failed to unmarshal response: %s", err)
		c.logger.Tracef("Response was: %v", string(response))
		return providers, err
	}

	return providers, err
}

func (c SASTClient) GetOIDCClients() ([]OIDCClient, error) {
	c.logger.Trace("Fetching OIDC Clients")

	var clients []OIDCClient

	response, err := c.get("/auth/OIDCClients")

	if err != nil {
		c.logger.Errorf("Failed to get OIDC Clients: %s", err)
		return clients, err
	}

	err = json.Unmarshal(response, &clients)
	if err != nil {
		c.logger.Errorf("Failed to unmarshal response: %s", err)
		c.logger.Tracef("Response was: %v", string(response))
		return clients, err
	}

	return clients, err
}

// convenience
func (c SASTClient) GetOIDCClientByID(clientId string) (OIDCClient, error) {
	c.logger.Tracef("Fetching OIDC Client with clientId %v", clientId)

	clients, err := c.GetOIDCClients()

	if err != nil {
		c.logger.Errorf("Failed to get OIDC Clients: %s", err)
		return OIDCClient{}, err
	}

	for _, c := range clients {
		if c.ClientID == clientId {
			return c, nil
		}
	}

	return OIDCClient{}, errors.New("No such client found")
}

func (c SASTClient) SaveOIDCClient(client *OIDCClient) error {
	c.logger.Tracef("Updating OIDC Client %v", client.ClientID)

	jsonBody, err := json.Marshal(*client)

	if err != nil {
		c.logger.Errorf("Failed to marshal data for OIDC client: %s", err)
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/auth/OIDCClients/%d", client.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Errorf("Failed to update OIDC Client: %s", err)
		return err
	}

	return nil
}

func (c SASTClient) CreateOIDCClient(client *OIDCClient) error {
	c.logger.Tracef("Creating OIDC Client %v", client.ClientID)

	jsonBody, err := json.Marshal(*client)

	if err != nil {
		c.logger.Errorf("Failed to marshal data for OIDC client: %s", err)
		return err
	}

	_, err = c.sendRequest(http.MethodPost, "/auth/OIDCClients", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Errorf("Failed to update OIDC Client: %s", err)
		return err
	}

	return nil
}

func (c SASTClient) DeleteOIDCClient(client *OIDCClient) error {
	c.logger.Tracef("Creating OIDC Client %v", client.ClientID)

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/auth/OIDCClients/%d", client.ID), nil, nil)
	if err != nil {
		c.logger.Errorf("Failed to delete OIDC Client: %s", err)
		return err
	}

	return nil
}
