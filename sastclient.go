package CxSASTClientGo

import (
	"bytes"
	"fmt"
	"io"

	//"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (c *SASTClient) createRequest(method, url string, body io.Reader, header *http.Header, cookies []*http.Cookie) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}

	for name, headers := range *header {
		for _, h := range headers {
			request.Header.Add(name, h)
		}
	}

	//if request.Header.Get("Authorization") == "" {
	//	request.Header.Set("Authorization", "Bearer "+c.authToken)
	//}

	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0")
	}

	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

	return request, nil
}

func (c *SASTClient) sendRequestInternal(client *http.Client, method, url string, body io.Reader, header http.Header) ([]byte, error) {
	var bodyBytes []byte
	c.logger.Debugf("Sending request to URL %v", url)
	if body != nil {
		closer := io.NopCloser(body)
		bodyBytes, _ = io.ReadAll(closer)
		defer closer.Close()
	}

	request, err := c.createRequest(method, url, bytes.NewReader(bodyBytes), &header, nil)
	if err != nil {
		c.logger.Errorf("Unable to create request: %s", err)
		return []byte{}, err
	}

	response, err := client.Do(request)
	if err != nil {
		c.logger.Errorf("HTTP request failed with error: %s", err)
		var resBody []byte

		if response != nil && response.Body != nil {
			resBody, _ = io.ReadAll(response.Body)
		}
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)

		return resBody, err
	}
	if response.StatusCode >= 400 {
		var resBody []byte
		if response != nil && response.Body != nil {
			resBody, _ = io.ReadAll(response.Body)
		}
		c.recordRequestDetailsInErrorCase(bodyBytes, resBody)
		c.logger.Errorf("HTTP response indicates error: %v", response.Status)
		return resBody, errors.New("HTTP Response: " + response.Status)
	}
	defer response.Body.Close()

	resBody, err := io.ReadAll(response.Body)

	if err != nil {
		if err.Error() == "remote error: tls: user canceled" {
			c.logger.Warnf("HTTP request encountered error: %s", err)
		} else {
			c.logger.Errorf("Error reading response body: %s", err)
		}
		c.logger.Tracef("Parsed: %v", string(resBody))
	}

	return resBody, nil
}

func (c *SASTClient) sendRequest(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	sasturl := fmt.Sprintf("%v/cxrestapi%v", c.baseUrl, url)
	return c.sendRequestInternal(c.restClient, method, sasturl, body, header)
}

func (c *SASTClient) sendSOAPRequest(method string, body string) ([]byte, error) {
	if c.soapClient == nil {
		return []byte{}, errors.New("No SOAP client initialized")
	}

	sasturl := fmt.Sprintf("%v/CxWebInterface/Portal/CxWebService.asmx", c.baseUrl)
	header := http.Header{}
	SOAPEnvOpen := "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>"
	SOAPEnvClose := "</soap:Body></soap:Envelope>"

	header.Set("Content-Type", "text/xml; charset=utf-8")
	header.Set("SOAPAction", fmt.Sprintf("%v/%v", "http://Checkmarx.com", method))
	//header.Set("Authorization", "Bearer "+c.soapToken)

	soap_msg := fmt.Sprintf("%v<%v xmlns=\"http://Checkmarx.com\">%v</%v>%v", SOAPEnvOpen, method, body, method, SOAPEnvClose)
	return c.sendRequestInternal(c.soapClient, http.MethodPost, sasturl, strings.NewReader(soap_msg), header)
}

func (c *SASTClient) recordRequestDetailsInErrorCase(requestBody []byte, responseBody []byte) {
	if len(requestBody) != 0 {
		c.logger.Errorf("Request body: %s", string(requestBody))
	}
	if len(responseBody) != 0 {
		c.logger.Errorf("Response body: %s", string(responseBody))
	}
}

// convenience function
func (c *SASTClient) getV(api string, version string) ([]byte, error) {
	header := http.Header{}
	header.Add("Accept", "application/json;version="+version)

	return c.sendRequest(http.MethodGet, api, nil, header)
}

func (c *SASTClient) get(api string) ([]byte, error) {
	return c.getV(api, "1.0")
}

func (s *Scan) String() string {
	return fmt.Sprintf("Scan ID: %d, Project ID: %d, Status: %v, Time: %v", s.ScanID, s.Project.ID, s.Status, s.FinishTime.Format(time.RFC3339))
}

func (c *SASTClient) String() string {
	return c.baseUrl // + " with token: " + ShortenGUID(c.authToken)
}

func ShortenGUID(guid string) string {
	return fmt.Sprintf("%v..%v", guid[:2], guid[len(guid)-2:])
}

// If you want to provide your own authenticated HTTP Client (prepared through OAuth2 library) you can use this instead.
// this is useful if you are using SAST authentication on a third-party website with authorization_code style oauth
// oauth authorization_code helper function are implemented in sastpassclient.go
func New(client *http.Client, soap_client *http.Client, base_url string, logger *logrus.Logger) *SASTClient {

	cli := &SASTClient{client, soap_client, base_url, logger, nil}

	user, err := cli.GetCurrentUser()
	if err != nil {
		logger.Fatalf("Error while fetching current user information: %s", err)
		return nil
	}

	cli.CurrentUser = &user

	//	cli.RefreshCache()
	return cli
}

// NewTokenClient will authenticate with SAST using the standard OIDC clients included in the platform
func NewTokenClient(client *http.Client, base_url string, username string, password string, logger *logrus.Logger) (*SASTClient, error) {
	// implemented in sastpassclient.go
	rest_client := OauthCredentialClient(client, base_url, "resource_owner_client", "014DF517-39D1-4453-B7B3-9930C563627C", username, password, []string{"sast_rest_api", "access_control_api"})
	if rest_client == nil {
		return nil, errors.New("Unable to initialize CxREST API client")
	}
	soap_client := OauthCredentialClient(client, base_url, "resource_owner_sast_client", "014DF517-39D1-4453-B7B3-9930C563627C", username, password, []string{"sast_api", "offline_access"})
	if soap_client == nil {
		return nil, errors.New("Unable to initialize CxSOAP API client")
	}

	cli := New(rest_client, soap_client, base_url, logger)
	if cli == nil {
		return nil, errors.New("Unable to create client.")
	}
	return cli, nil
}
