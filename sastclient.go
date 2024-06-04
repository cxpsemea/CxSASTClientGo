package CxSASTClientGo

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	//"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

func (c SASTClient) createRequest(method, url string, body io.Reader, header *http.Header, cookies []*http.Cookie) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}

	for name, headers := range *header {
		for _, h := range headers {
			request.Header.Add(name, h)
		}
	}

	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0")
	}

	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}

	return request, nil
}

func (c SASTClient) sendRequestInternal(client *http.Client, method, url string, body io.Reader, header http.Header) ([]byte, error) {
	var bodyBytes []byte
	c.logger.Tracef("Sending %v request to URL %v", method, url)
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
		//c.logger.Errorf("HTTP response indicates error: %v", response.Status)
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

func (c SASTClient) sendRequest(method, url string, body io.Reader, header http.Header) ([]byte, error) {
	sasturl := fmt.Sprintf("%v/cxrestapi%v", c.baseUrl, url)
	return c.sendRequestInternal(c.restClient, method, sasturl, body, header)
}

func (c SASTClient) sendSOAPRequest(method string, body string) ([]byte, error) {
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

func (c SASTClient) recordRequestDetailsInErrorCase(requestBody []byte, responseBody []byte) {
	if len(requestBody) != 0 {
		c.logger.Tracef("Request body: %s", string(requestBody))
	}
	if len(responseBody) != 0 {
		c.logger.Tracef("Response body: %s", string(responseBody))
	}
}

// convenience function
func (c SASTClient) getV(api string, version string) ([]byte, error) {
	header := http.Header{}
	header.Add("Accept", "application/json;v="+version)

	return c.sendRequest(http.MethodGet, api, nil, header)
}

func (c SASTClient) get(api string) ([]byte, error) {
	return c.getV(api, "1.0")
}

func (c SASTClient) ClientsValid() (bool, bool) {

	rest_valid := false
	soap_valid := false

	if c.restClient != nil {
		token, err := c.restClient.Transport.(*oauth2.Transport).Source.Token()
		if err != nil {
			rest_valid = false
		} else {
			rest_valid = token.Valid()
		}
	}

	if c.soapClient != nil {
		token, err := c.soapClient.Transport.(*oauth2.Transport).Source.Token()
		if err != nil {
			soap_valid = false
		} else {
			soap_valid = token.Valid()
		}
	}

	return rest_valid, soap_valid
}

func (s *Scan) String() string {
	return fmt.Sprintf("Scan ID: %d, Project ID: %d, Status: %v, Time: %v", s.ScanID, s.Project.ID, s.Status, s.DateAndTime.FinishedOn.Format(time.RFC3339))
}

func (c SASTClient) String() string {
	return c.baseUrl // + " with token: " + ShortenGUID(c.authToken)
}

func ShortenGUID(guid string) string {
	return fmt.Sprintf("%v..%v", guid[:2], guid[len(guid)-2:])
}

// If you want to provide your own authenticated HTTP Client (prepared through OAuth2 library) you can use this instead.
// this is useful if you are using SAST authentication on a third-party website with authorization_code style oauth
// oauth authorization_code helper function are implemented in sastpassclient.go
func New(client *http.Client, soap_client *http.Client, base_url string, logger *logrus.Logger) (*SASTClient, error) {

	cli := &SASTClient{client, soap_client, base_url, logger, nil}

	user, err := cli.GetCurrentUser()
	if err != nil {
		logger.Errorf("Error while fetching current user information: %s", err)
		return nil, err
	}

	cli.CurrentUser = &user

	//	cli.RefreshCache()
	return cli, nil
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

	cli, err := New(rest_client, soap_client, base_url, logger)
	if err != nil {
		return nil, fmt.Errorf("unable to create client: %s", err)
	}
	return cli, nil
}

func (c SASTClient) depwarn(old, new string) {
	if new == "" {
		c.logger.Warnf("Cx1SASTClientGo deprecation notice: %v will be deprecated", old)
	} else {
		c.logger.Warnf("Cx1SASTClientGo deprecation notice: %v will be deprecated and replaced by %v", old, new)
	}
}

func (c SASTClient) CompareVersions(version, target string) int {
	v := versionStringToInts(version)
	t := versionStringToInts(target)

	min := len(v)
	if min > len(t) {
		min = len(t)
	}

	for id := 0; id < min; id++ {
		if v[id] < t[id] {
			return -1
		}
		if v[id] > t[id] {
			return 1
		}
	}
	return 0
}

func versionStringToInts(version string) []int64 {
	if version == "" {
		return []int64{0, 0, 0, 0}
	}
	str := strings.Split(version, ".")
	ints := make([]int64, len(str))
	for id, val := range str {
		ints[id], _ = strconv.ParseInt(val, 10, 64)
	}
	return ints
}

const sastTimeLayout = "2006-01-02T15:04:05.999"

func (ct *SASTTime) UnmarshalJSON(b []byte) (err error) {
	s := strings.Trim(string(b), "\"")
	if s == "null" {
		ct.Time = time.Time{}
		return
	}
	ct.Time, err = time.Parse(sastTimeLayout, s)
	return
}
