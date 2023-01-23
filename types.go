package CxSASTClientGo

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type SASTClient struct {
	httpClient  *http.Client
	authToken   string
	soapToken   string
	baseUrl     string
	logger      *logrus.Logger
	CurrentUser *User
}

type User struct {
	UserID        uint64 `json:"id"`
	FirstName     string
	LastName      string
	UserName      string
	LastLoginDate string
	Email         string
	RoleIDs       []uint64
	TeamIDs       []uint64
}

type Role struct {
	RoleID        uint64 `json:"id"`
	IsSystemRole  bool
	Name          string
	Description   string
	PermissionIDs []uint64
}

type Links struct {
	Report Link `json:"report"`
	Status Link `json:"status"`
}

type Link struct {
	Rel string `json:"rel"`
	URI string `json:"uri"`
}

type Project struct {
	ProjectID uint64 `json:"id"`
	TeamID    uint64
	Name      string
	Settings  *ProjectSettings
}

type ProjectSettings struct {
	ProjectID             uint64
	PresetID              uint64
	EngineConfigurationID uint64
	PostScanAction        int64
	EmailNotifications    struct {
		FailedScan []string
		BeforeScan []string
		AfterScan  []string
	}
}

type Team struct {
	TeamID   uint64 `json:"id"`
	Name     string
	ParentID uint64
	Projects []Project
}

type Preset struct {
	PresetID uint64 `json:"id"`
	Name     string
	Filled   bool
	Queries  []Query
}

type Query struct {
	Name      string
	QueryID   uint64 `xml:"QueryId"`
	CWE       uint64 `xml:"Cwe"`
	Severity  int
	PackageID uint64 `xml:"PackageId"`
	Language  string
	Group     string
}

type QueryGroup struct {
	Name            string
	PackageID       uint64
	Queries         []*Query
	Language        string `xml:"languageName"`
	OwningProjectID uint64 `xml:"ProjectId"`
	PackageType     string `xml:"PackageTypeName"`
	OwningTeamID    uint64 `xml:"OwningTeam"`
}

type Report struct {
	ReportID uint64 `json:"reportId"`
	Links    Links  `json:"links"`
}

// ReportStatusResponse - ReportStatusResponse Structure
type ReportStatusResponse struct {
	Location    string       `json:"location"`
	ContentType string       `json:"contentType"`
	Status      ReportStatus `json:"status"`
}

// ReportStatus - ReportStatus Structure
type ReportStatus struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type Scan struct {
	ScanID  uint64 `json:"id"`
	Project struct {
		ID   uint64
		Name string
	}
	Status struct {
		ID   uint64
		Name string
	}
	FinishTime time.Time
}

type PathNode struct {
	FileName string
	Line     uint64
	Column   uint64
	Name     string
	Length   uint64
}

type ScanResult struct {
	QueryName         string
	PathID            uint64
	Line              uint64
	Column            uint64
	DetectionDate     string
	Filename          string
	DeepLink          string
	Status            string
	Severity          string
	State             string
	SimilarityID      int64
	SourceMethod      string
	DestinationMethod string
	Nodes             []PathNode
}

type ScanResultStatusSummary struct {
	ToVerify               uint64
	NotExploitable         uint64
	Confirmed              uint64
	ProposedNotExploitable uint64
	Urgent                 uint64
}

type ScanResultSummary struct {
	High        ScanResultStatusSummary
	Medium      ScanResultStatusSummary
	Low         ScanResultStatusSummary
	Information ScanResultStatusSummary
}
