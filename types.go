package CxSASTClientGo

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type SASTClient struct {
	restClient  *http.Client
	soapClient  *http.Client
	baseUrl     string
	logger      *logrus.Logger
	CurrentUser *User
}

type ApplicationVersion struct {
	ApplicationVersion string
	EnginePack         string
	HotFix             int
}

type AuthenticationProvider struct {
	ID           uint64
	Name         string
	ProviderID   uint64
	ProviderType string
	IsExternal   bool
	Active       bool
}

const (
	PreScanAction  = "SOURCE_CONTROL_COMMAND"
	PostScanAction = "POST_SCAN_COMMAND"
)

type CustomTask struct {
	ID   uint64
	Name string
	Type string
	Data string
}

type EngineConfiguration struct {
	ID   uint64
	Name string
}

type IssueTracker struct {
	ID   uint64
	Name string
	Type string
	URL  string
}

type Link struct {
	Rel string `json:"rel"`
	URI string `json:"uri"`
}

type Links struct {
	Report Link `json:"report"`
	Status Link `json:"status"`
}

type OIDCClaim struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type OIDCClient struct {
	ID                                uint64      `json:"id"`
	UpdateAccessTokenClaimsOnRefresh  bool        `json:"updateAccessTokenClaimsOnRefresh"`
	AccessTokenType                   uint64      `json:"accessTokenType"`
	IncludeJwtID                      bool        `json:"includeJwtId"`
	AlwaysIncludeUserClaimsInIDToken  bool        `json:"alwaysIncludeUserClaimsInIdToken"`
	ClientID                          string      `json:"clientId"`
	ClientName                        string      `json:"clientName"`
	AllowOfflineAccess                bool        `json:"allowOfflineAccess"`
	ClientSecrets                     []string    `json:"clientSecrets"`
	AllowedGrantTypes                 []string    `json:"allowedGrantTypes"`
	AllowedScopes                     []string    `json:"allowedScopes"`
	Enabled                           bool        `json:"enabled"`
	RequireClientSecret               bool        `json:"requireClientSecret"`
	RedirectUris                      []string    `json:"redirectUris"`
	PostLogoutRedirectUris            []string    `json:"postLogoutRedirectUris"`
	FrontChannelLogoutUri             *string     `json:"frontChannelLogoutUri"`
	FrontChannelLogoutSessionRequired bool        `json:"frontChannelLogoutSessionRequired"`
	BackChannelLogoutUri              *string     `json:"backChannelLogoutUri"`
	BackChannelLogoutSessionRequired  bool        `json:"backChannelLogoutSessionRequired"`
	IdentityTokenLifetime             uint64      `json:"identityTokenLifetime"`
	AccessTokenLifetime               uint64      `json:"accessTokenLifetime"`
	AuthorizationCodeLifetime         uint64      `json:"authorizationCodeLifetime"`
	AbsoluteRefreshTokenLifetime      uint64      `json:"absoluteRefreshTokenLifetime"`
	SlidingRefreshTokenLifetime       uint64      `json:"slidingRefreshTokenLifetime"`
	RefreshTokenUsage                 uint64      `json:"refreshTokenUsage"`
	RefreshTokenExpiration            uint64      `json:"refreshTokenExpiration"`
	AllowedCorsOrigins                []string    `json:"allowedCorsOrigins"`
	AllowAccessTokensViaBrowser       bool        `json:"allowAccessTokensViaBrowser"`
	Claims                            []OIDCClaim `json:"claims"`
	ClientClaimsPrefix                string      `json:"clientClaimsPrefix"`
	RequirePkce                       bool        `json:"requirePkce"`
}

type PathNode struct {
	FileName   string
	Line       uint64
	Column     uint64
	Name       string
	Length     uint64
	MethodLine uint64
	NodeId     uint64
}

type PathResultInfo struct {
	Source1           []string
	AbsoluteFileName1 string
	Line1             uint64
	Column1           uint64
	MethodLine1       uint64
	Source2           []string
	AbsoluteFileName2 string
	Line2             uint64
	Column2           uint64
	MethodLine2       uint64
	QueryID           uint64
	State             string
	Severity          string
	PathID            uint64
	SimilarityID      int64
	Comment           string
}

type Preset struct {
	PresetID uint64 `json:"id"`
	Name     string
	QueryIDs []uint64
	Filled   bool    `json:"-"`
	Queries  []Query `json:"-"`
}

type Project struct {
	ProjectID    uint64 `json:"id"`
	TeamID       uint64
	Name         string
	IsPublic     bool
	SourceType   string
	Settings     *ProjectSettings
	Repo         *ProjectRepo
	Filters      *SourceFilters
	CustomFields []ProjectCustomField
}

type ProjectCustomField struct {
	ID        uint   `json:"id"`
	Value     string `json:"value"`
	Name      string `json:"name"`
	Mandatory bool   `json:"isMandatory"`
}

type ProjectRepo struct {
	URL    string
	Branch string
	UseSSH bool
}

type ProjectSettings struct {
	ProjectID uint64
	PresetID  uint64
	//PresetName            string
	EngineConfigurationID uint64
	PostScanAction        int64
	EmailNotifications    struct {
		FailedScan []string
		BeforeScan []string
		AfterScan  []string
	}
}

type Query struct {
	Name               string
	QueryID            uint64 `xml:"QueryId"`
	BaseQueryID        uint64
	CWE                uint64 `xml:"Cwe"`
	Severity           int
	PackageID          uint64 `xml:"PackageId"`
	Language           string
	Group              string
	IsExecutable       bool        `xml:"IsExecutable"`
	Source             string      `xml:"Source"`
	DescriptionID      uint64      `xml:"CxDescriptionID"`
	Version            uint64      `xml:"QueryVersionCode"`
	OwningGroup        *QueryGroup `json:"-"`
	Dependencies       []uint64    `json:"-"`         // dependencies on queries outside of the inheritance hierarchy
	CustomDependencies []uint64    `json:"-"`         // dependencies on custom queries outside of the inheritance hierarchy
	UnknownCalls       []string    `json:"-"`         // calls ot functions that are not other CxQL queries (may be API)
	Hierarchy          []uint64    `json:"Hierarchy"` // inheritance hierarchy
	IsValid            bool        `json:"-"`
}

type QueryGroup struct {
	Name            string
	PackageID       uint64
	Queries         []Query
	Language        string `xml:"languageName"`
	OwningProjectID uint64 `xml:"ProjectId"`
	PackageType     string `xml:"PackageTypeName"`
	OwningTeamID    uint64 `xml:"OwningTeam"`
}

type QueryLanguage struct {
	Name        string
	LanguageID  uint64
	QueryGroups []QueryGroup
}

type QueryCollection struct {
	QueryLanguages []QueryLanguage
	QueryCount     uint
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

type ResultState struct {
	Name       string `xml:"ResultName"`
	ID         uint   `xml:"ResultID"`
	Permission string `xml:"ResultPermission"`
	IsCustom   bool
}

type Role struct {
	RoleID        uint64 `json:"id"`
	IsSystemRole  bool
	Name          string
	Description   string
	PermissionIDs []uint64
}

type SASTTime struct {
	time.Time
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
	ScanState struct {
		Path       string `json:"path"`
		FilesCount uint64 `json:"filesCount"`
		LOC        uint64 `json:"linesOfCode"`
		FailedLOC  uint64 `json:"failedLinesOfCode"`
		SourceID   string `json:"sourceId"`
		CxVersion  string `json:"cxVersion"`
		Languages  []struct {
			ID           uint64   `json:"languageID"`
			Name         string   `json:"languageName"`
			Hash         string   `json:"languageHash"`
			CreationDate SASTTime `json:"stateCreationDate"`
		} `json:"languageStateCollection"`
	}
	DateAndTime struct {
		StartedOn        SASTTime
		FinishedOn       SASTTime
		EngineStartedOn  SASTTime
		EngineFinishedOn SASTTime
	}
}

type ScanResult struct {
	QueryName         string
	QueryID           uint64
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
	Group             string
	Language          string
	Comment           string
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

type ScanSchedule struct {
	ProjectID   uint64   `json:"projectId"`
	ProjectName string   `json:"projectName"`
	Days        []string `json:"scanDays"`
	Time        string   `json:"scanTime"`
}

type ScanSettings struct {
	ProjectID              uint64  `json:"projectID"`
	OverrideProjectSetting bool    `json:"overrideProjectSetting"`
	IsIncremental          bool    `json:"isIncremental"`
	IsPublic               bool    `json:"isPublic"`
	ForceScan              bool    `json:"forceScan"`
	Comment                string  `json:"comment"`
	PresetID               uint64  `json:"presetId"`
	EngineConfigurationID  uint64  `json:"engineConfigurationId"`
	ZippedSource           *[]byte `json:"zippedSource,omitempty"`
}

type ScanSettingsSOAP struct {
	Text         string `xml:",chardata"`
	IsSuccesfull string `xml:"IsSuccesfull"`
	Started      struct {
		Text   string `xml:",chardata"`
		Hour   string `xml:"Hour"`
		Minute string `xml:"Minute"`
		Second string `xml:"Second"`
		Day    string `xml:"Day"`
		Month  string `xml:"Month"`
		Year   string `xml:"Year"`
	} `xml:"Started"`
	Finished struct {
		Text   string `xml:",chardata"`
		Hour   string `xml:"Hour"`
		Minute string `xml:"Minute"`
		Second string `xml:"Second"`
		Day    string `xml:"Day"`
		Month  string `xml:"Month"`
		Year   string `xml:"Year"`
	} `xml:"Finished"`
	RequestStarted struct {
		Text   string `xml:",chardata"`
		Hour   string `xml:"Hour"`
		Minute string `xml:"Minute"`
		Second string `xml:"Second"`
		Day    string `xml:"Day"`
		Month  string `xml:"Month"`
		Year   string `xml:"Year"`
	} `xml:"RequestStarted"`
	RequestComplete struct {
		Text   string `xml:",chardata"`
		Hour   string `xml:"Hour"`
		Minute string `xml:"Minute"`
		Second string `xml:"Second"`
		Day    string `xml:"Day"`
		Month  string `xml:"Month"`
		Year   string `xml:"Year"`
	} `xml:"RequestComplete"`
	ScanRisk                    string `xml:"ScanRisk"`
	Preset                      string `xml:"Preset"`
	Path                        string `xml:"Path"`
	Comment                     string `xml:"Comment"`
	LOC                         string `xml:"LOC"`
	FilesCount                  string `xml:"FilesCount"`
	High                        string `xml:"High"`
	Medium                      string `xml:"Medium"`
	Low                         string `xml:"Low"`
	Info                        string `xml:"Info"`
	ScanRiskSeverity            string `xml:"ScanRiskSeverity"`
	ScanRiskQuantity            string `xml:"ScanRiskQuantity"`
	IsIncremental               string `xml:"IsIncremental"`
	ScanType                    string `xml:"ScanType"`
	ScanLanguageStateCollection struct {
		Text                   string `xml:",chardata"`
		CxWSQueryLanguageState []struct {
			Text              string `xml:",chardata"`
			LanguageID        string `xml:"LanguageID"`
			LanguageName      string `xml:"LanguageName"`
			LanguageHash      string `xml:"LanguageHash"`
			StateCreationDate string `xml:"StateCreationDate"`
		} `xml:"CxWSQueryLanguageState"`
	} `xml:"ScanLanguageStateCollection"`
	EngineStart struct {
		Text   string `xml:",chardata"`
		Hour   string `xml:"Hour"`
		Minute string `xml:"Minute"`
		Second string `xml:"Second"`
		Day    string `xml:"Day"`
		Month  string `xml:"Month"`
		Year   string `xml:"Year"`
	} `xml:"EngineStart"`
	EngineFinish struct {
		Text   string `xml:",chardata"`
		Hour   string `xml:"Hour"`
		Minute string `xml:"Minute"`
		Second string `xml:"Second"`
		Day    string `xml:"Day"`
		Month  string `xml:"Month"`
		Year   string `xml:"Year"`
	} `xml:"EngineFinish"`
	ScanQueued struct {
		Text   string `xml:",chardata"`
		Hour   string `xml:"Hour"`
		Minute string `xml:"Minute"`
		Second string `xml:"Second"`
		Day    string `xml:"Day"`
		Month  string `xml:"Month"`
		Year   string `xml:"Year"`
	} `xml:"ScanQueued"`
	TotalScanTime             string `xml:"TotalScanTime"`
	TotalEngineTime           string `xml:"TotalEngineTime"`
	StatisticsCalculationDate struct {
		Text   string `xml:",chardata"`
		Hour   string `xml:"Hour"`
		Minute string `xml:"Minute"`
		Second string `xml:"Second"`
		Day    string `xml:"Day"`
		Month  string `xml:"Month"`
		Year   string `xml:"Year"`
	} `xml:"StatisticsCalculationDate"`
	ProjectName         string `xml:"ProjectName"`
	TeamName            string `xml:"TeamName"`
	ScanCompletedStatus string `xml:"ScanCompletedStatus"`
}

type SourceFilters struct {
	ProjectID      uint64 `json:"projectId"`
	FoldersPattern string `json:"excludeFoldersPattern"`
	FilesPattern   string `json:"excludeFilesPattern"`
	PathPattern    string `json:"pathFilter"`
}

type SourceFile struct {
	Filename string
	Source   string
}

type Team struct {
	TeamID         uint64 `json:"id"`
	Name           string
	FullName       string
	ParentID       uint64
	Projects       []*Project
	Users          []uint64
	InheritedUsers []uint64
}

type User struct {
	UserID        uint64 `json:"id"`
	FirstName     string
	LastName      string
	UserName      string
	LastLoginDate string
	Email         string
	IDPID         uint64 `json:"authenticationProviderId"`
	RoleIDs       []uint64
	TeamIDs       []uint64
	AccessToUI    bool `json:"accessToUi"`
}
