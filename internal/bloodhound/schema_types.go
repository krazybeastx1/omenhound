package bloodhound

// bhFile mirrors the BloodHound CE JSON wrapper:
//
//	{"data": [ ...objects... ], "meta": {"type": "users", "count": N, "version": 5}}
type bhFile struct {
	Data []bhEntry `json:"data"`
	Meta struct {
		Type    string `json:"type"`
		Count   int    `json:"count"`
		Version int    `json:"version"`
	} `json:"meta"`
}

// bhEntry is the union of every field BloodHound CE emits across object types.
type bhEntry struct {
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	Properties       map[string]any `json:"Properties"`
	IsDeleted        bool           `json:"IsDeleted"`
	IsACLProtected   bool           `json:"IsACLProtected"`

	Aces     []bhAce  `json:"Aces"`
	Members  []bhLink `json:"Members"`
	MemberOf []bhLink `json:"MemberOf"`

	ChildObjects []bhLink   `json:"ChildObjects"`
	Links        []bhGPLink `json:"Links"`

	AllowedToDelegate []bhLink `json:"AllowedToDelegate"`
	AllowedToAct      []bhLink `json:"AllowedToAct"`
	HasSIDHistory     []bhLink `json:"HasSIDHistory"`

	PrimaryGroupSID string `json:"PrimaryGroupSID"`

	LocalAdmins        *bhCollected   `json:"LocalAdmins"`
	PSRemoteUsers      *bhCollected   `json:"PSRemoteUsers"`
	RemoteDesktopUsers *bhCollected   `json:"RemoteDesktopUsers"`
	DcomUsers          *bhCollected   `json:"DcomUsers"`
	Sessions           *bhCollected   `json:"Sessions"`
	PrivilegedSessions *bhCollected   `json:"PrivilegedSessions"`
	RegistrySessions   *bhCollected   `json:"RegistrySessions"`
	LocalGroups        []bhLocalGroup `json:"LocalGroups"`

	Trusts []bhTrust `json:"Trusts"`
}

// bhLocalGroup mirrors a BloodHound CE v5 computer "LocalGroups" entry.
type bhLocalGroup struct {
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	Name             string     `json:"Name"`
	Collected        bool       `json:"Collected"`
	FailureReason    string     `json:"FailureReason"`
	Results          []bhResult `json:"Results"`
}

type bhAce struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
	Inherited     bool   `json:"Inherited"`
}

type bhLink struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type bhGPLink struct {
	GUID       string `json:"GUID"`
	IsEnforced bool   `json:"IsEnforced"`
}

type bhTrust struct {
	TargetDomainName    string      `json:"TargetDomainName"`
	TargetDomainSid     string      `json:"TargetDomainSid"`
	TrustDirection      interface{} `json:"TrustDirection"`
	TrustType           interface{} `json:"TrustType"`
	IsTransitive        bool        `json:"IsTransitive"`
	SidFilteringEnabled bool        `json:"SidFilteringEnabled"`
}

type bhCollected struct {
	Collected     bool       `json:"Collected"`
	FailureReason string     `json:"FailureReason"`
	Results       []bhResult `json:"Results"`
}

type bhResult struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
	ComputerSID      string `json:"ComputerSID"`
	UserSID          string `json:"UserSID"`
}
