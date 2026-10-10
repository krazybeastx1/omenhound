package bloodhound

import (
	"strings"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

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
// Go's JSON decoder ignores unknown fields, so one struct serves users, groups,
// computers, OUs, GPOs, containers and domains.
type bhEntry struct {
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	Properties       map[string]any `json:"Properties"`
	IsDeleted        bool           `json:"IsDeleted"`
	IsACLProtected   bool           `json:"IsACLProtected"`

	Aces     []bhAce  `json:"Aces"`
	Members  []bhLink `json:"Members"`  // groups: members of this group
	MemberOf []bhLink `json:"MemberOf"` // users: groups this object belongs to

	ChildObjects []bhLink   `json:"ChildObjects"`
	Links        []bhGPLink `json:"Links"`

	AllowedToDelegate []bhLink `json:"AllowedToDelegate"`
	AllowedToAct      []bhLink `json:"AllowedToAct"`
	HasSIDHistory     []bhLink `json:"HasSIDHistory"`

	PrimaryGroupSID string `json:"PrimaryGroupSID"`

	LocalAdmins        *bhCollected `json:"LocalAdmins"`
	PSRemoteUsers      *bhCollected `json:"PSRemoteUsers"`
	RemoteDesktopUsers *bhCollected `json:"RemoteDesktopUsers"`
	DcomUsers          *bhCollected `json:"DcomUsers"`
	Sessions           *bhCollected `json:"Sessions"`
	PrivilegedSessions *bhCollected `json:"PrivilegedSessions"`
	RegistrySessions   *bhCollected `json:"RegistrySessions"`

	Trusts []bhTrust `json:"Trusts"`
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
	TargetDomainName    string `json:"TargetDomainName"`
	TargetDomainSid     string `json:"TargetDomainSid"`
	TrustDirection      int    `json:"TrustDirection"`
	TrustType           int    `json:"TrustType"`
	IsTransitive        bool   `json:"IsTransitive"`
	SidFilteringEnabled bool   `json:"SidFilteringEnabled"`
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

// fileKind classifies a JSON file by its meta.type, falling back to the
// filename so prefixed/rotated BloodHound.py output still resolves.
func fileKind(metaType, fileName string) (model.Kind, bool) {
	switch strings.ToLower(strings.TrimSpace(metaType)) {
	case "users":
		return model.KindUser, true
	case "groups":
		return model.KindGroup, true
	case "computers":
		return model.KindComputer, true
	case "ous", "organizationalunits":
		return model.KindOU, true
	case "gpos":
		return model.KindGPO, true
	case "containers":
		return model.KindContainer, true
	case "domains":
		return model.KindDomain, true
	}
	base := strings.ToLower(fileName)
	for _, kw := range []struct {
		word string
		kind model.Kind
	}{
		{"organizationalunits", model.KindOU},
		{"containers", model.KindContainer},
		{"computers", model.KindComputer},
		{"domains", model.KindDomain},
		{"groups", model.KindGroup},
		{"users", model.KindUser},
		{"gpos", model.KindGPO},
		{"ous", model.KindOU},
	} {
		if strings.Contains(base, kw.word) {
			return kw.kind, true
		}
	}
	return "", false
}

// kindFromObjectType maps a BloodHound "ObjectType" hint to a node kind. The
// second return is false for genuinely unknown types, which map to Base.
func kindFromObjectType(t string) (model.Kind, bool) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "user":
		return model.KindUser, true
	case "group", "localgroup", "foreignsecurityprincipal":
		return model.KindGroup, true
	case "computer", "machine":
		return model.KindComputer, true
	case "domain":
		return model.KindDomain, true
	case "ou", "organizationalunit", "organizational-unit":
		return model.KindOU, true
	case "gpo", "grouppolicy":
		return model.KindGPO, true
	case "container":
		return model.KindContainer, true
	case "base", "wellknown", "unknown", "":
		return model.KindBase, true
	}
	return model.KindBase, false
}

// rightToKind maps BloodHound CE ACE right names to OmenHound edge kinds.
var rightToKind = map[string]model.EdgeKind{
	"GenericAll":                 model.EdgeGenericAll,
	"GenericWrite":               model.EdgeGenericWrite,
	"WriteDacl":                  model.EdgeWriteDacl,
	"WriteOwner":                 model.EdgeWriteOwner,
	"WriteOwnerLimitedRights":    model.EdgeWriteOwner,
	"Owns":                       model.EdgeOwns,
	"Owner":                      model.EdgeOwns,
	"ForceChangePassword":        model.EdgeForceChangePassword,
	"AddMember":                  model.EdgeAddMember,
	"AddSelf":                    model.EdgeAddSelf,
	"AllExtendedRights":          model.EdgeAllExtendedRights,
	"AddKeyCredentialLink":       model.EdgeAddKeyCredentialLink,
	"AddAllowedToAct":            model.EdgeAddAllowedToAct,
	"WriteSPN":                   model.EdgeWriteSPN,
	"WriteAccountRestrictions":   model.EdgeWriteAccountRestrictions,
	"WriteGPLink":                model.EdgeWriteGPLink,
	"WriteAltSecurityIdentities": model.EdgeWriteAltSecurityIdentities,
	"GetChanges":                 model.EdgeGetChanges,
	"GetChangesAll":              model.EdgeGetChangesAll,
	"GetChangesInFilteredSet":    model.EdgeGetChangesInFilteredSet,
	"DCSync":                     model.EdgeDCSync,
	"ReadLAPSPassword":           model.EdgeReadLAPSPassword,
	"ReadGMSAPassword":           model.EdgeReadGMSAPassword,
	"DumpSMSAPassword":           model.EdgeDumpSMSAPassword,
}
