package bloodhound

import (
	"strings"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

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
