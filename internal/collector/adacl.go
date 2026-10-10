package collector

import (
	"strings"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// ---------------------------------------------------------------------------
// ACE -> BloodHound edge mapping
//
// This is a faithful port of BloodHound.py's ACLProcessor
// (bloodhound/enumeration/acls.py, parse_binary_acl). Keeping the mapping
// identical means an operator's existing BloodHound reasoning and saved Cypher
// queries keep working against an OmenHound-collected graph.
// ---------------------------------------------------------------------------

// Well-known extended-right / property GUIDs, copied verbatim from
// BloodHound.py's EXTRIGHTS_GUID_MAPPING.
var (
	guidGetChanges              = mustGUID("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	guidGetChangesAll           = mustGUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
	guidGetChangesInFilteredSet = mustGUID("89e95b76-444d-4c62-991a-0facbeda640c")
	guidWriteMember             = mustGUID("bf9679c0-0de6-11d0-a285-00aa003049e2")
	guidUserForceChangePassword = mustGUID("00299570-246d-11d0-a768-00aa006e0529")
	guidAllowedToAct            = mustGUID("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")
	guidUserAccountRestrictions = mustGUID("4c164200-20c0-11d0-a768-00aa006e0529")
	guidWriteGPLink             = mustGUID("f30e3bbe-9ff0-11d1-b603-0000f80367c1")
)

// Schema names (lowercased CNs) of the attribute GUIDs that are looked up in
// the live schema rather than hard-coded, exactly as BloodHound.py does.
const (
	schemaAttrLAPSLegacy = "ms-mcs-admpwd"
	schemaAttrLAPS       = "ms-laps-password"
	schemaAttrLAPSEnc    = "ms-laps-encryptedpassword"
	schemaAttrKeyCred    = "ms-ds-key-credential-link"
	schemaAttrSPN        = "service-principal-name"
)

// aclIgnoreSIDs are the principals BloodHound.py never attributes a right to:
// CREATOR OWNER, LOCAL SYSTEM, and SELF. Their presence in a DACL is a
// placeholder, not a real grant.
var aclIgnoreSIDs = map[string]bool{
	"S-1-3-0":  true,
	"S-1-5-18": true,
	"S-1-5-10": true,
}

// aclClassNames maps a node kind to the lowercased schema class names whose
// inherited ACEs apply to it. BloodHound.py keys its map by lowercased schema
// CN ("Organizational-Unit", "Group-Policy-Container", "Domain-DNS"); the
// aliases here cover both the hyphenated schema spelling and the friendly
// BloodHound entry-type spelling.
var aclClassNames = map[model.Kind][]string{
	model.KindUser:      {"user"},
	model.KindGroup:     {"group"},
	model.KindComputer:  {"computer"},
	model.KindDomain:    {"domain-dns", "domain"},
	model.KindOU:        {"organizational-unit"},
	model.KindGPO:       {"group-policy-container", "gpo"},
	model.KindContainer: {"container"},
}

// aclEntryType is BloodHound.py's entrytype string for a node kind. The mapping
// rules are written in terms of these names, so they are kept verbatim.
func aclEntryType(k model.Kind) string {
	switch k {
	case model.KindUser:
		return "user"
	case model.KindGroup:
		return "group"
	case model.KindComputer:
		return "computer"
	case model.KindDomain:
		return "domain"
	case model.KindOU:
		return "organizational-unit"
	case model.KindGPO:
		return "gpo"
	case model.KindContainer:
		return "container"
	}
	return ""
}

// aclRelation is one edge an ACE grants. SID is the trustee (the ACE principal,
// or the owner for an Owns relation) and Inherited marks weaker, inherited
// evidence that BloodHound CE reports separately.
type aclRelation struct {
	Kind      model.EdgeKind
	SID       string
	Inherited bool
}

// aclStats records what the mapper skipped, so a run can report it instead of
// silently dropping data.
type aclStats struct {
	// Entries is the number of ACEs examined.
	Entries int
	// UnknownACETypes counts ACEs by type for types the mapper does not
	// interpret (denied, audit, resource-attribute, ...).
	UnknownACETypes map[uint8]int
	// InheritedFiltered counts inherited ACEs dropped because their
	// InheritedObjectType named a class other than this object's.
	InheritedFiltered int
	// InheritedUnfiltered counts inherited ACEs that were applied without
	// class filtering because the schema was unavailable to resolve class
	// GUIDs. Non-zero means the result may over-approximate.
	InheritedUnfiltered int
}

// aclRelations turns one object's security descriptor into edges. classGUIDs
// maps lowercased schema names to GUIDs (from the directory schema); when it is
// empty, class-based filtering of inherited ACEs is skipped and counted.
func aclRelations(kind model.Kind, sd *SecurityDescriptor, classGUIDs map[string]GUID, hasLAPS bool) ([]aclRelation, aclStats) {
	st := aclStats{UnknownACETypes: map[uint8]int{}}
	if sd == nil {
		return nil, st
	}
	st.Entries = len(sd.DACL)
	entrytype := aclEntryType(kind)
	var out []aclRelation

	// Owner -> Owns.
	if sd.OwnerSID != "" && !aclIgnoreSIDs[sd.OwnerSID] {
		out = append(out, aclRelation{Kind: model.EdgeOwns, SID: sd.OwnerSID})
	}

	schemaKnown := len(classGUIDs) > 0
	// appliesClass reports whether a class GUID restricts an ACE to this
	// object's class. known=false means the schema could not resolve it, in
	// which case the ACE is kept (BloodHound.py's ace_applies is permissive when
	// the class is unknown) and the caller reports the over-approximation.
	appliesClass := func(g *GUID) (applies, known bool) {
		if g == nil {
			return true, true
		}
		matchedAny := false
		for _, name := range aclClassNames[kind] {
			cg, ok := classGUIDs[name]
			if !ok {
				continue
			}
			matchedAny = true
			if cg == *g {
				return true, true
			}
		}
		if !matchedAny || !schemaKnown {
			return true, false
		}
		return false, true
	}

	for _, ace := range sd.DACL {
		if ace.Type != aceTypeAccessAllowed && ace.Type != aceTypeAccessAllowedObject {
			st.UnknownACETypes[ace.Type]++
			continue
		}
		if ace.SID == "" || aclIgnoreSIDs[ace.SID] {
			continue
		}
		inh := ace.inherited()
		if !inh && ace.inheritOnly() {
			// Set on this object but flagged for children only.
			continue
		}
		mask := ace.Mask
		add := func(k model.EdgeKind, inherited bool) {
			out = append(out, aclRelation{Kind: k, SID: ace.SID, Inherited: inherited})
		}

		switch ace.Type {
		case aceTypeAccessAllowedObject:
			// An inherited ACE can name the class it applies to.
			if inh && ace.InheritedObjectType != nil {
				ok, known := appliesClass(ace.InheritedObjectType)
				if !ok {
					if known {
						st.InheritedFiltered++
					} else {
						st.InheritedUnfiltered++
					}
					continue
				}
				if !known {
					// Schema unavailable: the ACE was kept without class
					// filtering, so the result may over-approximate.
					st.InheritedUnfiltered++
				}
			}

			if hasMask(mask, maskGenericAll) || mask&maskWriteDACL != 0 ||
				mask&maskWriteOwner != 0 || hasMask(mask, maskGenericWrite) {
				// A generic right restricted to another class does not apply.
				if ok, _ := appliesClass(ace.ObjectType); !ok {
					continue
				}
				if hasMask(mask, maskGenericAll) {
					if entrytype == "computer" && ace.ObjectType != nil && hasLAPS {
						if g, ok := classGUIDs[schemaAttrLAPSLegacy]; ok && g == *ace.ObjectType {
							add(model.EdgeReadLAPSPassword, inh)
						}
					} else {
						add(model.EdgeGenericAll, inh)
					}
					continue
				}
				if hasMask(mask, maskGenericWrite) {
					add(model.EdgeGenericWrite, inh)
					// On the domain and computer objects the mapper keeps
					// evaluating the lower bits, matching BloodHound.py.
					if entrytype != "domain" && entrytype != "computer" {
						continue
					}
				}
				if mask&maskWriteDACL != 0 {
					add(model.EdgeWriteDacl, inh)
				}
				if mask&maskWriteOwner != 0 {
					add(model.EdgeWriteOwner, inh)
				}
			}

			if mask&maskDSWriteProp != 0 {
				if aclWritableClass(entrytype) && ace.ObjectType == nil {
					add(model.EdgeGenericWrite, inh)
				}
				if entrytype == "group" && canWriteProperty(ace, guidWriteMember) {
					add(model.EdgeAddMember, inh)
				}
				if entrytype == "computer" && canWriteProperty(ace, guidAllowedToAct) {
					add(model.EdgeAddAllowedToAct, inh)
				}
				if (entrytype == "computer" || entrytype == "user") &&
					canWriteProperty(ace, guidUserAccountRestrictions) && !strings.HasSuffix(ace.SID, "-512") {
					add(model.EdgeWriteAccountRestrictions, inh)
				}
				if entrytype == "organizational-unit" && canWriteProperty(ace, guidWriteGPLink) {
					add(model.EdgeWriteGPLink, inh)
				}
				if (entrytype == "user" || entrytype == "computer") && guidMatches(ace.ObjectType, classGUIDs[schemaAttrKeyCred]) {
					add(model.EdgeAddKeyCredentialLink, inh)
				}
				if (entrytype == "user" || entrytype == "computer") && guidMatches(ace.ObjectType, classGUIDs[schemaAttrSPN]) {
					add(model.EdgeWriteSPN, inh)
				}
			} else if mask&maskDSSelf != 0 {
				// AddSelf: the ACE grants SELF over group membership.
				if entrytype == "group" && ace.ObjectType != nil && *ace.ObjectType == guidWriteMember {
					add(model.EdgeAddSelf, inh)
				}
			}

			// LAPS: property read over the managed-password attribute.
			if mask&maskDSReadProp != 0 && mask&maskDSControlAccess != 0 {
				if entrytype == "computer" && ace.ObjectType != nil && hasLAPS {
					for _, n := range []string{schemaAttrLAPSLegacy, schemaAttrLAPS, schemaAttrLAPSEnc} {
						if guidMatches(ace.ObjectType, classGUIDs[n]) {
							add(model.EdgeReadLAPSPassword, inh)
						}
					}
				}
			}

			// Extended (control-access) rights.
			if mask&maskDSControlAccess != 0 {
				if (entrytype == "user" || entrytype == "domain") && ace.ObjectType == nil {
					add(model.EdgeAllExtendedRights, inh)
				}
				if entrytype == "computer" && ace.ObjectType == nil {
					add(model.EdgeAllExtendedRights, inh)
				}
				if entrytype == "domain" && hasExtendedRight(ace, guidGetChanges) {
					add(model.EdgeGetChanges, inh)
				}
				if entrytype == "domain" && hasExtendedRight(ace, guidGetChangesAll) {
					add(model.EdgeGetChangesAll, inh)
				}
				if entrytype == "domain" && hasExtendedRight(ace, guidGetChangesInFilteredSet) {
					add(model.EdgeGetChangesInFilteredSet, inh)
				}
				if (entrytype == "user" || entrytype == "computer") && hasExtendedRight(ace, guidUserForceChangePassword) {
					add(model.EdgeForceChangePassword, inh)
				}
			}

		case aceTypeAccessAllowed:
			if hasMask(mask, maskGenericAll) {
				// GenericAll subsumes every other right on this object.
				add(model.EdgeGenericAll, inh)
				continue
			}
			if mask&maskDSWriteProp != 0 && aclWritableClass(entrytype) {
				add(model.EdgeGenericWrite, inh)
			}
			if mask&maskWriteOwner != 0 {
				add(model.EdgeWriteOwner, inh)
			}
			if (entrytype == "user" || entrytype == "domain") && mask&maskDSControlAccess != 0 {
				add(model.EdgeAllExtendedRights, inh)
			}
			if entrytype == "computer" && mask&maskDSControlAccess != 0 &&
				ace.SID != "S-1-5-32-544" && !strings.HasSuffix(ace.SID, "-512") {
				add(model.EdgeAllExtendedRights, inh)
			}
			if mask&maskWriteDACL != 0 {
				add(model.EdgeWriteDacl, inh)
			}
			if mask&maskDSSelf != 0 && ace.SID != "S-1-5-32-544" &&
				!strings.HasSuffix(ace.SID, "-512") && !strings.HasSuffix(ace.SID, "-519") &&
				entrytype == "group" {
				add(model.EdgeAddSelf, inh)
			}
		}
	}
	return out, st
}

// hasMask reports whether every bit in bits is set in mask, matching
// BloodHound.py's ACCESS_MASK.has_priv.
func hasMask(mask, bits uint32) bool { return mask&bits == bits }

// aclWritableClass lists the entry types that get a generic GenericWrite for a
// bare ADS_RIGHT_DS_WRITE_PROP ACE (i.e. one with no ObjectType restriction).
func aclWritableClass(entrytype string) bool {
	switch entrytype {
	case "user", "group", "computer", "gpo", "organizational-unit":
		return true
	}
	return false
}

// canWriteProperty mirrors BloodHound.py's can_write_property: WRITE_PROP with
// either no ObjectType (all properties) or the named property.
func canWriteProperty(ace ACE, want GUID) bool {
	if ace.Mask&maskDSWriteProp == 0 {
		return false
	}
	return ace.ObjectType == nil || *ace.ObjectType == want
}

// hasExtendedRight mirrors BloodHound.py's has_extended_right: CONTROL_ACCESS
// with either no ObjectType (all extended rights) or the named right.
func hasExtendedRight(ace ACE, want GUID) bool {
	if ace.Mask&maskDSControlAccess == 0 {
		return false
	}
	return ace.ObjectType == nil || *ace.ObjectType == want
}

// guidMatches reports whether an optional ACE GUID equals want. It requires the
// GUID to be present, matching BloodHound.py's explicit ACE_OBJECT_TYPE_PRESENT
// checks, and never matches the zero GUID.
func guidMatches(g *GUID, want GUID) bool {
	return g != nil && *g == want
}
