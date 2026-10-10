package bloodhound

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// kindToRight is the canonical BloodHound CE ACE right name for an edge kind.
// It is the inverse of rightToKind (which additionally accepts legacy aliases).
var kindToRight = map[model.EdgeKind]string{
	model.EdgeGenericAll:                 "GenericAll",
	model.EdgeGenericWrite:               "GenericWrite",
	model.EdgeWriteDacl:                  "WriteDacl",
	model.EdgeWriteOwner:                 "WriteOwner",
	model.EdgeOwns:                       "Owns",
	model.EdgeForceChangePassword:        "ForceChangePassword",
	model.EdgeAddMember:                  "AddMember",
	model.EdgeAddSelf:                    "AddSelf",
	model.EdgeAllExtendedRights:          "AllExtendedRights",
	model.EdgeAddKeyCredentialLink:       "AddKeyCredentialLink",
	model.EdgeAddAllowedToAct:            "AddAllowedToAct",
	model.EdgeWriteSPN:                   "WriteSPN",
	model.EdgeWriteAccountRestrictions:   "WriteAccountRestrictions",
	model.EdgeWriteGPLink:                "WriteGPLink",
	model.EdgeWriteAltSecurityIdentities: "WriteAltSecurityIdentities",
	model.EdgeGetChanges:                 "GetChanges",
	model.EdgeGetChangesAll:              "GetChangesAll",
	model.EdgeGetChangesInFilteredSet:    "GetChangesInFilteredSet",
	model.EdgeDCSync:                     "DCSync",
	model.EdgeReadLAPSPassword:           "ReadLAPSPassword",
	model.EdgeReadGMSAPassword:           "ReadGMSAPassword",
	model.EdgeDumpSMSAPassword:           "DumpSMSAPassword",
}

var boolProps = map[string]bool{
	"enabled": true, "highvalue": true, "admincount": true, "haslaps": true,
	"unconstraineddelegation": true, "trustedtoauth": true, "dontreqpreauth": true,
	"pwdneverexpires": true, "sensitive": true, "isaclprotected": true,
	"blocksinheritance": true,
}

func objectType(k model.Kind) string {
	switch k {
	case model.KindUser:
		return "User"
	case model.KindGroup:
		return "Group"
	case model.KindComputer:
		return "Computer"
	case model.KindOU:
		return "OU"
	case model.KindGPO:
		return "GPO"
	case model.KindContainer:
		return "Container"
	case model.KindDomain:
		return "Domain"
	}
	return "Base"
}

func ceFileName(k model.Kind) string {
	switch k {
	case model.KindUser:
		return "users"
	case model.KindGroup:
		return "groups"
	case model.KindComputer:
		return "computers"
	case model.KindOU:
		return "ous"
	case model.KindGPO:
		return "gpos"
	case model.KindContainer:
		return "containers"
	case model.KindDomain:
		return "domains"
	}
	return ""
}

// ExportCE converts an OmenHound graph into BloodHound CE v5 JSON files
// (users/groups/computers/ous/gpos/containers/domains). Placeholder "Base"
// nodes and their edges cannot be represented in CE output and are dropped; the
// second return value counts them.
func ExportCE(g *model.Graph) (map[string][]byte, int, error) {
	if g == nil {
		return nil, 0, fmt.Errorf("bloodhound: nil graph")
	}

	byKind := map[model.Kind][]model.Node{}
	nodeKind := map[string]model.Kind{}
	nodeName := map[string]string{}
	base := map[string]bool{}
	for _, n := range g.Nodes {
		nodeKind[n.ID] = n.Kind
		nodeName[n.ID] = n.Name
		if n.Kind == model.KindBase {
			base[n.ID] = true
			continue
		}
		byKind[n.Kind] = append(byKind[n.Kind], n)
	}

	out := map[string][]model.Edge{}
	in := map[string][]model.Edge{}
	dropped := 0
	for _, e := range g.Edges {
		if base[e.Source] || base[e.Target] {
			dropped++
			continue
		}
		out[e.Source] = append(out[e.Source], e)
		in[e.Target] = append(in[e.Target], e)
	}

	domainsid := ""
	domainName := ""
	for _, n := range byKind[model.KindDomain] {
		domainsid = n.ID
		domainName = n.Domain
		break
	}

	files := map[string][]byte{}
	for kind, nodes := range byKind {
		name := ceFileName(kind)
		if name == "" {
			continue
		}
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		if domainName == "" && kind == model.KindDomain {
			domainName = nodes[0].Domain
		}
		entries := make([]bhEntry, 0, len(nodes))
		for _, n := range nodes {
			entries = append(entries, buildEntry(n, kind, domainsid, in[n.ID], out[n.ID], nodeKind, nodeName))
		}
		blob, err := marshalFile(name, entries)
		if err != nil {
			return nil, dropped, err
		}
		files[name+".json"] = blob
	}
	return files, dropped, nil
}

func buildEntry(n model.Node, kind model.Kind, domainsid string, inEdges, outEdges []model.Edge, nodeKind map[string]model.Kind, nodeName map[string]string) bhEntry {
	e := bhEntry{ObjectIdentifier: n.ID, Properties: exportProperties(n, domainsid)}

	for _, ed := range inEdges {
		if rn, ok := kindToRight[ed.Kind]; ok {
			e.Aces = append(e.Aces, bhAce{
				PrincipalSID:  ed.Source,
				PrincipalType: objectType(nodeKind[ed.Source]),
				RightName:     rn,
				IsInherited:   ed.Props["inherited"] == "true",
			})
		}
	}

	switch kind {
	case model.KindGroup:
		for _, ed := range inEdges {
			if ed.Kind == model.EdgeMemberOf {
				e.Members = append(e.Members, bhLink{ObjectIdentifier: ed.Source, ObjectType: objectType(nodeKind[ed.Source])})
			}
		}
	case model.KindUser:
		for _, ed := range outEdges {
			if ed.Kind == model.EdgeMemberOf {
				e.MemberOf = append(e.MemberOf, bhLink{ObjectIdentifier: ed.Target, ObjectType: objectType(nodeKind[ed.Target])})
			}
		}
	case model.KindComputer:
		for _, ed := range outEdges {
			switch ed.Kind {
			case model.EdgeMemberOf:
				e.MemberOf = append(e.MemberOf, bhLink{ObjectIdentifier: ed.Target, ObjectType: objectType(nodeKind[ed.Target])})
			case model.EdgeAllowedToDelegate:
				e.AllowedToDelegate = append(e.AllowedToDelegate, bhLink{ObjectIdentifier: ed.Target, ObjectType: objectType(nodeKind[ed.Target])})
			}
		}
		for _, ed := range inEdges {
			link := bhLink{ObjectIdentifier: ed.Source, ObjectType: objectType(nodeKind[ed.Source])}
			switch ed.Kind {
			case model.EdgeAdminTo:
				e.LocalAdmins = appendResult(e.LocalAdmins, link, true)
			case model.EdgeCanRDP:
				e.RemoteDesktopUsers = appendResult(e.RemoteDesktopUsers, link, true)
			case model.EdgeExecuteDCOM:
				e.DcomUsers = appendResult(e.DcomUsers, link, true)
			case model.EdgeCanPSRemote:
				e.PSRemoteUsers = appendResult(e.PSRemoteUsers, link, true)
			case model.EdgeHasSession:
				e.Sessions = appendSession(e.Sessions, bhResult{ComputerSID: n.ID, UserSID: ed.Source})
			case model.EdgeAllowedToAct:
				e.AllowedToAct = append(e.AllowedToAct, link)
			}
		}
	case model.KindOU, model.KindContainer, model.KindDomain:
		for _, ed := range outEdges {
			if ed.Kind == model.EdgeContains {
				e.ChildObjects = append(e.ChildObjects, bhLink{ObjectIdentifier: ed.Target, ObjectType: objectType(nodeKind[ed.Target])})
			}
		}
		for _, ed := range inEdges {
			if ed.Kind == model.EdgeGPLink {
				e.Links = append(e.Links, bhGPLink{GUID: ed.Source, IsEnforced: ed.Props["enforced"] == "true"})
			}
		}
		if kind == model.KindDomain {
			for _, ed := range inEdges {
				if ed.Kind == model.EdgeTrustedBy {
					e.Trusts = append(e.Trusts, bhTrust{
						TargetDomainName: strings.ToUpper(nodeName[ed.Source]),
						TargetDomainSid:  ed.Source,
						TrustDirection:   2, // this domain trusts the source
					})
				}
			}
			for _, ed := range outEdges {
				if ed.Kind == model.EdgeTrustedBy {
					e.Trusts = append(e.Trusts, bhTrust{
						TargetDomainName: strings.ToUpper(nodeName[ed.Target]),
						TargetDomainSid:  ed.Target,
						TrustDirection:   1, // the target trusts this domain
					})
				}
			}
		}
	}
	return e
}

func appendResult(c *bhCollected, link bhLink, collected bool) *bhCollected {
	if c == nil {
		c = &bhCollected{Collected: collected}
	}
	c.Results = append(c.Results, bhResult{ObjectIdentifier: link.ObjectIdentifier, ObjectType: link.ObjectType})
	return c
}

func appendSession(c *bhCollected, r bhResult) *bhCollected {
	if c == nil {
		c = &bhCollected{Collected: true}
	}
	c.Results = append(c.Results, r)
	return c
}

func exportProperties(n model.Node, domainsid string) map[string]any {
	p := map[string]any{}
	for k, v := range n.Props {
		if boolProps[k] {
			p[k] = v == "true"
			continue
		}
		p[k] = v
	}
	if n.Name != "" {
		p["name"] = n.Name
	}
	if n.Domain != "" {
		p["domain"] = n.Domain
	}
	if n.SAMAccountName != "" {
		p["samaccountname"] = n.SAMAccountName
	}
	if n.DN != "" {
		p["distinguishedname"] = n.DN
	}
	if domainsid != "" {
		p["domainsid"] = domainsid
	}
	return p
}

func marshalFile(kind string, entries []bhEntry) ([]byte, error) {
	wrapper := struct {
		Data []bhEntry `json:"data"`
		Meta struct {
			Type    string `json:"type"`
			Count   int    `json:"count"`
			Version int    `json:"version"`
		} `json:"meta"`
	}{Data: entries}
	wrapper.Meta.Type = kind
	wrapper.Meta.Count = len(entries)
	wrapper.Meta.Version = 5
	return json.MarshalIndent(wrapper, "", "  ")
}

// WriteCEZip writes a BloodHound CE v5 archive for g to path and returns the
// archive members. prefix is prepended to each member name (BloodHound.py's
// --outputprefix).
func WriteCEZip(path string, g *model.Graph, prefix string) ([]string, error) {
	files, _, err := ExportCE(g)
	if err != nil {
		return nil, err
	}
	// Deterministic member order.
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("bloodhound: create %s: %w", path, err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, name := range names {
		w, err := zw.Create(prefix + name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(files[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	for i := range names {
		names[i] = prefix + names[i]
	}
	return names, nil
}
