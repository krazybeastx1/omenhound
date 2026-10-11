package bloodhound

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/internal/ingest"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

// fixture is a minimal but representative BloodHound CE (`--zip`) collection.
var fixture = map[string]string{
	"bh_users.json": `{"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3-1103",
		 "Properties":{"name":"JDOE@CORP.LOCAL","domain":"CORP.LOCAL","samaccountname":"jdoe",
		   "distinguishedname":"CN=JDOE,OU=USERS,DC=CORP,DC=LOCAL","enabled":true,"admincount":1},
		 "PrimaryGroupSID":"S-1-5-21-1-2-3-513",
		 "MemberOf":[{"ObjectIdentifier":"S-1-5-21-1-2-3-513","ObjectType":"Group"}],
		 "Aces":[],"IsDeleted":false}],
		"meta":{"type":"users","count":1,"version":5}}`,
	"bh_groups.json": `{"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3-512",
		 "Properties":{"name":"DOMAIN ADMINS@CORP.LOCAL","domain":"CORP.LOCAL","highvalue":true},
		 "Members":[{"ObjectIdentifier":"S-1-5-21-1-2-3-1103","ObjectType":"User"}],
		 "Aces":[{"PrincipalSID":"S-1-5-21-1-2-3-1103","PrincipalType":"User","RightName":"GenericAll","IsInherited":false},
		         {"PrincipalSID":"S-1-5-21-1-2-3-1103","PrincipalType":"User","RightName":"BogusRight","IsInherited":false}],
		 "IsDeleted":false}],
		"meta":{"type":"groups","count":1,"version":5}}`,
	"bh_computers.json": `{"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3-1003",
		 "Properties":{"name":"WS01.CORP.LOCAL","domain":"CORP.LOCAL","samaccountname":"WS01$",
		   "distinguishedname":"CN=WS01,OU=WORKSTATIONS,DC=CORP,DC=LOCAL"},
		 "PrimaryGroupSID":"S-1-5-21-1-2-3-515",
		 "LocalAdmins":{"Collected":true,"Results":[{"ObjectIdentifier":"S-1-5-21-1-2-3-512","ObjectType":"Group"}]},
		 "RemoteDesktopUsers":{"Collected":true,"Results":[{"ObjectIdentifier":"S-1-5-21-1-2-3-1103","ObjectType":"User"}]},
		 "PSRemoteUsers":{"Collected":false,"Results":[]},
		 "DcomUsers":{"Collected":false,"Results":[]},
		 "Sessions":{"Collected":true,"Results":[{"ComputerSID":"S-1-5-21-1-2-3-1003","UserSID":"S-1-5-21-1-2-3-1103"}]},
		 "PrivilegedSessions":{"Collected":false,"Results":[]},
		 "RegistrySessions":{"Collected":false,"Results":[]},
		 "AllowedToDelegate":[],"AllowedToAct":[],"Aces":[],"IsDeleted":false}],
		"meta":{"type":"computers","count":1,"version":5}}`,
	"bh_ous.json": `{"data":[
		{"ObjectIdentifier":"11111111-2222-3333-4444-555555555555",
		 "Properties":{"name":"WORKSTATIONS@CORP.LOCAL","domain":"CORP.LOCAL",
		   "distinguishedname":"OU=WORKSTATIONS,DC=CORP,DC=LOCAL"},
		 "ChildObjects":[{"ObjectIdentifier":"S-1-5-21-1-2-3-1003","ObjectType":"Computer"}],
		 "Links":[{"GUID":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE","IsEnforced":true}],
		 "Aces":[],"IsDeleted":false}],
		"meta":{"type":"ous","count":1,"version":5}}`,
	"bh_gpos.json": `{"data":[
		{"ObjectIdentifier":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
		 "Properties":{"name":"DEFPOL@CORP.LOCAL","domain":"CORP.LOCAL",
		   "distinguishedname":"CN={AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE},CN=POLICIES,CN=SYSTEM,DC=CORP,DC=LOCAL"},
		 "Aces":[],"IsDeleted":false}],
		"meta":{"type":"gpos","count":1,"version":5}}`,
	"bh_domains.json": `{"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3",
		 "Properties":{"name":"CORP.LOCAL","domain":"CORP.LOCAL","distinguishedname":"DC=CORP,DC=LOCAL","highvalue":true},
		 "Trusts":[{"TargetDomainName":"CHILD.CORP.LOCAL","TargetDomainSid":"S-1-5-21-9-9-9",
		   "TrustDirection":2,"TrustType":2,"IsTransitive":true,"SidFilteringEnabled":true}],
		 "Aces":[],"IsDeleted":false}],
		"meta":{"type":"domains","count":1,"version":5}}`,
}

func writeZip(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "collection.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func edgeSet(g *model.Graph) map[string]bool {
	m := map[string]bool{}
	for _, e := range g.Edges {
		m[string(e.Kind)+"|"+e.Source+"|"+e.Target] = true
	}
	return m
}

func nodeByID(g *model.Graph, id string) (model.Node, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return model.Node{}, false
}

func TestImportCEZip(t *testing.T) {
	g, rpt, err := Load(writeZip(t, fixture))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rpt.Domain != "CORP.LOCAL" {
		t.Errorf("domain = %q, want CORP.LOCAL", rpt.Domain)
	}
	if rpt.Placeholders != 3 {
		t.Errorf("placeholders = %d, want 3 (513, 515, trust target)", rpt.Placeholders)
	}
	if rpt.UnknownRights["BogusRight"] != 1 {
		t.Errorf("unknown rights = %v, want BogusRight:1", rpt.UnknownRights)
	}
	if err := ingest.Validate(g); err != nil {
		t.Fatalf("imported graph failed validation: %v", err)
	}

	const (
		user   = "S-1-5-21-1-2-3-1103"
		admins = "S-1-5-21-1-2-3-512"
		pc     = "S-1-5-21-1-2-3-1003"
		ou     = "11111111-2222-3333-4444-555555555555"
		gpo    = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
		dom    = "S-1-5-21-1-2-3"
		child  = "S-1-5-21-9-9-9"
	)
	es := edgeSet(g)

	want := []string{
		"MemberOf|" + user + "|" + admins,             // group Members
		"MemberOf|" + pc + "|" + "S-1-5-21-1-2-3-515", // primary group
		"GenericAll|" + user + "|" + admins,           // ACE
		"AdminTo|" + admins + "|" + pc,                // LocalAdmins
		"CanRDP|" + user + "|" + pc,                   // RemoteDesktopUsers
		"HasSession|" + user + "|" + pc,               // Sessions
		"Contains|" + ou + "|" + pc,                   // OU contains computer
		"GPLink|" + gpo + "|" + ou,                    // GPO -> linked OU (BH CE direction)
		"TrustedBy|" + child + "|" + dom,              // outbound trust: child trusted by corp
	}
	for _, k := range want {
		if !es[k] {
			t.Errorf("missing edge %s", k)
		}
	}
	for k := range es {
		if len(k) >= 10 && k[:10] == "BogusRight" {
			t.Errorf("unmapped right name was fabricated as an edge: %s", k)
		}
	}

	// Placeholder kind inference.
	if n, ok := nodeByID(g, "S-1-5-21-1-2-3-513"); !ok || n.Kind != model.KindGroup {
		t.Errorf("primary group placeholder = %+v ok=%v, want Group", n, ok)
	}
	if n, ok := nodeByID(g, child); !ok || n.Kind != model.KindDomain {
		t.Errorf("trust target = %+v ok=%v, want Domain", n, ok)
	}
	if n, ok := nodeByID(g, admins); !ok || n.Kind != model.KindGroup || n.Props["highvalue"] != "true" {
		t.Errorf("admins node = %+v ok=%v", n, ok)
	}
	if n, ok := nodeByID(g, user); !ok || n.SAMAccountName != "jdoe" || n.Domain != "CORP.LOCAL" || n.Props["enabled"] != "true" {
		t.Errorf("user node = %+v ok=%v", n, ok)
	}
}

// TestImportCELocalGroups proves OmenHound reads BloodHound CE v5
// "LocalGroups" (the format bloodhound-ce-python emits), not just the legacy
// LocalAdmins/… fields: each well-known alias becomes member -> computer edges.
func TestImportCELocalGroups(t *testing.T) {
	const (
		pc  = "S-1-5-21-7-7-7-1004"
		grp = "S-1-5-21-7-7-7-512"
		usr = "S-1-5-21-7-7-7-1103"
	)
	files := map[string]string{
		"bh_computers.json": `{"data":[
		{"ObjectIdentifier":"` + pc + `",
		 "Properties":{"name":"WS02.CORP.LOCAL","samaccountname":"WS02$","domain":"CORP.LOCAL"},
		 "LocalGroups":[
		   {"ObjectIdentifier":"` + pc + `-544","Name":"ADMINISTRATORS@WS02","Collected":true,
		    "Results":[{"ObjectIdentifier":"` + grp + `","ObjectType":"Group"}]},
		   {"ObjectIdentifier":"` + pc + `-555","Name":"REMOTE DESKTOP USERS@WS02","Collected":true,
		    "Results":[{"ObjectIdentifier":"` + usr + `","ObjectType":"User"}]},
		   {"ObjectIdentifier":"` + pc + `-562","Name":"DISTRIBUTED COM USERS@WS02","Collected":false,
		    "Results":[{"ObjectIdentifier":"` + usr + `","ObjectType":"User"}]},
		   {"ObjectIdentifier":"` + pc + `-580","Name":"REMOTE MANAGEMENT USERS@WS02","Collected":true,
		    "Results":[{"ObjectIdentifier":"` + usr + `","ObjectType":"User"}]},
		   {"ObjectIdentifier":"` + pc + `-579","Name":"PERF MON USERS@WS02","Collected":true,
		    "Results":[{"ObjectIdentifier":"` + usr + `","ObjectType":"User"}]}
		 ],"Aces":[],"IsDeleted":false}],
		"meta":{"type":"computers","count":1,"version":5}}`,
	}
	g, _, err := Load(writeZip(t, files))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := ingest.Validate(g); err != nil {
		t.Fatalf("imported graph failed validation: %v", err)
	}
	es := edgeSet(g)
	for _, k := range []string{
		"AdminTo|" + grp + "|" + pc,     // 544
		"CanRDP|" + usr + "|" + pc,      // 555
		"CanPSRemote|" + usr + "|" + pc, // 580
	} {
		if !es[k] {
			t.Errorf("missing edge %s", k)
		}
	}
	if es["ExecuteDCOM|"+usr+"|"+pc] {
		t.Error("a LocalGroup with Collected=false must not produce an edge")
	}
	// Exactly the three collected, modelled aliases become edges: the
	// un-collected 562 and the unmodelled 579 must produce none.
	wantCounts := map[model.EdgeKind]int{
		model.EdgeAdminTo:     1,
		model.EdgeCanRDP:      1,
		model.EdgeCanPSRemote: 1,
		model.EdgeExecuteDCOM: 0,
	}
	for kind, want := range wantCounts {
		if got := edgeKindCount(g, kind); got != want {
			t.Errorf("%s edges = %d, want %d", kind, got, want)
		}
	}
	if n, ok := nodeByID(g, grp); !ok || n.Kind != model.KindGroup {
		t.Errorf("local-group member kind = %+v ok=%v, want Group", n, ok)
	}
	if n, ok := nodeByID(g, usr); !ok || n.Kind != model.KindUser {
		t.Errorf("local-group member kind = %+v ok=%v, want User", n, ok)
	}
}

func edgeKindCount(g *model.Graph, kind model.EdgeKind) int {
	n := 0
	for _, e := range g.Edges {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func TestImportEnforcedGPLinkProp(t *testing.T) {
	g, _, err := Load(writeZip(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range g.Edges {
		if e.Kind == model.EdgeGPLink {
			if e.Props["enforced"] != "true" {
				t.Fatalf("GPLink props = %v, want enforced=true", e.Props)
			}
			return
		}
	}
	t.Fatal("no GPLink edge found")
}

// TestImportClassifiesByMetaTypeIgnoringPrefix proves that the exact filename
// (which includes a timestamp/prefix in real BloodHound.py output) does not
// matter as long as meta.type is present.
func TestImportClassifiesByMetaTypeIgnoringPrefix(t *testing.T) {
	dir := t.TempDir()
	name := "bh_cascade.local_20260101120000_users.json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(fixture["bh_users.json"]), 0o600); err != nil {
		t.Fatal(err)
	}
	g, rpt, err := Load(dir)
	if err != nil {
		t.Fatalf("Load dir: %v", err)
	}
	if _, ok := nodeByID(g, "S-1-5-21-1-2-3-1103"); !ok {
		t.Fatalf("prefixed users file was not imported: %+v", rpt)
	}
}

func TestImportRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected an error for a malformed JSON file")
	}
}

func TestLoadMissingPath(t *testing.T) {
	if _, _, err := Load(filepath.Join(t.TempDir(), "nope.zip")); err == nil {
		t.Fatal("expected an error for a missing path")
	}
}

// TestExportCERoundTrip proves import -> export(CE zip) -> import is lossless
// for every node and edge in the fixture.
func TestExportCERoundTrip(t *testing.T) {
	g, _, err := Load(writeZip(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "out.zip")
	members, err := WriteCEZip(zipPath, g, "rt_")
	if err != nil {
		t.Fatalf("WriteCEZip: %v", err)
	}
	if len(members) == 0 {
		t.Fatal("no CE members written")
	}
	for _, m := range members {
		if !strings.HasPrefix(m, "rt_") {
			t.Errorf("member %q missing output prefix", m)
		}
	}

	g2, rpt2, err := Load(zipPath)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if err := ingest.Validate(g2); err != nil {
		t.Fatalf("round-trip graph invalid: %v", err)
	}

	ids1 := map[string]bool{}
	for _, n := range g.Nodes {
		ids1[n.ID] = true
	}
	ids2 := map[string]bool{}
	for _, n := range g2.Nodes {
		ids2[n.ID] = true
	}
	if len(ids1) != len(ids2) {
		t.Errorf("node count %d -> %d (%+v)", len(ids1), len(ids2), rpt2.Skipped)
	}
	for id := range ids1 {
		if !ids2[id] {
			t.Errorf("lost node %s", id)
		}
	}

	e1, e2 := edgeSet(g), edgeSet(g2)
	if len(e1) != len(e2) {
		t.Errorf("edge count %d -> %d", len(e1), len(e2))
	}
	for k := range e1 {
		if !e2[k] {
			t.Errorf("lost edge %s", k)
		}
	}
	for k := range e2 {
		if !e1[k] {
			t.Errorf("extra edge %s", k)
		}
	}
}
