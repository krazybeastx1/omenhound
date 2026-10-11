package collector

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/dcerpc/mslsad"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

func TestSkipSession(t *testing.T) {
	const self = "CORP\\svc_collect"
	cases := []struct {
		name   string
		user   string
		source string
		want   bool
	}{
		{"normal", "alice", "\\\\WORKSTATION1", false},
		{"empty user", "", "\\\\W", true},
		{"empty source", "alice", "", true},
		{"whitespace source", "alice", "   ", true},
		{"self full", "CORP\\svc_collect", "\\\\W", true},
		{"self bare", "svc_collect", "\\\\W", true},
		{"self case-insensitive", "SVC_COLLECT", "\\\\W", true},
		{"machine account", "DC01$", "\\\\W", true},
		{"loopback v4", "alice", "127.0.0.1", true},
		{"loopback v6", "alice", "[::1]", true},
		{"loopback v6 bare", "alice", "::1", true},
		{"hostname source", "alice", "WORKSTATION1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := skipSession(tc.user, tc.source, self); got != tc.want {
				t.Fatalf("skipSession(%q, %q) = %v, want %v", tc.user, tc.source, got, tc.want)
			}
		})
	}
}

func TestIsLocalSID(t *testing.T) {
	const machine = "S-1-5-21-1-2-3"
	if !isLocalSID(machine+"-500", machine) {
		t.Fatal("a SID below the machine SID must be local")
	}
	if isLocalSID("S-1-5-21-9-8-7-1105", machine) {
		t.Fatal("a SID from another domain must not be local")
	}
	if isLocalSID("S-1-5-32-544", "") {
		t.Fatal("an empty prefix must keep every member (BloodHound.py UNKNOWN case)")
	}
}

func TestLsaKind(t *testing.T) {
	cases := map[mslsad.SidNameUse]model.Kind{
		mslsad.SidTypeUser:           model.KindUser,
		mslsad.SidTypeGroup:          model.KindGroup,
		mslsad.SidTypeAlias:          model.KindGroup,
		mslsad.SidTypeComputer:       model.KindComputer,
		mslsad.SidTypeDomain:         model.KindDomain,
		mslsad.SidTypeWellKnownGroup: model.KindBase,
		mslsad.SidTypeUnknown:        model.KindBase,
	}
	for use, want := range cases {
		if got := lsaKind(use); got != want {
			t.Errorf("lsaKind(%d) = %s, want %s", use, got, want)
		}
	}
}

func TestNodeFromLSA(t *testing.T) {
	n := nodeFromLSA("S-1-5-21-9-8-7-1105", lsaName{name: "alice", domain: "CORP", use: mslsad.SidTypeUser}, "corp.local")
	if n.ID != "S-1-5-21-9-8-7-1105" || n.Kind != model.KindUser || n.Name != "alice" || n.Domain != "CORP" {
		t.Fatalf("unexpected user node: %+v", n)
	}
	if n.Props["lsaresolved"] != "true" {
		t.Fatalf("missing lsaresolved prop: %+v", n.Props)
	}

	// Computer names lose their trailing $. The domain falls back when lsarpc
	// did not name one.
	c := nodeFromLSA("S-1-5-21-9-8-7-1106", lsaName{name: "WKSTA1$", use: mslsad.SidTypeComputer}, "corp.local")
	if c.Kind != model.KindComputer || c.Name != "WKSTA1" || c.Domain != "corp.local" {
		t.Fatalf("unexpected computer node: %+v", c)
	}
}

func TestHostOfNode(t *testing.T) {
	with := model.Node{ID: "x", Props: map[string]string{"dnshostname": "host1.corp.local"}}
	if got := hostOfNode(with); got != "host1.corp.local" {
		t.Fatalf("hostOfNode = %q", got)
	}
	if got := hostOfNode(model.Node{ID: "y"}); got != "" {
		t.Fatalf("hostOfNode without prop = %q, want empty", got)
	}
}

func TestBareUser(t *testing.T) {
	cases := map[string]string{
		"CORP\\alice":      "alice",
		"alice@corp.local": "alice",
		"alice":            "alice",
		"":                 "",
	}
	for in, want := range cases {
		if got := bareUser(in); got != want {
			t.Errorf("bareUser(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripNUL(t *testing.T) {
	if got := stripNUL("alice\x00"); got != "alice" {
		t.Fatalf("stripNUL = %q", got)
	}
	if got := stripNUL("alice"); got != "alice" {
		t.Fatalf("stripNUL = %q", got)
	}
}

func TestSMBAnyRequested(t *testing.T) {
	cases := []struct {
		methods []string
		want    bool
	}{
		{nil, false},
		{[]string{"group", "objectprops"}, false},
		{[]string{"acl"}, false},
		{[]string{"session"}, true},
		{[]string{"localadmin"}, true},
		{[]string{"rdp"}, true},
		{[]string{"dcom"}, true},
		{[]string{"psremote"}, true},
		{[]string{"loggedon"}, true},
		{[]string{"group", "session"}, true},
	}
	for _, tc := range cases {
		o := Options{Methods: &MethodPlan{Implemented: tc.methods}}
		if got := smbAnyRequested(o); got != tc.want {
			t.Errorf("smbAnyRequested(%v) = %v, want %v", tc.methods, got, tc.want)
		}
	}
	// The legacy flag implies sessions even with no plan.
	if !smbAnyRequested(Options{IncludeSessions: true}) {
		t.Fatal("IncludeSessions must imply an SMB pass")
	}
}

func TestSmbStatsAdd(t *testing.T) {
	a := smbStats{queried: 1, sessions: 2, unreachable: 1}
	b := smbStats{queried: 3, members: 4, rpcErrors: 1, dcSkipped: 2}
	got := a.add(b)
	want := smbStats{queried: 4, sessions: 2, members: 4, unreachable: 1, rpcErrors: 1, dcSkipped: 2}
	if got != want {
		t.Fatalf("add = %+v, want %+v", got, want)
	}
}

func TestIsDomainController(t *testing.T) {
	cases := []struct {
		pg   string
		want bool
	}{
		{"516", true},
		{" 516 ", true},
		{"515", false},                // Domain Computers
		{"", false},                   // unknown -> collect (never over-skip)
		{"S-1-5-21-1-2-3-516", false}, // a full SID is not a bare RID
	}
	for _, c := range cases {
		n := model.Node{Kind: model.KindComputer, Props: map[string]string{}}
		if c.pg != "" {
			n.Props["primarygroupid"] = c.pg
		}
		if got := isDomainController(n); got != c.want {
			t.Errorf("isDomainController(primarygroupid=%q) = %v, want %v", c.pg, got, c.want)
		}
	}
	// A node with no Props map must not panic.
	if isDomainController(model.Node{Kind: model.KindComputer}) {
		t.Error("isDomainController(no props) = true, want false")
	}
}

func TestLocalGroupRIDs(t *testing.T) {
	all := localGroupRIDs(Options{Methods: &MethodPlan{Implemented: []string{"localadmin", "rdp", "dcom", "psremote"}}})
	if !reflect.DeepEqual(all, []uint32{544, 555, 562, 580}) {
		t.Fatalf("localGroupRIDs(all) = %v", all)
	}
	if got := localGroupRIDs(Options{Methods: &MethodPlan{Implemented: []string{"session"}}}); got != nil {
		t.Fatalf("localGroupRIDs(session only) = %v, want nil", got)
	}
	if got := localGroupRIDs(Options{}); got != nil {
		t.Fatalf("localGroupRIDs(nil plan) = %v, want nil", got)
	}
}

// newTestIndex builds a two-node graph (one user, one computer) and the index
// over it.
func newTestIndex(t *testing.T) *sidIndex {
	t.Helper()
	g := &model.Graph{}
	g.AddNode(model.Node{ID: "S-1-5-21-9-8-7-1105", Kind: model.KindUser, Name: "Alice", SAMAccountName: "alice", Domain: "corp.local"})
	g.AddNode(model.Node{ID: "S-1-5-21-9-8-7-1106", Kind: model.KindComputer, Name: "HOST1", SAMAccountName: "HOST1$", Domain: "corp.local",
		Props: map[string]string{"dnshostname": "host1.corp.local"}})
	return newSIDIndex(g, "corp.local")
}

func TestSIDIndexUserSID(t *testing.T) {
	ix := newTestIndex(t)
	for _, in := range []string{"alice", "ALICE", "CORP\\alice", "corp\\ALICE"} {
		id, ok := ix.userSID(in)
		if !ok || id != "S-1-5-21-9-8-7-1105" {
			t.Fatalf("userSID(%q) = %q, %v", in, id, ok)
		}
	}
	if _, ok := ix.userSID("bob"); ok {
		t.Fatal("userSID resolved an account that is not in the graph")
	}
}

func TestSIDIndexSourceSID(t *testing.T) {
	ix := newTestIndex(t)

	// The index must be restored after the test, whatever happens.
	orig := ptrLookup
	defer func() { ptrLookup = orig }()

	// A bare \\HOST resolves directly (indexed short name), and the FQDN also
	// resolves.
	for _, in := range []string{"\\\\HOST1", "host1.corp.local", "HOST1.CORP.LOCAL"} {
		id, ok := ix.sourceSID(in, "corp.local")
		if !ok || id != "S-1-5-21-9-8-7-1106" {
			t.Fatalf("sourceSID(%q) = %q, %v", in, id, ok)
		}
	}

	// A bare name with no dot gets the search domain appended.
	if id, ok := ix.sourceSID("host1", "corp.local"); !ok || id != "S-1-5-21-9-8-7-1106" {
		t.Fatalf("sourceSID(host1) = %q, %v", id, ok)
	}

	// An address is reverse-resolved.
	ptrLookup = func(ip net.IP) []string { return []string{"host1.corp.local."} }
	if id, ok := ix.sourceSID("10.0.0.5", "corp.local"); !ok || id != "S-1-5-21-9-8-7-1106" {
		t.Fatalf("sourceSID(10.0.0.5) = %q, %v", id, ok)
	}

	// Loopback, IPv6, and unresolvable addresses never resolve.
	ptrLookup = func(ip net.IP) []string { return nil }
	for _, in := range []string{"127.0.0.1", "::1", "[::1]", "10.0.0.9", ""} {
		if id, ok := ix.sourceSID(in, "corp.local"); ok {
			t.Fatalf("sourceSID(%q) = %q, want unresolved", in, id)
		}
	}
}

func TestSIDIndexRecordUpgradesSeen(t *testing.T) {
	g := &model.Graph{}
	ix := newSIDIndex(g, "corp.local")
	if ix.has("S-1-5-21-9-8-7-1105") {
		t.Fatal("index must start empty")
	}
	ix.record(model.Node{ID: "S-1-5-21-9-8-7-1105", Kind: model.KindUser, SAMAccountName: "bob"})
	if !ix.has("S-1-5-21-9-8-7-1105") {
		t.Fatal("record must mark the node as seen")
	}
	if id, ok := ix.userSID("bob"); !ok || id != "S-1-5-21-9-8-7-1105" {
		t.Fatalf("record did not index the SAM name: %q %v", id, ok)
	}
}

func TestCollectSMBNoneRequested(t *testing.T) {
	g := &model.Graph{}
	if err := collectSMB(context.Background(), g, Options{}); err != nil {
		t.Fatalf("collectSMB with no methods = %v", err)
	}
	if len(g.Meta.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", g.Meta.Warnings)
	}
}

func TestCollectSMBWithoutCredentialsWarns(t *testing.T) {
	g := &model.Graph{}
	g.AddNode(model.Node{ID: "c1", Kind: model.KindComputer, Name: "HOST1", Props: map[string]string{"dnshostname": "host1.corp.local"}})
	o := Options{Methods: &MethodPlan{Implemented: []string{"session"}}}
	if err := collectSMB(context.Background(), g, o); err != nil {
		t.Fatalf("collectSMB = %v", err)
	}
	if len(g.Meta.Warnings) == 0 || !strings.Contains(g.Meta.Warnings[0], "no password or hash") {
		t.Fatalf("expected a no-credential warning, got %v", g.Meta.Warnings)
	}
	if len(g.Edges) != 0 {
		t.Fatalf("no edges must be produced without credentials: %v", g.Edges)
	}
}

func TestCollectSMBNoTargetsWarnsOnMissingHostname(t *testing.T) {
	// Credentials are present so the pass proceeds to target selection, but the
	// only computer has no dNSHostName and nothing must be dialled.
	g := &model.Graph{}
	g.AddNode(model.Node{ID: "c1", Kind: model.KindComputer, Name: "HOST1"})
	o := Options{Password: []byte("pw"), Methods: &MethodPlan{Implemented: []string{"session"}}}
	if err := collectSMB(context.Background(), g, o); err != nil {
		t.Fatalf("collectSMB = %v", err)
	}
	joined := strings.Join(g.Meta.Warnings, " | ")
	if !strings.Contains(joined, "no dNSHostName") {
		t.Fatalf("expected a missing-hostname warning, got %v", g.Meta.Warnings)
	}
	if len(g.Edges) != 0 {
		t.Fatalf("no edges must be produced: %v", g.Edges)
	}
}

func TestCollectSMBUnreachableHostIsCounted(t *testing.T) {
	// A deterministic, local-only integration test of the pass wiring: the host
	// resolves to 127.0.0.1, whose 445/tcp is closed here, so dialHost must fail
	// at the TCP probe. Skip if something really is listening on 445 (a local
	// SMB server), because then the negotiation path would be exercised instead
	// and the assertion below would not hold.
	if c, err := net.DialTimeout("tcp", "127.0.0.1:445", 200*time.Millisecond); err == nil {
		c.Close()
		t.Skip("a local SMB listener is present on 127.0.0.1:445; skipping")
	}
	g := &model.Graph{}
	g.AddNode(model.Node{ID: "S-1-5-21-9-8-7-1106", Kind: model.KindComputer, Name: "HOST1",
		SAMAccountName: "HOST1$", Domain: "corp.local",
		Props: map[string]string{"dnshostname": "127.0.0.1"}})
	o := Options{
		Domain:   "corp.local",
		Username: `CORP\svc`,
		Password: []byte("pw"),
		Methods:  &MethodPlan{Implemented: []string{"session", "localadmin"}},
	}
	if err := collectSMB(context.Background(), g, o); err != nil {
		t.Fatalf("collectSMB = %v", err)
	}
	joined := strings.Join(g.Meta.Warnings, " | ")
	if !strings.Contains(joined, "1 unreachable") {
		t.Fatalf("expected the host to be counted unreachable, warnings: %s", joined)
	}
	if !strings.Contains(joined, "0 of 1 computers queried") {
		t.Fatalf("expected 0 of 1 computers queried, warnings: %s", joined)
	}
	if len(g.Edges) != 0 {
		t.Fatalf("no edges must be produced by an unreachable host: %v", g.Edges)
	}
}

func TestSmbGroupMethodTable(t *testing.T) {
	want := []struct {
		method string
		rid    uint32
		edge   model.EdgeKind
	}{
		{"localadmin", 544, model.EdgeAdminTo},
		{"rdp", 555, model.EdgeCanRDP},
		{"dcom", 562, model.EdgeExecuteDCOM},
		{"psremote", 580, model.EdgeCanPSRemote},
	}
	if len(smbGroupMethod) != len(want) {
		t.Fatalf("smbGroupMethod has %d entries, want %d", len(smbGroupMethod), len(want))
	}
	for i, w := range want {
		got := smbGroupMethod[i]
		if got.method != w.method || got.rid != w.rid || got.edge != w.edge {
			t.Fatalf("smbGroupMethod[%d] = %+v, want %+v", i, got, w)
		}
	}
}

func TestDedupeUnknownMethodsPlanKeepsOrder(t *testing.T) {
	p, err := PlanMethods("session,localadmin,session")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Implemented, []string{"session", "localadmin"}) {
		t.Fatalf("implemented = %v", p.Implemented)
	}
}
