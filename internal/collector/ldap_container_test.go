package collector

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// ldapEntry builds an ldap.Entry the way the client returns search results: the
// typed value and the raw bytes are both populated.
func ldapEntry(dn string, attrs map[string]string) *ldap.Entry {
	e := &ldap.Entry{DN: dn}
	for k, v := range attrs {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{
			Name:       k,
			Values:     []string{v},
			ByteValues: [][]byte{[]byte(v)},
		})
	}
	return e
}

func TestParseGPLink(t *testing.T) {
	const gpoA = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local"
	const gpoB = "CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local"

	t.Run("empty", func(t *testing.T) {
		if got := parseGPLink(""); len(got) != 0 {
			t.Fatalf("parseGPLink(\"\") = %v, want none", got)
		}
	})

	t.Run("single enabled", func(t *testing.T) {
		got := parseGPLink("[LDAP://" + gpoA + ";0]")
		if len(got) != 1 || got[0].option != 0 || got[0].dn != gpoA {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("multiple with option and trailing bracket", func(t *testing.T) {
		got := parseGPLink("[LDAP://" + gpoB + ";2][LDAP://" + gpoA + ";0]")
		if len(got) != 2 {
			t.Fatalf("got %d links, want 2: %+v", len(got), got)
		}
		if got[0].option != 2 || got[1].option != 0 {
			t.Fatalf("options = %d,%d want 2,0", got[0].option, got[1].option)
		}
		if got[0].dn != gpoB || got[1].dn != gpoA {
			t.Fatalf("dns = %q,%q", got[0].dn, got[1].dn)
		}
	})

	t.Run("malformed segments are skipped", func(t *testing.T) {
		got := parseGPLink("[LDAP://" + gpoA + "][LDAP://garbage;x][LDAP://" + gpoB + ";1]")
		if len(got) != 1 || got[0].option != 1 {
			t.Fatalf("got %+v, want the single ;1 link", got)
		}
	})
}

func TestGPOIDFromDN(t *testing.T) {
	id, ok := gpoIDFromDN("CN={31b2f340-016d-11d2-945f-00c04fb984f9},CN=Policies,CN=System,DC=corp,DC=local")
	if !ok || id != "31B2F340-016D-11D2-945F-00C04FB984F9" {
		t.Fatalf("gpoIDFromDN = %q,%v", id, ok)
	}
	for _, bad := range []string{"CN=Policies,CN=System,DC=corp,DC=local", "CN={not-a-guid},CN=Policies", "CN={31b2f340-016d-11d2-945f-00c04fb984f9"} {
		if got, ok := gpoIDFromDN(bad); ok {
			t.Errorf("gpoIDFromDN(%q) = %q, want failure", bad, got)
		}
	}
}

func TestIsFilteredContainer(t *testing.T) {
	filtered := []string{
		"CN=DomainUpdates,CN=System,DC=corp,DC=local",
		"CN=User,CN=Policies,CN=System,DC=corp,DC=local",
		"CN=Machine,CN={GUID},CN=Policies,CN=System,DC=corp,DC=local",
	}
	for _, dn := range filtered {
		if !isFilteredContainer(dn) {
			t.Errorf("isFilteredContainer(%q) = false, want true", dn)
		}
	}
	kept := []string{
		"CN=Users,DC=corp,DC=local",
		"CN=System,DC=corp,DC=local", // the System container itself is kept
		"CN=Policies,CN=System,DC=corp,DC=local",
	}
	for _, dn := range kept {
		if isFilteredContainer(dn) {
			t.Errorf("isFilteredContainer(%q) = true, want false", dn)
		}
	}
}

func TestIsFilteredContainerChild(t *testing.T) {
	if !isFilteredContainerChild("CN=System,DC=corp,DC=local") {
		t.Error("CN=System should be filtered")
	}
	if !isFilteredContainerChild("CN=Program Data,DC=corp,DC=local") {
		t.Error("Program Data should be filtered")
	}
	if isFilteredContainerChild("CN=Workstations,DC=corp,DC=local") {
		t.Error("an ordinary OU should not be filtered")
	}
}

func TestObjectKindFromClasses(t *testing.T) {
	cases := []struct {
		classes []string
		samType string
		want    model.Kind
	}{
		{[]string{"top", "organizationalUnit"}, "", model.KindOU},
		{[]string{"top", "container"}, "", model.KindContainer},
		{[]string{"top", "group"}, "", model.KindGroup},
		{[]string{"top", "person", "organizationalPerson", "user", "computer"}, "", model.KindComputer},
		{[]string{"top", "person", "organizationalPerson", "user"}, "", model.KindUser},
		// No usable class, but a machine sAMAccountType.
		{[]string{"top"}, "805306369", model.KindComputer},
		{[]string{"top", "foreignSecurityPrincipal"}, "", model.KindBase},
	}
	for _, tc := range cases {
		if got := objectKindFromClasses(tc.classes, tc.samType); got != tc.want {
			t.Errorf("objectKindFromClasses(%v, %q) = %s, want %s", tc.classes, tc.samType, got, tc.want)
		}
	}
}

func TestUpsertNodeMerges(t *testing.T) {
	g := &model.Graph{}
	index := g.NodeIndex()

	// A container pass creates the node...
	upsertNode(g, index, model.Node{ID: "ID1", Kind: model.KindOU, Name: "Servers", Domain: "corp.local",
		DN: "OU=Servers,DC=corp,DC=local", Props: map[string]string{"highvalue": "false"}})
	// ...then a Base placeholder arrives first for an unknown SID peer.
	upsertNode(g, index, model.Node{ID: "S-1-5-21-9-9-9", Kind: model.KindBase, Name: "S-1-5-21-9-9-9"})
	upsertNode(g, index, model.Node{ID: "S-1-5-21-9-9-9", Kind: model.KindUser, Name: "jdoe"})
	// ...and finally the ACL pass merges a property into the OU.
	upsertNode(g, index, model.Node{ID: "ID1", Name: "ignored", Props: map[string]string{"isaclprotected": "true"}})

	if len(g.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(g.Nodes))
	}
	by := g.NodeIndex()
	ou := by["ID1"]
	if ou.Name != "Servers" {
		t.Errorf("Name = %q, want the first writer's %q", ou.Name, "Servers")
	}
	if ou.Kind != model.KindOU {
		t.Errorf("Kind = %s, want OU", ou.Kind)
	}
	if ou.Props["highvalue"] != "false" || ou.Props["isaclprotected"] != "true" {
		t.Errorf("props = %v, want both merged", ou.Props)
	}
	peer := by["S-1-5-21-9-9-9"]
	if peer.Kind != model.KindUser {
		t.Errorf("placeholder Kind = %s, want the upgrade to User", peer.Kind)
	}
	if peer.Name != "S-1-5-21-9-9-9" {
		t.Errorf("placeholder Name = %q, want the first (SID) writer", peer.Name)
	}
}

func TestGuidOfIsCanonicalUppercase(t *testing.T) {
	// objectGUID is little-endian on the wire: 31b2f340-016d-11d2-945f-00c04fb984f9.
	raw := []byte{0x40, 0xf3, 0xb2, 0x31, 0x6d, 0x01, 0xd2, 0x11, 0x94, 0x5f, 0x00, 0xc0, 0x4f, 0xb9, 0x84, 0xf9}
	e := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "objectGUID", ByteValues: [][]byte{raw}}}}
	if got := guidOf(e); got != "31B2F340-016D-11D2-945F-00C04FB984F9" {
		t.Fatalf("guidOf = %q", got)
	}
	if got := guidOf(&ldap.Entry{}); got != "" {
		t.Fatalf("guidOf(empty) = %q, want \"\"", got)
	}
	if got := guidOf(&ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "objectGUID", ByteValues: [][]byte{{1, 2, 3}}}}}); got != "" {
		t.Fatalf("guidOf(short) = %q, want \"\"", got)
	}
}

func TestAttrIsCaseInsensitive(t *testing.T) {
	e := ldapEntry("OU=x,DC=corp,DC=local", map[string]string{"gPLink": "[LDAP://x;0]", "gPOptions": "1"})
	if got := attr(e, "gplink"); got != "[LDAP://x;0]" {
		t.Errorf("attr(gplink) = %q", got)
	}
	if got := attr(e, "gPOptions"); !strings.EqualFold(got, "1") {
		t.Errorf("attr(gPOptions) = %q", got)
	}
	if got := attr(e, "missing"); got != "" {
		t.Errorf("attr(missing) = %q, want empty", got)
	}
}

func TestClassifyTrust(t *testing.T) {
	cases := []struct {
		name       string
		flags      int
		wantType   int
		transitive bool
		sidFilter  bool
	}{
		{"within forest (parent/child)", trustWithinForest, trustTypeParentChild, true, false},
		{"quarantined within forest", trustWithinForest | trustQuarantined, trustTypeParentChild, true, true},
		{"forest transitive", trustForestTransitive, trustTypeForest, true, true},
		{"forest but treat-as-external", trustForestTransitive | trustTreatAsExternal, trustTypeForest, true, false},
		{"external", trustTreatAsExternal, trustTypeExternal, false, true},
		{"cross-organization", trustCrossOrganization, trustTypeExternal, false, true},
		{"non-transitive only", trustNonTransitive, trustTypeUnknown, false, true},
		{"no flags", 0, trustTypeUnknown, true, true},
	}
	for _, tc := range cases {
		typ, transitive, sidFilter := classifyTrust(tc.flags)
		if typ != tc.wantType || transitive != tc.transitive || sidFilter != tc.sidFilter {
			t.Errorf("%s: classifyTrust(0x%x) = (%d,%v,%v), want (%d,%v,%v)",
				tc.name, tc.flags, typ, transitive, sidFilter, tc.wantType, tc.transitive, tc.sidFilter)
		}
	}
}
