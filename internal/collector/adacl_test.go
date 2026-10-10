package collector

import (
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// The fixtures below are real self-relative SECURITY_DESCRIPTORs. They were laid
// out byte-for-byte to MS-DTYP 2.4.6 and independently re-parsed with impacket's
// ldaptypes module -- the same library BloodHound.py uses -- before being
// committed here, so the parser is tested against genuinely-formed input rather
// than bytes invented to match the implementation.
var sdFixtures = map[string]string{
	"user_generic":        "010004803001000000000000000000001400000002001c010600000000002400ff010f00010500000000000515000000dcf4dc3b833d2b46828ba6284f0400000000240000000400010500000000000515000000dcf4dc3b833d2b46828ba6284f0400000000240000010000010500000000000515000000dcf4dc3b833d2b46828ba6284f040000050038000001000001000000709529006d24d011a76800aa006e0529010500000000000515000000dcf4dc3b833d2b46828ba6284f0400000500380020000000010000008847a6f30653d111a9c50000f80367c1010500000000000515000000dcf4dc3b833d2b46828ba6284f0400000500380020000000010000000fd6475b9060b2409f372a4de88f3063010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
	"user_inherited":      "01000480b000000000000000000000001400000002009c000300000005103800ff010f0002000000ba7a96bfe60dd011a28500aa003049e2010500000000000515000000dcf4dc3b833d2b46828ba6284f04000005103800ff010f0002000000867a96bfe60dd011a28500aa003049e2010500000000000515000000dcf4dc3b833d2b46828ba6284f04000000082400ff010f00010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
	"group_member":        "01000480c40000000000000000000000140000000200b00003000000050038002000000001000000c07996bfe60dd011a28500aa003049e2010500000000000515000000dcf4dc3b833d2b46828ba6284f040000050038000800000001000000c07996bfe60dd011a28500aa003049e2010500000000000515000000dcf4dc3b833d2b46828ba6284f040000050038002000000001000000e5c3783f9af7bd46a0b89d18116ddc79010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
	"domain_replication":  "01000480c40000000000000000000000140000000200b00003000000050038000001000001000000aaf63111079cd111f79f00c04fc2dcd2010500000000000515000000dcf4dc3b833d2b46828ba6284f040000050038000001000001000000adf63111079cd111f79f00c04fc2dcd2010500000000000515000000dcf4dc3b833d2b46828ba6284f040000050038000001000001000000765be9894d44624c991a0facbeda640c010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
	"computer_laps":       "01000480540000000000000000000000140000000200400001000000050038001001000001000000aaaaaaaabbbbccccddddeeeeeeeeeeee010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
	"ou_gplink":           "01000480540000000000000000000000140000000200400001000000050038002000000001000000be3b0ef3f09fd111b6030000f80367c1010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
	"owner_local_system":  "010004804000000000000000000000001400000002002c00010000000000240000000400010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010100000000000512000000",
	"denied_ignored":      "010004804000000000000000000000001400000002002c000100000001002400ff010f00010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
	"dacl_protected":      "010004904000000000000000000000001400000002002c00010000000000240000000400010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
	"group_generic_write": "010004804000000000000000000000001400000002002c00010000000000240028000200010500000000000515000000dcf4dc3b833d2b46828ba6284f040000010500000000000515000000dcf4dc3b833d2b46828ba628f4010000",
}

// sdFixtureACECount is the ACE count impacket read from each fixture's ACL header.
var sdFixtureACECount = map[string]int{
	"user_generic": 6, "user_inherited": 3, "group_member": 3, "domain_replication": 3,
	"computer_laps": 1, "ou_gplink": 1, "owner_local_system": 1, "denied_ignored": 1,
	"dacl_protected": 1, "group_generic_write": 1,
}

func fixture(t *testing.T, name string) *SecurityDescriptor {
	t.Helper()
	raw, err := hex.DecodeString(sdFixtures[name])
	if err != nil {
		t.Fatalf("fixture %s: bad hex: %v", name, err)
	}
	sd, err := ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatalf("fixture %s: ParseSecurityDescriptor: %v", name, err)
	}
	return sd
}

// testClassGUIDs is the lowercased schema name -> GUID map the ACL mapper uses,
// as it would be built from a real directory schema.
func testClassGUIDs(t *testing.T) map[string]GUID {
	t.Helper()
	src := map[string]string{
		"user":                      "bf967aba-0de6-11d0-a285-00aa003049e2",
		"group":                     "bf967a9c-0de6-11d0-a285-00aa003049e2",
		"computer":                  "bf967a86-0de6-11d0-a285-00aa003049e2",
		"domain":                    "19195a5a-6da0-11d0-afd3-00c04fd930c9",
		"domain-dns":                "19195a5b-6da0-11d0-afd3-00c04fd930c9",
		"organizational-unit":       "bf967aa5-0de6-11d0-a285-00aa003049e2",
		"group-policy-container":    "f30e3bc2-9ff0-11d1-b603-0000f80367c1",
		"container":                 "bf967a8b-0de6-11d0-a285-00aa003049e2",
		"service-principal-name":    "f3a64788-5306-11d1-a9c5-0000f80367c1",
		"ms-ds-key-credential-link": "5b47d60f-6090-40b2-9f37-2a4de88f3063",
		"ms-mcs-admpwd":             "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
	out := make(map[string]GUID, len(src))
	for name, s := range src {
		g, err := ParseGUID(s)
		if err != nil {
			t.Fatalf("test class guid %s: %v", s, err)
		}
		out[name] = g
	}
	return out
}

func TestParseSecurityDescriptorFixtures(t *testing.T) {
	cases := []struct {
		fixture   string
		owner     string
		control   uint16
		protected bool
	}{
		{"user_generic", "S-1-5-21-1004336348-1177238915-682003330-500", 0x8004, false},
		{"user_inherited", "S-1-5-21-1004336348-1177238915-682003330-500", 0x8004, false},
		{"group_member", "S-1-5-21-1004336348-1177238915-682003330-500", 0x8004, false},
		{"domain_replication", "S-1-5-21-1004336348-1177238915-682003330-500", 0x8004, false},
		{"computer_laps", "S-1-5-21-1004336348-1177238915-682003330-500", 0x8004, false},
		{"ou_gplink", "S-1-5-21-1004336348-1177238915-682003330-500", 0x8004, false},
		{"owner_local_system", "S-1-5-18", 0x8004, false},
		{"denied_ignored", "S-1-5-21-1004336348-1177238915-682003330-500", 0x8004, false},
		// 0x9004 = SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED.
		{"dacl_protected", "S-1-5-21-1004336348-1177238915-682003330-500", 0x9004, true},
		{"group_generic_write", "S-1-5-21-1004336348-1177238915-682003330-500", 0x8004, false},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			sd := fixture(t, tc.fixture)
			if sd.OwnerSID != tc.owner {
				t.Errorf("owner = %q, want %q", sd.OwnerSID, tc.owner)
			}
			if sd.Control != tc.control {
				t.Errorf("Control = 0x%04x, want 0x%04x", sd.Control, tc.control)
			}
			if sd.DACLProtected != tc.protected {
				t.Errorf("DACLProtected = %v, want %v", sd.DACLProtected, tc.protected)
			}
			if sd.RawACECount != sdFixtureACECount[tc.fixture] {
				t.Errorf("RawACECount = %d, want %d", sd.RawACECount, sdFixtureACECount[tc.fixture])
			}
			if len(sd.DACL) != sdFixtureACECount[tc.fixture] {
				t.Errorf("len(DACL) = %d, want %d", len(sd.DACL), sdFixtureACECount[tc.fixture])
			}
		})
	}
}

func TestParseSecurityDescriptorFirstACE(t *testing.T) {
	// The first ACE of user_generic is a plain ACCESS_ALLOWED_ACE granting
	// 0x000F01FF to the principal SID.
	sd := fixture(t, "user_generic")
	if len(sd.DACL) == 0 {
		t.Fatal("no ACEs parsed")
	}
	a := sd.DACL[0]
	if a.Type != aceTypeAccessAllowed {
		t.Errorf("Type = 0x%02x, want 0x00", a.Type)
	}
	if a.Mask != 0x000F01FF {
		t.Errorf("Mask = 0x%08x, want 0x000F01FF", a.Mask)
	}
	if a.SID != "S-1-5-21-1004336348-1177238915-682003330-1103" {
		t.Errorf("SID = %q", a.SID)
	}
	if a.ObjectType != nil || a.InheritedObjectType != nil {
		t.Errorf("plain allowed ACE must have no object types, got %v/%v", a.ObjectType, a.InheritedObjectType)
	}
}

func TestParseSecurityDescriptorObjectACE(t *testing.T) {
	// The fourth ACE of user_generic restricts CONTROL_ACCESS to the
	// User-Force-Change-Password extended right.
	sd := fixture(t, "user_generic")
	var found bool
	for _, a := range sd.DACL {
		if a.Type != aceTypeAccessAllowedObject {
			continue
		}
		if a.Mask == maskDSControlAccess && a.ObjectType != nil &&
			a.ObjectType.String() == "00299570-246d-11d0-a768-00aa006e0529" {
			found = true
		}
	}
	if !found {
		t.Fatal("did not find the ForceChangePassword object ACE")
	}
}

func TestParseSecurityDescriptorErrors(t *testing.T) {
	cases := []struct {
		name string
		hex  string
	}{
		{"empty", ""},
		{"19 bytes", strings.Repeat("00", 19)},
		{"owner offset out of range", "01000480ff000000000000000000000014000000"},
		{"not self-relative", "01000400" + strings.Repeat("00", 16)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := hex.DecodeString(tc.hex)
			if _, err := ParseSecurityDescriptor(raw); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestParseSecurityDescriptorNoDACL(t *testing.T) {
	// 20-byte header with no owner, no DACL, no SACL.
	raw, _ := hex.DecodeString("0100048000000000000000000000000000000000")
	sd, err := ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sd.OwnerSID != "" || len(sd.DACL) != 0 {
		t.Fatalf("want empty descriptor, got owner=%q dacl=%d", sd.OwnerSID, len(sd.DACL))
	}
}

// relKeys renders relations as sorted "Kind" / "Kind/inherited" keys. Duplicates
// are collapsed because Graph.AddEdge deduplicates on (source, kind, target), so
// two ACEs granting the same edge are indistinguishable in the graph.
func relKeys(rels []aclRelation) []string {
	seen := make(map[string]bool, len(rels))
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		k := string(r.Kind)
		if r.Inherited {
			k += "/inherited"
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestACLRelationsFixtures(t *testing.T) {
	cases := []struct {
		fixture    string
		kind       model.Kind
		hasLAPS    bool
		want       []string
		wantUnk    map[uint8]int
		wantUnfilt int
	}{
		{
			fixture: "user_generic", kind: model.KindUser,
			// Owns (owner 500); GenericAll, WriteDacl from plain ACEs;
			// AllExtendedRights + ForceChangePassword from the unrestricted
			// CONTROL_ACCESS ACE; WriteSPN and AddKeyCredentialLink from the
			// property-write ACEs.
			want: []string{"Owns", "GenericAll", "WriteDacl", "AllExtendedRights", "ForceChangePassword", "WriteSPN", "AddKeyCredentialLink"},
		},
		{
			fixture: "user_inherited", kind: model.KindUser,
			// The user-class inherited ACE applies; the computer-class one does
			// not; the inherit-only ACE is skipped entirely.
			want: []string{"Owns", "GenericAll/inherited"},
		},
		{
			fixture: "group_member", kind: model.KindGroup,
			want: []string{"Owns", "AddMember", "AddSelf"},
		},
		{
			fixture: "domain_replication", kind: model.KindDomain,
			want: []string{"Owns", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet"},
		},
		{
			fixture: "computer_laps", kind: model.KindComputer, hasLAPS: true,
			want: []string{"Owns", "ReadLAPSPassword"},
		},
		{
			// Without LAPS deployed, the same ACE yields nothing.
			fixture: "computer_laps", kind: model.KindComputer, hasLAPS: false,
			want: []string{"Owns"},
		},
		{
			fixture: "ou_gplink", kind: model.KindOU,
			want: []string{"Owns", "WriteGPLink"},
		},
		{
			fixture: "owner_local_system", kind: model.KindUser,
			want: []string{"WriteDacl"},
		},
		{
			fixture: "denied_ignored", kind: model.KindUser,
			want:    []string{"Owns"},
			wantUnk: map[uint8]int{0x01: 1},
		},
		{
			fixture: "dacl_protected", kind: model.KindUser,
			want: []string{"Owns", "WriteDacl"},
		},
		{
			fixture: "group_generic_write", kind: model.KindGroup,
			// 0x00020028 carries both WRITE_PROP and SELF, so a plain
			// GenericWrite ACE on a group also yields AddSelf.
			want: []string{"Owns", "GenericWrite", "AddSelf"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.fixture+"/"+string(tc.kind), func(t *testing.T) {
			sd := fixture(t, tc.fixture)
			rels, st := aclRelations(tc.kind, sd, testClassGUIDs(t), tc.hasLAPS)
			got := relKeys(rels)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("relations = %v, want %v", got, want)
			}
			if len(tc.wantUnk) == 0 {
				if len(st.UnknownACETypes) != 0 {
					t.Errorf("UnknownACETypes = %v, want none", st.UnknownACETypes)
				}
			} else {
				for typ, n := range tc.wantUnk {
					if st.UnknownACETypes[typ] != n {
						t.Errorf("UnknownACETypes[0x%02x] = %d, want %d", typ, st.UnknownACETypes[typ], n)
					}
				}
			}
			if st.InheritedUnfiltered != tc.wantUnfilt {
				t.Errorf("InheritedUnfiltered = %d, want %d", st.InheritedUnfiltered, tc.wantUnfilt)
			}
			for _, r := range rels {
				if r.SID == "" {
					t.Fatalf("relation %v has an empty principal", r.Kind)
				}
			}
		})
	}
}

func TestACLRelationsWithoutSchema(t *testing.T) {
	// With no schema the class filtering cannot run: both inherited ACEs are
	// applied and counted as unfiltered, so the run can report over-approximation
	// rather than silently dropping or silently keeping them.
	sd := fixture(t, "user_inherited")
	rels, st := aclRelations(model.KindUser, sd, nil, false)
	got := relKeys(rels)
	want := []string{"GenericAll/inherited", "Owns"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("relations = %v, want %v", got, want)
	}
	if st.InheritedUnfiltered != 2 {
		t.Errorf("InheritedUnfiltered = %d, want 2", st.InheritedUnfiltered)
	}
}

func TestACLRelationsInheritedFiltered(t *testing.T) {
	// The computer-class inherited ACE is dropped because the target is a user.
	sd := fixture(t, "user_inherited")
	_, st := aclRelations(model.KindUser, sd, testClassGUIDs(t), false)
	if st.InheritedFiltered != 1 {
		t.Errorf("InheritedFiltered = %d, want 1", st.InheritedFiltered)
	}
}

func TestParseGUIDRoundTrip(t *testing.T) {
	for _, s := range []string{
		"00299570-246d-11d0-a768-00aa006e0529",
		"bf9679c0-0de6-11d0-a285-00aa003049e2",
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	} {
		g, err := ParseGUID(s)
		if err != nil {
			t.Fatalf("ParseGUID(%q): %v", s, err)
		}
		if g.String() != s {
			t.Errorf("round trip %q -> %q", s, g.String())
		}
	}
	for _, bad := range []string{"", "not-a-guid", "00299570-246d-11d0-a768", "00299570-246d-11d0-a768-00aa006e052", "zzzzzzzz-246d-11d0-a768-00aa006e0529"} {
		if _, err := ParseGUID(bad); err == nil {
			t.Errorf("ParseGUID(%q): expected error", bad)
		}
	}
}

func TestSDFlagsControl(t *testing.T) {
	c := sdFlagsControl()
	if got := c.GetControlType(); got != oidSDFlags {
		t.Errorf("control OID = %q, want %q", got, oidSDFlags)
	}
	cs, ok := c.(*ldap.ControlString)
	if !ok {
		t.Fatalf("control is %T, want *ldap.ControlString", c)
	}
	want := string([]byte{0x30, 0x03, 0x02, 0x01, sdFlagOwner | sdFlagDACL})
	if cs.ControlValue != want {
		t.Errorf("control value = %x, want %x", cs.ControlValue, want)
	}
	if !cs.Criticality {
		t.Error("control should be marked critical")
	}
	if sdFlagOwner|sdFlagDACL != 0x05 {
		t.Errorf("owner|dacl = %#x, want 0x05", sdFlagOwner|sdFlagDACL)
	}
}

func TestHasMask(t *testing.T) {
	if !hasMask(0x000F01FF, maskGenericAll) {
		t.Error("full generic-all mask should satisfy maskGenericAll")
	}
	if hasMask(0x00000020, maskGenericAll) {
		t.Error("write-prop should not satisfy maskGenericAll")
	}
	if !hasMask(0x00020028, maskGenericWrite) {
		t.Error("0x00020028 should satisfy maskGenericWrite")
	}
}
