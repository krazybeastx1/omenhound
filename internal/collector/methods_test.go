package collector

import (
	"reflect"
	"testing"
)

func TestPlanMethodsDefault(t *testing.T) {
	p, err := PlanMethods("")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Implemented, []string{"group", "objectprops"}) {
		t.Fatalf("default implemented = %v", p.Implemented)
	}
	if len(p.Skipped) != 0 {
		t.Fatalf("default skipped = %v, want none", p.Skipped)
	}
}

func TestPlanMethodsAllReportsUnimplemented(t *testing.T) {
	p, err := PlanMethods("all")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Implemented, []string{"group", "trusts", "objectprops", "acl", "container"}) {
		t.Fatalf("all implemented = %v", p.Implemented)
	}
	want := map[string]bool{"localadmin": true, "session": true, "dcom": true, "rdp": true, "psremote": true, "loggedon": true}
	if len(p.Skipped) != len(want) {
		t.Fatalf("all skipped = %v, want %d entries", p.Skipped, len(want))
	}
	for _, m := range p.Skipped {
		if !want[m] {
			t.Errorf("unexpected skipped method %q", m)
		}
	}
}

func TestPlanMethodsDConly(t *testing.T) {
	// `dc` expands to group, trusts, objectprops, acl, container — every one of
	// which the LDAP collector now implements, so nothing is skipped.
	p, err := PlanMethods("dc")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Implemented, []string{"group", "trusts", "objectprops", "acl", "container"}) {
		t.Fatalf("dc implemented = %v", p.Implemented)
	}
	if len(p.Skipped) != 0 {
		t.Fatalf("dc skipped = %v, want none", p.Skipped)
	}
}

func TestPlanMethodsACLAlone(t *testing.T) {
	// `-c acl` is now implemented: the ACL pass is self-sufficient, so it no
	// longer needs group/objectprops to have run first.
	p, err := PlanMethods("acl")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Implemented, []string{"acl"}) {
		t.Fatalf("acl implemented = %v", p.Implemented)
	}
	if len(p.Skipped) != 0 {
		t.Fatalf("acl skipped = %v, want none", p.Skipped)
	}
}

func TestPlanMethodsMixedAndDedupe(t *testing.T) {
	p, err := PlanMethods("group,acl,group,objectprops")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Implemented, []string{"group", "acl", "objectprops"}) {
		t.Fatalf("implemented = %v", p.Implemented)
	}
	if len(p.Skipped) != 0 {
		t.Fatalf("skipped = %v, want none", p.Skipped)
	}
}

func TestPlanMethodsUnknown(t *testing.T) {
	if _, err := PlanMethods("teleport"); err == nil {
		t.Fatal("expected an error for an unknown method")
	}
}

func TestPlanMethodsContainerAndTrustsAlone(t *testing.T) {
	// `container` and `trusts` are self-sufficient passes: each creates the
	// nodes it needs, so requesting one alone skips nothing.
	for _, m := range []string{"container", "trusts"} {
		p, err := PlanMethods(m)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p.Implemented, []string{m}) {
			t.Fatalf("%s implemented = %v", m, p.Implemented)
		}
		if len(p.Skipped) != 0 {
			t.Fatalf("%s skipped = %v, want none", m, p.Skipped)
		}
	}
}
