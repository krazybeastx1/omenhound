package abuse

import (
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

func TestRenderGenericAll(t *testing.T) {
	src := model.Node{ID: "S-1-5-21-1-2-3-1103", Kind: model.KindUser, Name: "John Doe", SAMAccountName: "jdoe", Domain: "corp.local", DN: "CN=John Doe,OU=Users,DC=corp,DC=local"}
	tgt := model.Node{ID: "S-1-5-21-1-2-3-1003", Kind: model.KindComputer, Name: "WS01", SAMAccountName: "WS01$", Domain: "corp.local", DN: "CN=WS01,OU=Workstations,DC=corp,DC=local", Props: map[string]string{"dc": "dc01.corp.local"}}

	r, ok := Render(model.Edge{Source: src.ID, Target: tgt.ID, Kind: model.EdgeGenericAll}, src, tgt)
	if !ok {
		t.Fatal("expected a template for GenericAll")
	}
	if r.Command == "" {
		t.Fatal("empty command")
	}
	if r.Read == "" {
		t.Fatal("empty read (verify) command")
	}
	for _, ph := range []string{phDomain, phDC, phSourceSAM, phTargetSAM, phTargetDN, phTargetSID, phSourceDN, phSourceSID, phTargetName} {
		if strings.Contains(r.Command, ph) {
			t.Errorf("unresolved placeholder %s in %q", ph, r.Command)
		}
		if strings.Contains(r.Read, ph) {
			t.Errorf("unresolved placeholder %s in read %q", ph, r.Read)
		}
	}
	if !strings.Contains(r.Command, "jdoe") {
		t.Errorf("command should contain the real source sAMAccountName: %q", r.Command)
	}
	if !strings.Contains(r.Read, "jdoe") {
		t.Errorf("read command should contain the real source sAMAccountName: %q", r.Read)
	}
	if r.Read == r.Command {
		t.Errorf("read and add must be distinct steps: %q", r.Read)
	}
	if r.OPSEC == "" {
		t.Error("expected an OPSEC note")
	}
}

func TestRenderUnsupported(t *testing.T) {
	if _, ok := Render(model.Edge{Kind: model.EdgeKind("NotAThing")}, model.Node{}, model.Node{}); ok {
		t.Fatal("expected no render for unknown edge kind")
	}
}

func TestRenderWarnsOnMissingData(t *testing.T) {
	src := model.Node{ID: "S-1", Kind: model.KindUser, SAMAccountName: "a"}
	tgt := model.Node{ID: "S-2", Kind: model.KindUser, SAMAccountName: "b"}
	r, ok := Render(model.Edge{Source: src.ID, Target: tgt.ID, Kind: model.EdgeForceChangePassword}, src, tgt)
	if !ok {
		t.Fatal("expected template")
	}
	if len(r.Warnings) == 0 {
		t.Error("expected warnings when domain/DC/DN are missing")
	}
}

func TestSupportedNonEmpty(t *testing.T) {
	if len(Supported()) < 20 {
		t.Fatalf("expected many supported edges, got %d", len(Supported()))
	}
}
