package main

import (
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

func TestExportBaseNameIsSelfDescribing(t *testing.T) {
	g := &model.Graph{Meta: model.Meta{Collector: "ldap", Domain: "htb.local"}}
	name := exportBaseName(g, "", "json")
	if !strings.HasPrefix(name, "ldap_htb.local_") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("name = %q, want ldap_htb.local_<timestamp>.json", name)
	}

	// A prefix leads, and the collector/domain still disambiguate the file.
	prefixed := exportBaseName(g, "lab", "zip")
	if !strings.HasPrefix(prefixed, "lab_ldap_htb.local_") || !strings.HasSuffix(prefixed, ".zip") {
		t.Fatalf("name = %q, want lab_ldap_htb.local_<timestamp>.zip", prefixed)
	}

	// An import is distinguishable from a native collect at a glance.
	imp := &model.Graph{Meta: model.Meta{Collector: "bloodhound-import", Domain: "HTB.LOCAL"}}
	if got := exportBaseName(imp, "", "json"); !strings.HasPrefix(got, "bloodhound-import_HTB.LOCAL_") {
		t.Fatalf("name = %q, want bloodhound-import_HTB.LOCAL_<timestamp>.json", got)
	}
}

func TestSanitizeFilePart(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"  htb.local  ": "htb.local",
		"corp/charlie":  "corp_charlie",
		"a b":           "a_b",
	}
	for in, want := range cases {
		if got := sanitizeFilePart(in); got != want {
			t.Fatalf("sanitizeFilePart(%q) = %q, want %q", in, got, want)
		}
	}
}
