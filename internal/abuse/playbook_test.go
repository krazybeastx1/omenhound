package abuse

import (
	"strings"
	"testing"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// TestPlaybookComplete asserts each entry has the fields the UI renders and
// that every edge template appears in the library, so the two cannot drift.
func TestPlaybookComplete(t *testing.T) {
	seen := map[model.EdgeKind]bool{}
	ids := map[string]bool{}
	for _, cat := range Playbook() {
		if cat.ID == "" || cat.Title == "" {
			t.Errorf("category with missing id/title: %+v", cat)
		}
		if len(cat.Techniques) == 0 {
			t.Errorf("category %q has no techniques", cat.ID)
		}
		for _, tech := range cat.Techniques {
			if tech.ID == "" || tech.Title == "" || tech.Command == "" || tech.Summary == "" {
				t.Errorf("category %q: incomplete technique %+v", cat.ID, tech)
			}
			if ids[tech.ID] {
				t.Errorf("duplicate technique id %q", tech.ID)
			}
			ids[tech.ID] = true
			if tech.Edge != "" {
				seen[model.EdgeKind(tech.Edge)] = true
			}
		}
	}
	for k := range Templates {
		if !seen[k] {
			t.Errorf("edge %s has a template but is missing from the playbook", k)
		}
	}
}

// TestPlaybookCommandsAreTemplates keeps the library honest: entries are
// reference templates, so none may be pre-filled with a fabricated result.
func TestPlaybookCommandsAreTemplates(t *testing.T) {
	for _, cat := range Playbook() {
		for _, tech := range cat.Techniques {
			if tech.Edge != "" && !strings.Contains(tech.Command, "{") {
				t.Errorf("edge technique %s lost its placeholders: %q", tech.ID, tech.Command)
			}
		}
	}
}

// TestPlaybookReadAndAdd asserts every technique carries a distinct "read"
// (verify) step and "add" (act) step, and that neither fabricates output.
func TestPlaybookReadAndAdd(t *testing.T) {
	for _, cat := range Playbook() {
		for _, tech := range cat.Techniques {
			if tech.Read == "" {
				t.Errorf("technique %s has no read (verify) step", tech.ID)
				continue
			}
			if tech.Read == tech.Command {
				t.Errorf("technique %s read and add are identical", tech.ID)
			}
			// A read step is either a command template or an explicit note.
			if !strings.Contains(tech.Read, "{") && !strings.HasPrefix(strings.TrimSpace(tech.Read), "#") {
				t.Errorf("technique %s read step is not a template: %q", tech.ID, tech.Read)
			}
			if tech.Edge != "" && !strings.Contains(tech.Read, "{") {
				t.Errorf("edge technique %s read step lost its placeholders: %q", tech.ID, tech.Read)
			}
		}
	}
}
