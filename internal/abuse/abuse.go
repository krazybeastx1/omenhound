package abuse

import (
	"strings"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Rendered is a fully-resolved abuse instruction for a concrete edge, with the
// real node properties interpolated and honest warnings about missing data.
type Rendered struct {
	Edge       model.Edge `json:"edge"`
	Source     model.Node `json:"source"`
	Target     model.Node `json:"target"`
	Summary    string     `json:"summary"`
	Command    string     `json:"command"`
	Alternates []string   `json:"alternates,omitempty"`
	OPSEC      string     `json:"opsec,omitempty"`
	EventIDs   []int      `json:"event_ids,omitempty"`
	Warnings   []string   `json:"warnings,omitempty"`
}

const unknown = "<unknown>"

// buildVars derives the interpolation map from a concrete edge and its endpoint
// nodes, preferring the target's domain and falling back sensibly.
func buildVars(e model.Edge, src, tgt model.Node) map[string]string {
	domain := firstNonEmpty(tgt.Domain, src.Domain, domainFromDN(tgt.DN), domainFromDN(src.DN))
	dc := ""
	if tgt.Props != nil {
		dc = tgt.Props["dc"]
	}
	if dc == "" && src.Props != nil {
		dc = src.Props["dc"]
	}
	if dc == "" && domain != "" {
		dc = "DC." + domain
	}
	return map[string]string{
		phDomain:     orUnknown(domain),
		phDC:         orUnknown(dc),
		phSourceSAM:  orUnknown(firstNonEmpty(src.SAMAccountName, src.Name)),
		phSourceDN:   orUnknown(src.DN),
		phSourceSID:  orUnknown(src.ID),
		phSourceName: orUnknown(firstNonEmpty(src.Name, src.SAMAccountName)),
		phTargetSAM:  orUnknown(firstNonEmpty(tgt.SAMAccountName, tgt.Name)),
		phTargetDN:   orUnknown(tgt.DN),
		phTargetSID:  orUnknown(tgt.ID),
		phTargetName: orUnknown(firstNonEmpty(tgt.Name, tgt.SAMAccountName)),
	}
}

func interpolate(s string, vars map[string]string) string {
	repl := make([]string, 0, len(vars)*2)
	for k, v := range vars {
		repl = append(repl, k, v)
	}
	return strings.NewReplacer(repl...).Replace(s)
}

// Render resolves the abuse template for an edge. The bool is false when no
// template exists for that edge kind.
func Render(e model.Edge, src, tgt model.Node) (Rendered, bool) {
	t, ok := Templates[e.Kind]
	if !ok {
		return Rendered{}, false
	}
	vars := buildVars(e, src, tgt)
	r := Rendered{
		Edge:     e,
		Source:   src,
		Target:   tgt,
		Summary:  t.Summary,
		Command:  interpolate(t.Command, vars),
		OPSEC:    t.OPSEC,
		EventIDs: t.EventIDs,
	}
	for _, a := range t.Alternates {
		r.Alternates = append(r.Alternates, interpolate(a, vars))
	}
	// Honest warnings: surface missing data instead of silently emitting a
	// broken command.
	if strings.Contains(r.Command, unknown) {
		r.Warnings = append(r.Warnings, "one or more placeholders could not be resolved from graph properties; fill them manually")
	}
	if vars[phDC] == unknown {
		r.Warnings = append(r.Warnings, "no domain controller (DC) known for this edge; commands using {DC} must be directed manually")
	}
	return r, true
}

func orUnknown(s string) string {
	if s == "" {
		return unknown
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// domainFromDN extracts "example.com"-style domain from a DN
// ("CN=x,OU=y,DC=example,DC=com" -> "example.com").
func domainFromDN(dn string) string {
	if dn == "" {
		return ""
	}
	var parts []string
	for _, seg := range strings.Split(dn, ",") {
		seg = strings.TrimSpace(seg)
		if len(seg) >= 3 && strings.EqualFold(seg[:3], "DC=") {
			parts = append(parts, seg[3:])
		}
	}
	return strings.Join(parts, ".")
}
