package bloodhound

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// builder accumulates a model.Graph while preserving BloodHound CE's node IDs,
// labels and relationship directions.
type builder struct {
	g            *model.Graph
	rpt          *Report
	nodeSeen     map[string]bool
	hints        map[string]model.Node // placeholder templates for referenced IDs
	domain       string
	placeholders int
}

func newBuilder(rpt *Report) *builder {
	return &builder{
		g:        &model.Graph{Meta: model.Meta{Collector: "bloodhound-import"}},
		rpt:      rpt,
		nodeSeen: map[string]bool{},
		hints:    map[string]model.Node{},
	}
}

func (b *builder) graph() *model.Graph { return b.g }

func (b *builder) skip(reason string) {
	if b.rpt.Skipped == nil {
		b.rpt.Skipped = map[string]int{}
	}
	b.rpt.Skipped[reason]++
}

func (b *builder) unknownRight(right string) {
	if b.rpt.UnknownRights == nil {
		b.rpt.UnknownRights = map[string]int{}
	}
	b.rpt.UnknownRights[right]++
}

// parseFile decodes one BloodHound JSON file and folds its objects into the graph.
func (b *builder) parseFile(r io.Reader, name string) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("bloodhound: read %s: %w", name, err)
	}
	var f bhFile
	if uerr := json.Unmarshal(data, &f); uerr != nil {
		var arr []bhEntry
		if aerr := json.Unmarshal(data, &arr); aerr != nil {
			return fmt.Errorf("bloodhound: parse %s: %w", name, uerr)
		}
		f.Data = arr
	}
	kind, ok := fileKind(f.Meta.Type, name)
	if !ok {
		b.skip("unclassified_file")
		if b.rpt.ByFile == nil {
			b.rpt.ByFile = map[string]int{}
		}
		b.rpt.ByFile[name] = 0
		return nil
	}
	if b.rpt.ByFile == nil {
		b.rpt.ByFile = map[string]int{}
	}
	b.rpt.ByFile[name] = len(f.Data)
	for i := range f.Data {
		b.addEntry(kind, &f.Data[i])
	}
	return nil
}

func (b *builder) addEntry(kind model.Kind, e *bhEntry) {
	id := strings.TrimSpace(e.ObjectIdentifier)
	if id == "" {
		b.skip("empty_object_id")
		return
	}
	if e.IsDeleted {
		b.skip("deleted_object")
		return
	}
	props := flattenProps(e.Properties)
	if e.IsACLProtected {
		props = setProp(props, "isaclprotected", "true")
	}
	domain := propOr(props, "domain", b.domain)
	sam := propOr(props, "samaccountname", "")
	dn := propOr(props, "distinguishedname", "")
	name := propOr(props, "name", "")

	if kind == model.KindDomain && b.domain == "" {
		b.domain = firstNonEmpty(propOr(props, "domain", ""), propOr(props, "name", ""))
	}
	if name == "" {
		name = firstNonEmpty(sam, id)
	}

	b.g.AddNode(model.Node{
		ID:             id,
		Kind:           kind,
		Name:           name,
		Domain:         domain,
		SAMAccountName: sam,
		DN:             dn,
		Props:          props,
	})
	b.nodeSeen[id] = true

	// ACL edges (principal -> target).
	for _, a := range e.Aces {
		pid := strings.TrimSpace(a.PrincipalSID)
		if pid == "" {
			b.skip("ace_without_principal")
			continue
		}
		k, ok := rightToKind[a.RightName]
		if !ok {
			b.unknownRight(a.RightName)
			continue
		}
		var ep map[string]string
		if a.IsInherited || a.Inherited {
			ep = map[string]string{"inherited": "true"}
		}
		b.addEdge(pid, id, k, ep)
		b.guessKind(pid, a.PrincipalType)
	}

	// Group membership (member -> group).
	for _, m := range e.Members {
		if m.ObjectIdentifier == "" {
			continue
		}
		b.addEdge(m.ObjectIdentifier, id, model.EdgeMemberOf, nil)
		b.guessKind(m.ObjectIdentifier, m.ObjectType)
	}
	for _, m := range e.MemberOf {
		if m.ObjectIdentifier == "" {
			continue
		}
		b.addEdge(id, m.ObjectIdentifier, model.EdgeMemberOf, nil)
		b.guessKind(m.ObjectIdentifier, m.ObjectType)
	}
	if pg := strings.TrimSpace(e.PrimaryGroupSID); pg != "" {
		b.addEdge(id, pg, model.EdgeMemberOf, map[string]string{"primary": "true"})
		b.guessKind(pg, "Group")
	}

	// Container containment (parent -> child).
	for _, c := range e.ChildObjects {
		if c.ObjectIdentifier == "" {
			continue
		}
		b.addEdge(id, c.ObjectIdentifier, model.EdgeContains, nil)
		b.guessKind(c.ObjectIdentifier, c.ObjectType)
	}

	// GPO links (GPO -> linked container), matching the BloodHound CE direction.
	for _, l := range e.Links {
		if l.GUID == "" {
			continue
		}
		var ep map[string]string
		if l.IsEnforced {
			ep = map[string]string{"enforced": "true"}
		}
		b.addEdge(l.GUID, id, model.EdgeGPLink, ep)
		b.guessKind(l.GUID, "GPO")
	}

	// Delegation.
	for _, t := range e.AllowedToDelegate {
		if t.ObjectIdentifier == "" {
			continue
		}
		b.addEdge(id, t.ObjectIdentifier, model.EdgeAllowedToDelegate, nil)
		b.guessKind(t.ObjectIdentifier, t.ObjectType)
	}
	for _, t := range e.AllowedToAct {
		if t.ObjectIdentifier == "" {
			continue
		}
		b.addEdge(t.ObjectIdentifier, id, model.EdgeAllowedToAct, nil)
		b.guessKind(t.ObjectIdentifier, t.ObjectType)
	}

	// Local admin / remote access results (principal -> computer).
	b.collected(e.LocalAdmins, id, model.EdgeAdminTo)
	b.collected(e.PSRemoteUsers, id, model.EdgeCanPSRemote)
	b.collected(e.RemoteDesktopUsers, id, model.EdgeCanRDP)
	b.collected(e.DcomUsers, id, model.EdgeExecuteDCOM)

	// Sessions (user -> computer).
	b.sessions(e.Sessions, id)
	b.sessions(e.PrivilegedSessions, id)
	b.sessions(e.RegistrySessions, id)

	// Domain trusts.
	for _, t := range e.Trusts {
		b.addTrust(id, t)
	}
}

func (b *builder) collected(c *bhCollected, computer string, kind model.EdgeKind) {
	if c == nil {
		return
	}
	for _, r := range c.Results {
		oid := firstNonEmpty(strings.TrimSpace(r.ObjectIdentifier), strings.TrimSpace(r.UserSID))
		if oid == "" {
			continue
		}
		b.addEdge(oid, computer, kind, nil)
		b.guessKind(oid, r.ObjectType)
	}
}

func (b *builder) sessions(c *bhCollected, computer string) {
	if c == nil {
		return
	}
	for _, r := range c.Results {
		user := firstNonEmpty(strings.TrimSpace(r.UserSID), strings.TrimSpace(r.ObjectIdentifier))
		host := firstNonEmpty(strings.TrimSpace(r.ComputerSID), computer)
		if user == "" || host == "" {
			continue
		}
		b.addEdge(user, host, model.EdgeHasSession, nil)
		b.guessKind(user, "User")
		b.guessKind(host, "Computer")
	}
}

// addTrust materializes a TrustedBy edge. TrustDirection is relative to the
// domain carrying the trust: INBOUND (1) means the other domain trusts this
// one, OUTBOUND (2) means this domain trusts the other.
func (b *builder) addTrust(domainID string, t bhTrust) {
	name := strings.ToUpper(strings.TrimSpace(t.TargetDomainName))
	other := strings.TrimSpace(t.TargetDomainSid)
	if other == "" {
		if name == "" {
			b.skip("trust_without_target")
			return
		}
		other = "TRUST\\" + name
	}
	if _, ok := b.hints[other]; !ok {
		b.hints[other] = model.Node{ID: other, Kind: model.KindDomain, Name: firstNonEmpty(name, other)}
	}
	if t.TrustDirection&1 != 0 {
		b.addEdge(domainID, other, model.EdgeTrustedBy, nil)
	}
	if t.TrustDirection&2 != 0 {
		b.addEdge(other, domainID, model.EdgeTrustedBy, nil)
	}
}

func (b *builder) addEdge(src, dst string, kind model.EdgeKind, props map[string]string) {
	if src == "" || dst == "" {
		return
	}
	b.g.AddEdge(model.Edge{Source: src, Target: dst, Kind: kind, Props: props})
	b.reference(src)
	b.reference(dst)
}

func (b *builder) reference(id string) {
	if id == "" || b.nodeSeen[id] {
		return
	}
	if _, ok := b.hints[id]; !ok {
		b.hints[id] = model.Node{ID: id, Kind: model.KindBase, Name: id}
	}
}

// guessKind records a placeholder template for an ID referenced by an edge, so
// that un-collected principals still appear with a sensible label.
func (b *builder) guessKind(id, objectType string) {
	if id == "" || b.nodeSeen[id] {
		return
	}
	k, known := kindFromObjectType(objectType)
	h, ok := b.hints[id]
	if !ok {
		h = model.Node{ID: id, Kind: model.KindBase, Name: id}
	}
	// Only upgrade a default Base guess; never downgrade a stronger hint.
	if h.Kind == model.KindBase && known {
		h.Kind = k
	}
	if h.Name == "" {
		h.Name = id
	}
	b.hints[id] = h
}

// finish adds placeholder nodes for every referenced-but-uncollected ID.
func (b *builder) finish() {
	ids := make([]string, 0, len(b.hints))
	for id := range b.hints {
		if b.nodeSeen[id] {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		h := b.hints[id]
		if h.ID == "" {
			h.ID = id
		}
		if h.Name == "" {
			h.Name = id
		}
		b.g.AddNode(h)
		b.placeholders++
	}
}

// ---- property helpers ------------------------------------------------------

func flattenProps(p map[string]any) map[string]string {
	if len(p) == 0 {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		s, ok := scalarString(v)
		if !ok || s == "" {
			continue
		}
		out[strings.ToLower(k)] = truncate(s, 400)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case json.Number:
		return t.String(), true
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := scalarString(e); ok && s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return "", false
		}
		return strings.Join(parts, ","), true
	default:
		return "", false
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func setProp(m map[string]string, k, v string) map[string]string {
	if m == nil {
		m = map[string]string{}
	}
	m[k] = v
	return m
}

func propOr(m map[string]string, k, def string) string {
	if m == nil {
		return def
	}
	if v, ok := m[k]; ok && v != "" {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
