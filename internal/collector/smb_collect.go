package collector

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc/mslsad"
	"github.com/jfjallid/go-smb/dcerpc/mssamr"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/mswkst"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/golog"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// ---------------------------------------------------------------------------
// SMB collection: -c session, localadmin, rdp, dcom, psremote, loggedon
//
// Each host is queried once over an authenticated SMB session with the DCE/RPC
// calls BloodHound.py uses:
//
//	session    srvsvc  NetrSessionEnum level 10   -> user -HasSession-> source host
//	loggedon   wkssvc  NetrWkstaUserEnum level 1  -> user -HasSession-> this host
//	localadmin samr    alias 544 members          -> member -AdminTo-> this host
//	rdp        samr    alias 555 members          -> member -CanRDP-> this host
//	dcom       samr    alias 562 members          -> member -ExecuteDCOM-> this host
//	psremote   samr    alias 580 members          -> member -CanPSRemote-> this host
//
// The results are filtered exactly as BloodHound.py filters them (machine
// accounts, the bind user's own session, loopback sources, and SIDs belonging to
// the host's own local SAM), then resolved to node IDs the same way: sessions by
// SAM account name and by reverse DNS of the source address, local-group members
// by the graph's SID index with an lsarpc lookup for the rest.
// ---------------------------------------------------------------------------

// smbGroupMethod maps a BloodHound.py collection method to the well-known local
// alias (RID) whose members it contributes and the edge that membership creates.
var smbGroupMethod = []struct {
	method string
	rid    uint32
	edge   model.EdgeKind
}{
	{"localadmin", 544, model.EdgeAdminTo},
	{"rdp", 555, model.EdgeCanRDP},
	{"dcom", 562, model.EdgeExecuteDCOM},
	{"psremote", 580, model.EdgeCanPSRemote},
}

// MS-SAMR access masks BloodHound.py requests when opening the builtin domain
// and an alias: DOMAIN_LOOKUP (0x00000200) and ALIAS_LIST_MEMBERS (0x00000004),
// OR'd with MAXIMUM_ALLOWED the way impacket does.
const (
	samrDomainLookup     uint32 = 0x00000200
	samrAliasListMembers uint32 = 0x00000004
	builtinDomainSID            = "S-1-5-32"
)

// ptrLookup resolves a source address back to a name. It is a variable so tests
// can stub DNS. BloodHound.py falls back to an unauthenticated NTLM hostname
// lookup when the PTR record is missing; OmenHound does not, and reports the
// session as unresolvable instead.
var ptrLookup = func(ip net.IP) []string {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return nil
	}
	return names
}

// smbMethodRequested reports whether an SMB/RPC collection method was planned.
func smbMethodRequested(m *MethodPlan, name string) bool {
	if m == nil {
		return false
	}
	for _, s := range m.Implemented {
		if s == name {
			return true
		}
	}
	return false
}

// smbSessionRequested includes the legacy Options.IncludeSessions flag.
func smbSessionRequested(o Options) bool {
	return o.IncludeSessions || smbMethodRequested(o.Methods, "session")
}

// localGroupRIDs returns the well-known local-alias RIDs to enumerate for the
// requested local-group methods, in table order.
func localGroupRIDs(o Options) []uint32 {
	var rids []uint32
	for _, gm := range smbGroupMethod {
		if smbMethodRequested(o.Methods, gm.method) {
			rids = append(rids, gm.rid)
		}
	}
	return rids
}

// smbAnyRequested reports whether any SMB/RPC method should run at all.
func smbAnyRequested(o Options) bool {
	if smbSessionRequested(o) {
		return true
	}
	for _, gm := range smbGroupMethod {
		if smbMethodRequested(o.Methods, gm.method) {
			return true
		}
	}
	return smbMethodRequested(o.Methods, "loggedon")
}

// smbStats accumulates what a run over one or more hosts produced.
type smbStats struct {
	noHostname   int // skipped: no dNSHostName to dial
	queried      int // hosts reached and authenticated
	unreachable  int // hosts that did not answer
	dcSkipped    int // domain controllers whose local groups were skipped
	rpcErrors    int // per-method RPC failures (typically access denied)
	sessions     int // HasSession edges from sessions
	loggedOn     int // HasSession edges from logged-on users
	members      int // local-group edges
	unresolved   int // local-group SIDs the target could not name
	unresolvable int // session users/hosts that did not resolve to a node
}

func (s smbStats) add(o smbStats) smbStats {
	s.queried += o.queried
	s.unreachable += o.unreachable
	s.dcSkipped += o.dcSkipped
	s.rpcErrors += o.rpcErrors
	s.sessions += o.sessions
	s.loggedOn += o.loggedOn
	s.members += o.members
	s.unresolved += o.unresolved
	s.unresolvable += o.unresolvable
	return s
}

// collectSMB runs the SMB/RPC pass over every collected computer. The pass only
// produces edges; it never invents a node for a principal the target cannot name.
func collectSMB(ctx context.Context, g *model.Graph, o Options) error {
	if !smbAnyRequested(o) {
		return nil
	}
	// The SMB library logs diagnostic "Skip:"/"Error:" lines at Notice/Error
	// level for routine conditions (SMB1 packets, other sessions, encrypted
	// frames). Silence them so OmenHound's output carries only its own honest
	// reporting; real failures still come back as errors and are counted in
	// Meta.Warnings.
	golog.SetLogLevel(golog.LevelNone)
	if len(o.Password) == 0 && len(o.Hashes) == 0 {
		g.Meta.Warnings = append(g.Meta.Warnings,
			"smb: no password or hash available for SMB authentication — session and local-group methods skipped")
		return nil
	}
	if smbMethodRequested(o.Methods, "loggedon") {
		g.Meta.Warnings = append(g.Meta.Warnings,
			"smb: loggedon uses NetrWkstaUserEnum only; registry (winreg) logon sessions are not collected")
	}

	index := g.NodeIndex()
	ix := newSIDIndex(g, o.Domain)

	var st smbStats
	var targets []model.Node
	for _, n := range g.Nodes {
		if n.Kind != model.KindComputer {
			continue
		}
		if hostOfNode(n) == "" {
			st.noHostname++
			continue
		}
		targets = append(targets, n)
	}
	// Deterministic iteration: the graph's node order is whatever the paged LDAP
	// search returned.
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	if st.noHostname > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"smb: %d computer(s) skipped because they have no dNSHostName", st.noHostname))
	}
	if len(targets) == 0 {
		return nil
	}

	for _, t := range targets {
		if ctx.Err() != nil {
			// The run budget ran out. Keep the graph built so far (the LDAP
			// data is valuable) and say exactly where the pass stopped.
			g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
				"smb: stopped after %d of %d computers (%v); the remaining hosts were not queried",
				st.queried, len(targets), ctx.Err()))
			break
		}
		hostCtx, cancel := context.WithTimeout(ctx, smbHostTimeout)
		hostStats := collectHost(hostCtx, g, o, ix, index, t)
		cancel()
		st = st.add(hostStats)
	}

	g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
		"smb: %d of %d computers queried (HasSession %d, local-group %d, loggedon %d; %d unreachable, %d RPC failure(s))",
		st.queried, len(targets), st.sessions, st.members, st.loggedOn, st.unreachable, st.rpcErrors))
	if st.dcSkipped > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"smb: local groups skipped on %d domain controller(s) (their local groups are the domain builtin groups)", st.dcSkipped))
	}
	if st.unresolvable > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"smb: %d session account(s)/host(s) dropped: not in this domain or no reverse DNS", st.unresolvable))
	}
	if st.unresolved > 0 {
		g.Meta.Warnings = append(g.Meta.Warnings, fmt.Sprintf(
			"smb: %d local-group member(s) dropped: the target returned no name for the SID", st.unresolved))
	}
	return nil
}

// collectHost performs all requested SMB/RPC methods against one computer.
func collectHost(ctx context.Context, g *model.Graph, o Options, ix *sidIndex, index map[string]model.Node, t model.Node) smbStats {
	var st smbStats
	h, err := dialHost(ctx, o, hostOfNode(t))
	if err != nil {
		st.unreachable++
		return st
	}
	defer h.close()
	st.queried++

	if smbSessionRequested(o) {
		entries, err := hostSessions(h, o.Username)
		if err != nil {
			st.rpcErrors++
		} else {
			for _, e := range entries {
				userSID, ok := ix.userSID(e.user)
				if !ok {
					st.unresolvable++
					continue
				}
				hostSID, ok := ix.sourceSID(e.source, o.Domain)
				if !ok {
					st.unresolvable++
					continue
				}
				g.AddEdge(model.Edge{Source: userSID, Target: hostSID, Kind: model.EdgeHasSession})
				st.sessions++
			}
		}
	}

	// Local-group methods share one samr session on the host. BloodHound.py
	// skips local groups on domain controllers (primarygroup.endswith('-516')):
	// a DC's "local" groups are the domain's builtin groups, already collected
	// over LDAP under the group method.
	rids := localGroupRIDs(o)
	if len(rids) > 0 && isDomainController(t) {
		st.dcSkipped++
		rids = nil
	}
	if len(rids) > 0 {
		members, err := hostLocalGroups(h, t.SAMAccountName, rids)
		if err != nil {
			st.rpcErrors++
		} else {
			// Resolve, once per host, the members that are not in the graph yet.
			var unknown []string
			seen := map[string]bool{}
			for _, rid := range rids {
				for _, sid := range members[rid] {
					if ix.has(sid) || seen[sid] {
						continue
					}
					seen[sid] = true
					unknown = append(unknown, sid)
				}
			}
			lsa := resolveSIDs(h, unknown)
			for _, gm := range smbGroupMethod {
				sids, ok := members[gm.rid]
				if !ok {
					continue
				}
				for _, sid := range sids {
					if !ix.has(sid) {
						info, ok := lsa[sid]
						if !ok {
							// BloodHound.py drops a SID it cannot resolve
							// rather than inventing a node for it.
							st.unresolved++
							continue
						}
						n := nodeFromLSA(sid, info, o.Domain)
						upsertNode(g, index, n)
						ix.record(n)
					}
					g.AddEdge(model.Edge{Source: sid, Target: t.ID, Kind: gm.edge})
					st.members++
				}
			}
		}
	}

	if smbMethodRequested(o.Methods, "loggedon") {
		entries, err := hostLoggedOn(h, t.SAMAccountName)
		if err != nil {
			st.rpcErrors++
		} else {
			for _, e := range entries {
				userSID, ok := ix.userSID(e.user)
				if !ok {
					st.unresolvable++
					continue
				}
				g.AddEdge(model.Edge{Source: userSID, Target: t.ID, Kind: model.EdgeHasSession})
				st.loggedOn++
			}
		}
	}
	return st
}

// ---------------------------------------------------------------------------
// Per-host RPC calls
// ---------------------------------------------------------------------------

// sessionEntry is one accepted session returned by srvsvc at level 10.
type sessionEntry struct {
	user   string
	source string
}

// hostSessions queries srvsvc NetrSessionEnum at level 10 and applies
// BloodHound.py's session filtering. An error (typically access denied on a
// hardened host) is returned so the caller can count it.
func hostSessions(h *smbHost, selfUser string) ([]sessionEntry, error) {
	bind, cleanup, err := h.rpc(mssrvs.MSRPCSrvSvcPipe, mssrvs.MSRPCUuidSrvSvc,
		mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	res, err := mssrvs.NewRPCCon(bind).NetSessionEnum("", "", 10)
	if err != nil {
		return nil, fmt.Errorf("NetSessionEnum: %w", err)
	}
	if res == nil || res.Level10 == nil {
		return nil, nil
	}
	var out []sessionEntry
	for _, s := range res.Level10.Buffer {
		user := stripNUL(s.Username)
		source := stripNUL(s.Cname)
		if skipSession(user, source, selfUser) {
			continue
		}
		out = append(out, sessionEntry{user: user, source: source})
	}
	return out, nil
}

// skipSession applies BloodHound.py's rules from rpc_get_sessions: an empty
// source, the operator's own session, an empty or machine-account user, and
// loopback sources are all skipped (they never describe a useful edge).
func skipSession(user, source, selfUser string) bool {
	user = strings.TrimSpace(user)
	source = strings.TrimSpace(source)
	if source == "" || user == "" {
		return true
	}
	if strings.EqualFold(user, selfUser) || strings.EqualFold(user, bareUser(selfUser)) {
		return true
	}
	if strings.HasSuffix(user, "$") {
		return true
	}
	switch strings.TrimSuffix(strings.Trim(source, "[]"), ".") {
	case "127.0.0.1", "::1":
		return true
	}
	return false
}

// hostLocalGroups lists the members of the requested well-known local aliases on
// one host over a single samr session. Members that are local accounts on the
// host itself (those below the host's own local SAM SID) are filtered out here,
// exactly as BloodHound.py filters them.
//
// A failure to list one alias is not fatal: the alias map simply lacks that RID,
// exactly as if the group did not exist on that SKU. Only a failure to connect
// to samr is returned as an error.
func hostLocalGroups(h *smbHost, samName string, rids []uint32) (members map[uint32][]string, err error) {
	bind, cleanup, err := h.rpc(mssamr.MSRPCSamrPipe, mssamr.MSRPCUuidSamr,
		mssamr.MSRPCSamrMajorVersion, mssamr.MSRPCSamrMinorVersion)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	rpc := mssamr.NewRPCCon(bind)

	server, err := rpc.SamrConnect5("")
	if err != nil {
		return nil, fmt.Errorf("SamrConnect5: %w", err)
	}
	defer rpc.SamrCloseHandle(server)

	// The host's own local SAM SID: members below it are local accounts and
	// never produce a useful edge. A failed lookup leaves the prefix empty,
	// which keeps every member (BloodHound.py's "UNKNOWN" behaviour).
	localPrefix := ""
	if name := strings.TrimSuffix(strings.TrimSpace(samName), "$"); name != "" {
		if sid, e := rpc.SamrLookupDomain(server, name); e == nil && sid != nil {
			localPrefix = msdtyp.ConvertSIDtoStr(sid)
		}
	}

	builtin, err := msdtyp.ConvertStrToSID(builtinDomainSID)
	if err != nil {
		return nil, err
	}
	domain, err := rpc.SamrOpenDomain(server, mssamr.MaximumAllowed|samrDomainLookup, builtin)
	if err != nil {
		return nil, fmt.Errorf("SamrOpenDomain(%s): %w", builtinDomainSID, err)
	}
	defer rpc.SamrCloseHandle(domain)

	members = make(map[uint32][]string, len(rids))
	for _, rid := range rids {
		alias, err := rpc.SamrOpenAlias(domain, mssamr.MaximumAllowed|samrAliasListMembers, rid)
		if err != nil {
			// STATUS_NO_SUCH_ALIAS on a SKU without the alias, or access
			// denied: skip just this alias.
			continue
		}
		list, err := rpc.SamrGetMembersInAlias(alias)
		rpc.SamrCloseHandle(alias)
		if err != nil {
			continue
		}
		var sids []string
		for i := range list {
			sid := msdtyp.ConvertSIDtoStr(&list[i])
			if sid == "" || isLocalSID(sid, localPrefix) {
				continue
			}
			sids = append(sids, sid)
		}
		members[rid] = sids
	}
	return members, nil
}

// isLocalSID implements BloodHound.py's `not sid.startswith(self.sid)` test: a
// member below the host's own local-SAM SID is a local account and is ignored.
// An empty prefix keeps every member, matching BloodHound.py's "UNKNOWN" case.
func isLocalSID(sid, localPrefix string) bool {
	if localPrefix == "" {
		return false
	}
	return strings.HasPrefix(sid, localPrefix)
}

// lsaName is one resolved lsarpc name translation.
type lsaName struct {
	name   string
	domain string
	use    mslsad.SidNameUse
}

// resolveSIDs translates SIDs to names through lsarpc. It performs one lookup per
// SID, as BloodHound.py does, so an unmapped SID can never shift the mapping of
// the SIDs after it. SIDs the target refuses to name are absent from the map.
func resolveSIDs(h *smbHost, sids []string) map[string]lsaName {
	if len(sids) == 0 {
		return nil
	}
	bind, cleanup, err := h.rpc(mslsad.MSRPCLsaRpcPipe, mslsad.MSRPCUuidLsaRpc,
		mslsad.MSRPCLsaRpcMajorVersion, mslsad.MSRPCLsaRpcMinorVersion)
	if err != nil {
		return nil
	}
	defer cleanup()
	rpc := mslsad.NewRPCCon(bind)

	out := make(map[string]lsaName, len(sids))
	for _, sid := range sids {
		res, err := rpc.LsarLookupSids2(mslsad.LsapLookupWksta, []string{sid})
		if err != nil || len(res.TranslatedNames) == 0 {
			continue
		}
		tr := res.TranslatedNames[0]
		if tr.Name == "" {
			continue
		}
		info := lsaName{name: stripNUL(tr.Name), use: tr.Use}
		if tr.DomainIndex >= 0 && int(tr.DomainIndex) < len(res.ReferencedDomains) {
			info.domain = res.ReferencedDomains[tr.DomainIndex].Name
		}
		out[sid] = info
	}
	return out
}

// nodeFromLSA builds the node for a SID that only the target machine could name.
// It follows BloodHound.py's resolve_sid_entry: the account name with its domain,
// and the SID_NAME_USE class mapped to a BloodHound node kind.
func nodeFromLSA(sid string, info lsaName, fallbackDomain string) model.Node {
	kind := lsaKind(info.use)
	name := info.name
	if kind == model.KindComputer {
		name = strings.TrimSuffix(name, "$")
	}
	domain := info.domain
	if domain == "" {
		domain = fallbackDomain
	}
	return model.Node{
		ID:     sid,
		Kind:   kind,
		Name:   name,
		Domain: domain,
		Props:  map[string]string{"lsaresolved": "true"},
	}
}

// lsaKind maps LSA SID_NAME_USE to a BloodHound node kind the way
// BloodHound.py's translateSidType does: alias is really a domain-local group.
func lsaKind(use mslsad.SidNameUse) model.Kind {
	switch use {
	case mslsad.SidTypeUser:
		return model.KindUser
	case mslsad.SidTypeGroup, mslsad.SidTypeAlias:
		return model.KindGroup
	case mslsad.SidTypeComputer:
		return model.KindComputer
	case mslsad.SidTypeDomain:
		return model.KindDomain
	}
	return model.KindBase
}

// loggedOnEntry is one accepted NetrWkstaUserEnum row.
type loggedOnEntry struct {
	user   string
	domain string
}

// hostLoggedOn queries wkssvc NetrWkstaUserEnum level 1 and applies
// BloodHound.py's filtering: machine accounts and logons on the host's own local
// account domain are skipped.
func hostLoggedOn(h *smbHost, samName string) ([]loggedOnEntry, error) {
	bind, cleanup, err := h.rpc(mswkst.MSRPCWksSvcPipe, mswkst.MSRPCUuidWksSvc,
		mswkst.MSRPCWksSvcMajorVersion, mswkst.MSRPCWksSvcMinorVersion)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	res, err := mswkst.NewRPCCon(bind).EnumWkstLoggedOnUsers(1)
	if err != nil {
		return nil, fmt.Errorf("NetrWkstaUserEnum: %w", err)
	}
	if res == nil || res.Level1 == nil {
		return nil, nil
	}
	local := strings.TrimSuffix(strings.TrimSpace(samName), "$")
	seen := map[string]bool{}
	var out []loggedOnEntry
	for _, rec := range res.Level1.Buffer {
		user := strings.TrimSpace(stripNUL(rec.Username))
		domain := strings.TrimSpace(stripNUL(rec.LogonDomain))
		if user == "" || strings.HasSuffix(user, "$") {
			continue
		}
		if domain != "" && strings.EqualFold(domain, local) {
			continue // a local account of this machine
		}
		key := strings.ToLower(user) + "@" + strings.ToLower(domain)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, loggedOnEntry{user: user, domain: domain})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Name-to-node resolution
// ---------------------------------------------------------------------------

// sidIndex resolves the two kinds of name an SMB query returns back to node IDs:
// a SAM account name (sessions, logged-on users) and a host name (session
// sources).
type sidIndex struct {
	sam  map[string]string // lower(sAMAccountName) -> node ID
	host map[string]string // lower(dNSHostName or NAME.domain) -> node ID
	seen map[string]bool   // node IDs known to the graph
}

func newSIDIndex(g *model.Graph, domain string) *sidIndex {
	ix := &sidIndex{sam: map[string]string{}, host: map[string]string{}, seen: map[string]bool{}}
	for _, n := range g.Nodes {
		ix.record(n)
		// BloodHound.py's computersidcache is keyed on dNSHostname; adding the
		// short-name form lets a \\HOST session source resolve too.
		if n.Kind == model.KindComputer && n.Name != "" && domain != "" {
			ix.host[strings.ToLower(n.Name+"."+domain)] = n.ID
		}
	}
	return ix
}

func (ix *sidIndex) record(n model.Node) {
	if n.ID == "" {
		return
	}
	ix.seen[n.ID] = true
	if sam := strings.TrimSpace(n.SAMAccountName); sam != "" {
		ix.sam[strings.ToLower(sam)] = n.ID
	}
	if hn := strings.TrimSpace(n.Props["dnshostname"]); hn != "" {
		ix.host[strings.ToLower(hn)] = n.ID
	}
	if n.Kind == model.KindComputer && n.Name != "" {
		ix.host[strings.ToLower(n.Name)] = n.ID
	}
}

func (ix *sidIndex) has(id string) bool { return ix.seen[id] }

// userSID resolves a SAM account name to a node ID. A "DOMAIN\user" or
// "user@domain" form is accepted and reduced to the account name.
func (ix *sidIndex) userSID(sam string) (string, bool) {
	sam = bareUser(strings.TrimSpace(sam))
	id, ok := ix.sam[strings.ToLower(sam)]
	return id, ok
}

// sourceSID turns a NetSessionEnum client name (an IP, an IPv6 literal, or a bare
// \\HOST) into a computer node ID, following BloodHound.py: reverse DNS first,
// then the domain suffix when the name has none, then the host index.
func (ix *sidIndex) sourceSID(source, domain string) (string, bool) {
	s := strings.TrimSpace(source)
	s = strings.TrimPrefix(s, "\\\\")
	s = strings.Trim(s, "[]")
	if s == "" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() == nil || !ip.IsGlobalUnicast() {
			// BloodHound.py skips loopback and IPv6 sources.
			return "", false
		}
		names := ptrLookup(ip)
		if len(names) == 0 {
			return "", false
		}
		s = strings.TrimSuffix(names[0], ".")
		if strings.Contains(s, ":") {
			return "", false
		}
	}
	if !strings.Contains(s, ".") && domain != "" {
		s = s + "." + domain
	}
	id, ok := ix.host[strings.ToLower(s)]
	return id, ok
}

// hostOfNode returns the FQDN to dial for a computer node, or "" when the object
// carries no hostname (BloodHound.py skips those computers too).
func hostOfNode(n model.Node) string {
	return strings.TrimSpace(n.Props["dnshostname"])
}

// dcPrimaryGroupRID is "Domain Controllers". BloodHound.py skips local-group
// collection on a computer whose primary group SID ends in this RID.
const dcPrimaryGroupRID = "516"

// isDomainController reports whether a computer node is a domain controller,
// from its primaryGroupID (516). Absent the attribute the answer is "no", so an
// imported graph with no primary-group data still gets its local groups.
func isDomainController(n model.Node) bool {
	return strings.TrimSpace(n.Props["primarygroupid"]) == dcPrimaryGroupRID
}

// bareUser returns the account part of "DOMAIN\user" or "user@domain".
func bareUser(u string) string {
	if i := strings.IndexByte(u, '\\'); i >= 0 {
		return u[i+1:]
	}
	if i := strings.IndexByte(u, '@'); i >= 0 {
		return u[:i]
	}
	return u
}
