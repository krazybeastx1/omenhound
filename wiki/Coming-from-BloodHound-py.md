# Coming from BloodHound.py

OmenHound is designed to sit **alongside** your existing `bloodhound-ce-python`
workflow, not replace it. You can bring your tooling and your data.

## Your command still works

```bash
bloodhound-ce-python -d cascade.local -u s.smith -p 'sT333ve2' -ns 10.129.46.41 -c all --zip
```

Import the resulting archive:

```bash
./bin/omenhound import --in <prefix>_cascade.local_bloodhound.zip --out cascade.json
```

The importer reads **BloodHound CE v5 JSON** and BloodHound.py `--zip` archives (zip,
directory, or a single `.json`). It preserves SIDs/GUIDs verbatim, follows CE edge
directions, and **reports** anything it can't map.

## Auth methods

| Method | BloodHound.py | OmenHound (now) |
|---|---|---|
| LDAP simple bind + LDAPS | ✓ | **✓ supported** |
| LDAP simple bind + Kerberos (`-k`, `--kerberos`) | ✓ | **✓** (password, NT hash, AES key, or `$KRB5CCNAME`) |
| Pass-the-hash (`--hashes`) | ✓ | **✓** (`NT` or `LM:NT`; implies NTLM) |
| NTLM auth (`--auth-method ntlm`) | ✓ | **✓** (plain password, hash, or empty password) |

OmenHound refuses to silently fall back. An unknown auth method is rejected, and a
Kerberos run with no credential source is refused before any traffic, instead of
dropping to a weaker bind.

NTLM and pass-the-hash use go-ldap's built-in NTLMSSP bind, so there is no extra
dependency and no weaker protocol. Only the **NT** half of `--hashes` is used — the LM
half is discarded because NTLMSSP derives the response from the NT hash. As with simple
bind, a cleartext (non-LDAPS) NTLM bind is refused unless you pass
`--allow-plaintext-ldap`, because NTLM over cleartext LDAP is relayable.

Kerberos (`-k`) authenticates LDAP with a **GSSAPI SASL bind** and SMB with a **cifs
service ticket**, both from one credential source: a password, an NT hash
(`--hashes`, RC4-HMAC overpass-the-hash), an AES key (`--aes-key`), or an existing
ccache (`--use-kcache`, `$KRB5CCNAME`). It needs the DC **hostname** (`--server
dc01.corp.local`), because a service ticket is issued for a name, not an address;
`--dc-ip` supplies the KDC address when that name does not resolve. As with
BloodHound.py, OmenHound never prompts — use `--password-stdin` or
`$OMENHOUND_PASSWORD`.

> **Validation status.** The hash/AES-key parsing (impacket's `LM:NT` and bare-NT
> forms), the `DOMAIN\user` / `user@domain` split, the SPN construction, the KDC
> selection, the auth-method resolution and every refusal path are unit-tested. The
> handshakes themselves — NTLMSSP, LDAP GSSAPI SASL and SMB Kerberos — are
> **code-only**: no AD lab was available for end-to-end Kerberos/NTLM handshakes.
> Note: LDAP **simple bind** has been exercised against a live domain controller; other
> auth modes (NTLM/Kerberos over LDAP/SMB) remain code-only.

`--use-ldaps` and `-ns/--nameserver` (DC SRV discovery) behave as you expect.
`--ldap-channel-binding` is accepted for parity and documented as a **no-op for simple
bind over TLS**.

## Collection methods

Requested methods are planned up front. Unknown method names are reported as
`not implemented — skipped`; they are never silently dropped. Every BloodHound.py
method is implemented.

| Method | BloodHound.py | OmenHound (now) |
|---|---|---|
| `group` | ✓ | **✓** |
| `objectprops` | ✓ | **✓** |
| `dc` / `dconly` | ✓ | expands (see notes) |
| `localadmin` | ✓ | **✓** (SMB/samr — see status note) |
| `session` | ✓ | **✓** (SMB/srvsvc — see status note) |
| `loggedon` | ✓ | **✓** (SMB/wkssvc — see status note) |
| `trusts` | ✓ | **✓** (see status note) |
| `acl` | ✓ | **✓** (see status note) |
| `container` | ✓ | **✓** (see status note) |
| `dcom` / `rdp` / `psremote` | ✓ | **✓** (SMB/samr — see status note) |
| `all`, `default` | ✓ | expand to the above |

**ACL collection is now native** (`-c acl`). OmenHound reads each object's
`nTSecurityDescriptor` (owner + DACL) and applies the same ACE→edge rules as
BloodHound.py: `Owns`, `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`,
`AddMember`, `AddSelf`, `AllExtendedRights`, `GetChanges`, `GetChangesAll`,
`GetChangesInFilteredSet`, `ForceChangePassword`, `ReadLAPSPassword`, `WriteSPN`,
`AddKeyCredentialLink`, `WriteAccountRestrictions`, `AddAllowedToAct`,
`WriteGPLink`. The pass is self-sufficient — it also creates the OU/GPO/container
nodes it needs — so `-c acl` works on its own.

**Structure collection is now native** (`-c container`). GPOs, OUs and containers
are collected as nodes keyed by `objectGUID` (BloodHound's canonical uppercase form);
each container's direct children become `Contains` edges and each container's `gPLink`
becomes `GPO -GPLink-> container` edges, with `enforced` recorded for option-2 links.
Disabled links (option `1`/`3`) are omitted exactly as BloodHound.py does, and a link
whose GPO was not enumerated keeps its edge by taking the GUID out of the link DN.

**Trust collection is now native** (`-c trusts`). `trustedDomain` objects under
`CN=System` become `TrustedBy` edges between `Domain` nodes in BloodHound's direction
(`(trusted domain) -TrustedBy-> (trusting domain)`) from `trustDirection`; the peer is
keyed by its domain SID. `trustAttributes` is classified into BloodHound's trust type,
transitivity and SID-filtering triple (ported from `ADDomainTrust.to_output`) and
carried on the edge. `-c dc` / `-c dconly` now expands to methods that are **all**
implemented, so it skips nothing.

**SMB/RPC collection is now native** (`-c session,localadmin,rdp,dcom,psremote,loggedon`).
Over one authenticated SMB session per computer (DCE/RPC over named pipes), OmenHound
makes the same calls BloodHound.py does:

| Method | RPC call | Edge |
|---|---|---|
| `session` | srvsvc `NetrSessionEnum` level 10 | `User -HasSession-> Computer` (the session's **source** host) |
| `loggedon` | wkssvc `NetrWkstaUserEnum` level 1 | `User -HasSession-> Computer` (the queried host) |
| `localadmin` | samr alias **544** members | `Principal -AdminTo-> Computer` |
| `rdp` | samr alias **555** members | `Principal -CanRDP-> Computer` |
| `dcom` | samr alias **562** members | `Principal -ExecuteDCOM-> Computer` |
| `psremote` | samr alias **580** members | `Principal -CanPSRemote-> Computer` |

Filtering and resolution mirror BloodHound.py: the operator's own session, empty
users, machine accounts (`user$`) and loopback sources are dropped; local-group
members below the host's own local SAM SID are dropped; local groups are
**skipped on domain controllers** (their local groups are the domain's builtin
groups, matching BloodHound.py's `primarygroup.endswith('-516')`); session accounts
resolve through a SAM-name index, session sources through reverse DNS then the
`dNSHostname`/short-name index; and a member the graph does not already know is named
by the target over lsarpc `LsarLookupSids2`, **one SID per call** so an unmapped SID
cannot shift the mapping of the ones after it. A SID the target will not name is
dropped and counted — never invented.

Pass-the-hash works over SMB too: `--hashes NT` (or `LM:NT`) authenticates the SMB
session with the raw NT hash, exactly as it authenticates the LDAP bind.

Computers are queried **sequentially**, one at a time (an OPSEC choice, not a
limitation of the protocol). Each dial is bounded at 10 s and all RPC work against a
host at 30 s, but the run's `--timeout` is the overall budget — raise it for a large
domain (`--timeout 30m` for a /24). BloodHound.py's `tcp_ping`-style reachability gate
is preserved, so dead hosts cost a connect attempt rather than an SMB negotiation.

Known divergences from BloodHound.py, all reported as warnings: **no port-139
(NetBIOS session service) fallback** — the SMB library speaks only direct
SMB-over-TCP on 445; **no unauthenticated NTLM hostname lookup** when a session source
has no PTR record (such a source is dropped rather than guessed); and `loggedon` reads
**wkssvc only**, not registry (`winreg`) logon sessions.

> **Validation status.** The SMB pass's filtering, name/SID resolution, kind mapping
> and wiring are unit-tested (`smb_test.go`). The **live SMB/RPC path is code-only**:
> no SMB-capable host was available, so the SMB handshake, the srvsvc/samr/wkssvc/lsarpc
> calls and the pipe I/O have not been exercised end to end — treat first contact with
> a real host as unverified.

> **Validation status.** The descriptor parser and the ACE→edge mapping are
> unit-tested against security descriptors built to `[MS-DTYP]` and independently
> re-parsed with **impacket** (the library BloodHound.py itself uses). The
> `-c container` and `-c trusts` parsers (gPLink, GPO-DN GUID extraction, the
> filtered-container rules, class→kind, trust classification) are unit-tested too.
> The **live LDAP path** — schema GUID fetch, the `LDAP_SERVER_SD_FLAGS` control,
> the per-object and per-child searches, and the `trustedDomain` search — is
> **code-only**: no AD lab was available to run it end to end, so treat first
> contact with a real DC as unverified.

Every collection method is now native, so **import** is no longer needed to fill
*method* gaps — it remains the way to bring in **existing** BloodHound data (for
example, to merge a CE run, or to add delegation edges the collector does not yet
emit). The importer follows CE edge directions and keeps those edges fully available
to the abuse engine and the UI.

```bash
# fill the gaps with your existing tool
bloodhound-ce-python -d cascade.local -u s.smith -p '...' -ns 10.129.46.41 -c all --zip
# merge it into OmenHound (CE schema, SID-keyed)
./bin/omenhound import --in cascade.local_bloodhound.zip --out cascade.json
./bin/omenhound import --in cascade.local_bloodhound.zip --api http://127.0.0.1:8080 --token "$TOKEN"
```

## Mapping notes (what the importer translates)

- **ACE rights → edges**: `GenericAll, GenericWrite, WriteDacl, ForceChangePassword,
  AddMember, AddSelf, AllExtendedRights, GetChanges, GetChangesAll,
  GetChangesInFilteredSet, ReadLAPSPassword, ReadGMSAPassword, AddKeyCredentialLink,
  WriteSPN, WriteAccountRestrictions, AddAllowedToAct, WriteGPLink,
  WriteAltSecurityIdentities, DumpSMSAPassword`. Aliases: `Owner` → `Owns`,
  `WriteOwnerLimitedRights` → `WriteOwner`.
- **Local-admin / remote-access results** → `AdminTo`, `CanRDP`, `ExecuteDCOM`,
  `CanPSRemote`. Both the legacy layout (`LocalAdmins`/`PSRemoteUsers`/
  `RemoteDesktopUsers`/`DcomUsers`) and BloodHound CE v5 `LocalGroups` are read;
  the latter is collapsed to the same direct member → computer edges BloodHound CE
  derives in its analysis phase.
- **Sessions** → `HasSession` (user → computer).
- **Delegation** → `AllowedToDelegate`, `AllowedToAct`.
- **`ChildObjects`** → `Contains`; **`Links`** → `GPLink` (with `enforced`);
  **`Trusts`** → `TrustedBy` (per direction bits).
- Rights with **no** OmenHound edge are counted and listed — never fabricated.

## Output compatibility

`--zip` on `omenhound collect` writes a **BloodHound CE v5 archive**
(`users/groups/computers/ous/gpos/containers/domains.json` + `meta`), so you can feed
OmenHound collections to BloodHound CE. `omenhound import` reads them back.
Import → export → import round-trips losslessly on the test fixture.

## Exit codes / behaviour on gaps

| Situation | Result |
|---|---|
| Unknown collection method | error listing known methods |
| Some methods unimplemented | run proceeds + explicit warnings in `Meta.Warnings` |
| Unknown auth method | error before any traffic |
| Kerberos with no credentials / against an IP | error before any traffic (a ticket needs a hostname) |
| `--use-kcache` with no `$KRB5CCNAME` | error before any traffic |
| Plaintext LDAP requested | refusal unless `--allow-plaintext-ldap` |
| SMB methods requested with no password/hash | run proceeds; LDAP-only graph + explicit warning |
| SMB host unreachable / RPC denied | counted, reported in `Meta.Warnings`, run continues |

Next: **[Roadmap](Roadmap)** →
