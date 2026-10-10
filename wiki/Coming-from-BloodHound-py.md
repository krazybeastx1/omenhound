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
| LDAP simple bind + Kerberos (`-k`, `--kerberos`) | ✓ | roadmap — fails loudly until implemented |
| Pass-the-hash (`--hashes`) | ✓ | **✓** (`NT` or `LM:NT`; implies NTLM) |
| NTLM auth (`--auth-method ntlm`) | ✓ | **✓** (plain password, hash, or empty password) |

OmenHound refuses to silently fall back. If you pass an unsupported auth method, it
tells you it is not implemented instead of collecting with weaker guarantees.

NTLM and pass-the-hash use go-ldap's built-in NTLMSSP bind, so there is no extra
dependency and no weaker protocol. Only the **NT** half of `--hashes` is used — the LM
half is discarded because NTLMSSP derives the response from the NT hash. As with simple
bind, a cleartext (non-LDAPS) NTLM bind is refused unless you pass
`--allow-plaintext-ldap`, because NTLM over cleartext LDAP is relayable.

> **Validation status.** The hash parsing (impacket's `LM:NT` and bare-NT forms), the
> `DOMAIN\user` / `user@domain` split, the auth-method resolution and every refusal path
> are unit-tested. The bind itself is **code-only**: no AD lab was available, so the
> NTLMSSP handshake has not been exercised against a real DC.

`--use-ldaps` and `-ns/--nameserver` (DC SRV discovery) behave as you expect.
`--ldap-channel-binding` is accepted for parity and documented as a **no-op for simple
bind over TLS**.

## Collection methods

Requested methods are planned up front. What OmenHound can't collect yet is reported as
`not implemented — skipped`; it is never silently dropped.

| Method | BloodHound.py | OmenHound (now) |
|---|---|---|
| `group` | ✓ | **✓** |
| `objectprops` | ✓ | **✓** |
| `dc` / `dconly` | ✓ | expands (see notes) |
| `localadmin` | ✓ | not implemented |
| `session` / `loggedon` | ✓ | not implemented |
| `trusts` | ✓ | **✓** (see status note) |
| `acl` | ✓ | **✓** (see status note) |
| `container` | ✓ | **✓** (see status note) |
| `dcom` / `rdp` / `psremote` | ✓ | not implemented |
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

> **Validation status.** The descriptor parser and the ACE→edge mapping are
> unit-tested against security descriptors built to `[MS-DTYP]` and independently
> re-parsed with **impacket** (the library BloodHound.py itself uses). The
> `-c container` and `-c trusts` parsers (gPLink, GPO-DN GUID extraction, the
> filtered-container rules, class→kind, trust classification) are unit-tested too.
> The **live LDAP path** — schema GUID fetch, the `LDAP_SERVER_SD_FLAGS` control,
> the per-object and per-child searches, and the `trustedDomain` search — is
> **code-only**: no AD lab was available to run it end to end, so treat first
> contact with a real DC as unverified.

Where a gap exists, **import** is the bridge: collect the missing data with
BloodHound.py/CE and `omenhound import` it. The graph then contains those edges (ACL
rights, sessions, local-admin, delegation, trust direction, GPO links) with correct CE
directions, and they are fully available to the abuse engine and the UI.

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
  `CanPSRemote`.
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
| Only unimplemented methods requested | **refusal** with the implemented set |
| Some methods unimplemented | run proceeds + explicit warnings in `Meta.Warnings` |
| Unsupported auth method (NTLM/Kerberos/hash) | loud "not implemented", no collection |
| Plaintext LDAP requested | refusal unless `--allow-plaintext-ldap` |

Next: **[Roadmap](Roadmap)** →
