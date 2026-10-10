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
| Pass-the-hash (`--hashes`) | ✓ | roadmap — fails loudly |
| NTLM auth (`--auth-method ntlm`) | ✓ | roadmap |

OmenHound refuses to silently fall back. If you pass an unsupported auth method, it
tells you it is not implemented instead of collecting with weaker guarantees.

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
| `trusts` | ✓ | not implemented |
| `acl` | ✓ | not implemented |
| `container` | ✓ | not implemented |
| `dcom` / `rdp` / `psremote` | ✓ | not implemented |
| `all`, `default` | ✓ | expand to the above |

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
