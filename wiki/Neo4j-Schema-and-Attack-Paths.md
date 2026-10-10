# Neo4j Schema & Attack Paths

OmenHound writes Neo4j using **BloodHound CE's label and relationship model**, so
existing BloodHound Cypher, tooling and mental models keep working — and imported
(BloodHound.py/CE) objects merge with collected ones **by SID**.

## Labels

Every node has an `id` (the AD SID, or the objectGUID for non-SID objects) and **exactly
one** label:

`User` · `Group` · `Computer` · `Domain` · `OU` · `GPO` · `Container` · `Trust`

`Base` is used for **placeholder nodes** — an endpoint referenced by an edge but not
collected. Placeholders let the graph stay referentially valid without inventing data.

Uniqueness constraints are created automatically at startup:

```cypher
CREATE CONSTRAINT User_id IF NOT EXISTS FOR (n:User) REQUIRE n.id IS UNIQUE
-- … one per label
```

## Relationship types

```
GenericAll        GenericWrite      WriteDacl         WriteOwner
ForceChangePassword                 AddMember         AddSelf
Owns              AllExtendedRights WriteSPN          WriteAccountRestrictions
WriteGPLink       WriteAltSecurityIdentities
AddKeyCredentialLink                AddAllowedToAct
AllowedToDelegate AllowedToAct      AdminTo           CanPSRemote
ExecuteDCOM       CanRDP            HasSession        DCSync
GetChanges        GetChangesAll     GetChangesInFilteredSet
ReadLAPSPassword  ReadGMSAPassword  DumpSMSAPassword
MemberOf          Contains          GPLink            TrustedBy
```

Every relationship is a **whitelisted** string (injection-proof) and every one of them
has an abuse template.

## Directions

OmenHound follows **BloodHound CE directions** exactly:

| Relationship | Direction | Cypher | Meaning |
|---|---|---|---|
| `MemberOf` | member → group | `(u:User)-[:MemberOf]->(g:Group)` | `u` is a member of `g` |
| `AdminTo` | principal → computer | `(u)-[:AdminTo]->(c:Computer)` | `u` is local admin on `c` |
| `HasSession` | user → computer | `(u)-[:HasSession]->(c)` | `u` has a session on `c` |
| `DCSync` | principal → domain | `(u)-[:DCSync]->(d:Domain)` | `u` can replicate from `d` |
| `GPLink` | **GPO → container** | `(g:GPO)-[:GPLink]->(ou:OU)` | `g` is linked at `ou`/domain/site |
| `Contains` | container → child | `(d:Domain)-[:Contains]->(u)` | structural containment |
| `TrustedBy` | trusted → trusting | `(a:Domain)-[:TrustedBy]->(b:Domain)` | `a` is trusted by `b` |
| `AllowedToDelegate` | computer → target | `(c:Computer)-[:AllowedToDelegate]->(t)` | constrained delegation to `t` |
| `AllowedToAct` | principal → computer | `(u)-[:AllowedToAct]->(c)` | RBCD: `u` may act for `c` |
| `GPLink` carries `enforced` | — | `props.enforced` | GPO link is enforced |

## Example Cypher

Shortest path from a compromised user to Domain Admins:

```cypher
MATCH p = shortestPath(
  (u:User {sam_account_name:'jdoe'})-[*1..]->(g:Group)
)
WHERE g.name = 'DOMAIN ADMINS@OMENHOUND.LAB'
RETURN p
```

Everything a principal can reach in ≤ 3 hops:

```cypher
MATCH p = (u:User {id:$sid})-[*1..3]->(n)
RETURN p
```

Computers where a user is local admin and has a session:

```cypher
MATCH (u:User {sam_account_name:'jdoe'})-[:AdminTo]->(c:Computer),
      (u)-[:HasSession]->(c)
RETURN c.name
```

Unconstrained-delegation style paths (`AllowedToDelegate`) into the DC:

```cypher
MATCH p = (c:Computer)-[:AllowedToDelegate*1..]->(d:Domain)
RETURN p
```

GPOs that grant full control of an OU:

```cypher
MATCH (g:GPO)-[l:GPLink]->(ou:OU)
RETURN g.name, ou.name, l.enforced
```

Kerberoastable / AS-REP-roastable users (if collected in `props`):

```cypher
MATCH (u:User)
WHERE u.serviceprincipalnames <> '' AND u.enabled = 'true'
RETURN u.sam_account_name, u.serviceprincipalnames
```

## Node properties

Node fields (`id`, `kind`, `name`, `domain`, `sam_account_name`,
`distinguished_name`) are written as first-class Neo4j properties, and `props` may carry
collector-specific attributes (`enabled`, `admincount`, `pwdlastset`, `serviceprincipalnames`,
`description`, `whencreated`, `lastlogon`, …).

## Attack-path reference

[`docs/ATTACK-PATHS.md`](https://github.com/krazybeastx1/omenhound/blob/main/docs/ATTACK-PATHS.md)
is the full per-edge catalogue: meaning, primary command, alternates, OPSEC, event IDs,
and preconditions. `GET /api/v1/abuse/supported` returns the edge list the renderer
supports.

Next: **[Coming from BloodHound.py](Coming-from-BloodHound-py)** →
