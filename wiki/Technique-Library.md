# Technique Library (Read + Add)

OmenHound ships a browsable **technique library** — the same offensive-playbook
knowledge the abuse panel renders per edge, but grouped by operator intent and
independent of any particular graph selection.

Every technique is a pair:

- **Read** — the verification/enumeration step: confirm the condition or current
  state *before* acting (e.g. `impacket-dacledit -action read …`).
- **Add** — the act/abuse step (the JSON field is `command`; the UI labels it "Add").

Both are reference strings with `{PLACEHOLDER}` tokens. **OmenHound never executes
them** — they are guidance for a human operator.

---

## Where it lives

Two Go files hold the whole library:

| File | Role |
|---|---|
| `internal/abuse/templates.go` | `Template{Edge, Summary, Read, Command, Alternates, OPSEC, EventIDs, RequiresAuth}` keyed by edge kind in the `Templates` map — **33 entries**. The single source of truth. |
| `internal/abuse/playbook.go` | The presentation layer: `edgeGroup`/`edgeEntry` headings that *reference* edge kinds (title + tags only), plus `playbookExtraGroups` for techniques with no single edge. |

The `Playbook()` function walks the edge groups, looks each `edgeEntry.kind` up in
`Templates`, and copies Summary/Read/Command/Alternates/OPSEC/EventIDs/RequiresAuth
into a `PlaybookTechnique`, keeping the operator-facing title and tags. Because the
edge-backed entries pull straight from `Templates`, **the library and the per-edge
renderer can never drift apart.**

---

## The categories

| Category | Title | Techniques | Backing |
|---|---|---|---|
| `acl` | Access control (ACL) | 13 | edge-backed |
| `credentials` | Credential access | 7 | edge-backed |
| `delegation` | Delegation | 3 | edge-backed |
| `remote` | Remote execution & sessions | 5 | edge-backed |
| `structure` | Directory structure & trust | 5 | edge-backed |
| `coercion` | Coercion & relay | 6 | standalone |
| `adcs` | AD CS (certificate services) | 5 | standalone |
| `roasting` | Roasting, GPP & tickets | 5 | standalone |
| `cve` | Known CVEs | 3 | standalone |
| `setup` | Recon & setup | 2 | standalone |

**10 categories / 54 techniques** = **33 edge-backed** + **21 standalone**.

- **Edge-backed** — tied to a graph relationship (`GenericAll`, `DCSync`, `AdminTo`,
  …). The very same string, rendered with real source/target properties, is what the
  abuse panel shows when you select that edge in the UI.
- **Standalone** — no single edge represents them (coercion methods, AD CS
  misconfigurations, roasting, CVEs, recon). Tool invocations written inline in
  `playbookExtraGroups`.

---

## The placeholder rule

Edge templates only use tokens the renderer can derive from graph nodes:

```
{DOMAIN} {DC} {SOURCE_SAM} {SOURCE_DN} {SOURCE_SID} {SOURCE_NAME}
{TARGET_SAM} {TARGET_DN} {TARGET_SID} {TARGET_NAME}
```

Tokens that are inherently manual appear **only** in standalone techniques, which
are never auto-interpolated:

```
{TARGET_FQDN} {LISTENER} {CA} {TEMPLATE} {SPN}
{KRBTGT_HASH} {SERVICE_HASH} {DOMAIN_SID} {AES256}
```

Rendered per-edge, any node property that cannot be resolved becomes `<unknown>`
and a human-readable entry is added to `warnings[]` — a command is never silently
emitted broken.

---

## Two render modes

| Mode | Endpoint | Placeholders |
|---|---|---|
| **Library** (edge-agnostic) | `GET /api/v1/abuse/playbook` | left literal `{TARGET_SAM}` |
| **Per-edge** (concrete) | `GET /api/v1/abuse?src=&kind=&dst=` | interpolated with real values |

Per-edge interpolation (`internal/abuse/abuse.go`): `buildVars()` reads the two
nodes and fills the node-derivable tokens — domain prefers the target's then the
source's; `{DC}` comes from the node's `dc` property, else `DC.<domain>`; SAM falls
back to `name`. Everything it cannot resolve becomes `<unknown>` plus a `warnings[]`
entry (honest, never silent).

```
templates.go (Templates: 33) ─┬─> Playbook() ──> /abuse/playbook ──> UI empty panel · nxc MODE=playbook
                              │
                              └─> Render(edge, src, tgt) ─> /abuse?src&kind&dst ─> edge panel · modal · nxc MODE=target
playbook.go (grouping + 21 standalone) ────> Playbook()
```

---

## Consumers

| Consumer | Sees |
|---|---|
| **Web Inspector** — empty state (nothing selected) | the grouped library, searchable, collapsible, copy-per-step |
| **Web Inspector** — edge panel and modal | the **per-edge** render: Read + Add + alternates + OPSEC + event IDs + warnings |
| **HTTP API** | `GET /api/v1/abuse/playbook` (library) and `GET /api/v1/abuse?src=&kind=&dst=` (per-edge) |
| **NetExec module** — `nxc -M omenhound` | `MODE=playbook` prints the library; `MODE=target` resolves the host/account you logged in with and prints the Read/Add steps for its outgoing edges. See [contrib/nxc](https://github.com/krazybeastx1/omenhound/blob/main/contrib/nxc/README.md). |

---

## Guardrails

- **Print-only.** Nothing in the playbook is ever executed by OmenHound.
- **Read is additive** — a separate verify step, never a replacement for the act step.
- **No drift.** Edge-backed entries are generated from `Templates`, the same map the
  per-edge renderer uses.
- **No lying.** Missing node data becomes `<unknown>` + a `warnings[]` entry, and the
  UI says data coverage is unknown rather than implying exploitability.

---

## Related

- [Web UI Guide](Web-UI-Guide) — the Inspector includes the library when nothing is selected.
- [API Reference](API-Reference) — `/api/v1/abuse`, `/api/v1/abuse/supported`, `/api/v1/abuse/playbook`.
- [Neo4j Schema & Attack Paths](Neo4j-Schema-and-Attack-Paths) — the edges each technique maps to.
- [contrib/nxc](https://github.com/krazybeastx1/omenhound/blob/main/contrib/nxc/README.md) — the NetExec module that surfaces this library from the shell.