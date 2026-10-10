# OmenHound wiki

This directory is the **source of truth** for the OmenHound documentation, and it is
written in GitHub-wiki format so it can be published as-is:

| File | Becomes |
|---|---|
| `Home.md` | the wiki home page |
| `*.md` | one wiki page each (`-` becomes a space in the title) |
| `_Sidebar.md` | the wiki navigation sidebar |
| `_Footer.md` | the wiki footer |
| `img/` | the screenshots referenced by the guides |

It is also perfectly readable **directly on GitHub**:
<https://github.com/krazybeastx1/omenhound/tree/main/wiki>

## Pages

- [Home](Home)
- [Getting Started](Getting-Started)
- [How It Works](How-It-Works)
- [Web UI Guide](Web-UI-Guide)
- [Operations & Hardening](Operations-and-Hardening)
- [API Reference](API-Reference)
- [Neo4j Schema & Attack Paths](Neo4j-Schema-and-Attack-Paths)
- [Coming from BloodHound.py](Coming-from-BloodHound-py)
- [Roadmap](Roadmap)

## Regenerate the screenshots

```bash
make build
./bin/omenhound serve --collector sample --addr 127.0.0.1:18091 --api-token operator-secret &
python3 scripts/shots.py http://127.0.0.1:18091 wiki/img
```

## Publish to the GitHub wiki (optional)

GitHub creates the wiki git repository only **after the first page exists** — there is no
API to initialise it, and pushing to a non-existent `*.wiki.git` fails:

```
remote: Repository not found.
```

To publish these pages as a real GitHub wiki:

1. Open <https://github.com/krazybeastx1/omenhound/wiki> and click **Create the first
   page** (title `Home`, content anything). Save.
2. Run:

   ```bash
   scripts/publish-wiki.sh
   ```

The script syncs every page in this directory, plus `img/`, into
`omenhound.wiki.git` and pushes. Re-run it any time the docs change.

> Until the wiki is initialised, this directory is the canonical, browsable copy.
