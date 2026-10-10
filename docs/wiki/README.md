# OmenHound wiki

This directory is the **source of truth** for the OmenHound wiki. Each `*.md` file maps
to a wiki page (`_Sidebar.md` → the navigation sidebar, `_Footer.md` → the footer), and
`img/` holds the WebUI screenshots referenced by the guides.

## Regenerate the screenshots

```bash
make build
./bin/omenhound serve --collector sample --addr 127.0.0.1:18091 --api-token operator-secret &
python3 scripts/shots.py http://127.0.0.1:18091 docs/wiki/img
```

## Publish to GitHub

GitHub creates the wiki git repository only **after the first page exists** (there is no
API to initialise it):

1. Open <https://github.com/krazybeastx1/omenhound/wiki> and click **Create the first
   page** (title `Home`, content anything). Save.
2. Run:

   ```bash
   scripts/publish-wiki.sh
   ```

The script syncs every page in this directory, plus `img/`, into
`omenhound.wiki.git` and pushes.
