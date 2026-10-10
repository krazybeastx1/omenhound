// Package bloodhound imports BloodHound CE (v5) JSON output — including the
// `--zip` archives produced by BloodHound.py — into OmenHound's graph model.
//
// Node identifiers used by BloodHound CE are kept verbatim: objectSIDs for
// users/groups/computers/domains and objectGUIDs for OUs, GPOs and containers.
// Relationship directions follow the BloodHound CE schema so existing Cypher
// queries keep working against a Neo4j store: MemberOf is member -> group,
// GPLink is GPO -> linked container, Contains is container -> child, and
// TrustedBy is trusted -> trusting domain.
package bloodhound

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/krazybeastx1/omenhound/pkg/model"
)

// Report gives an honest accounting of an import: what was parsed, what was
// materialized as nodes/edges, and what was deliberately skipped (with
// reasons), so no result is ever silently fabricated.
type Report struct {
	Source        string         `json:"source"`
	Files         []string       `json:"files"`
	ByFile        map[string]int `json:"by_file,omitempty"`            // file -> objects parsed
	Nodes         int            `json:"nodes"`                        // nodes materialized
	Edges         int            `json:"edges"`                        // edges materialized
	Placeholders  int            `json:"placeholder_nodes"`            // nodes synthesized for unknown IDs
	Skipped       map[string]int `json:"skipped,omitempty"`            // reason -> objects dropped
	UnknownRights map[string]int `json:"unknown_ace_rights,omitempty"` // unmapped ACE right names
	Domain        string         `json:"domain,omitempty"`
}

// Load reads a BloodHound CE zip archive, a directory of JSON files, or a
// single JSON file and returns the corresponding OmenHound graph.
func Load(path string) (*model.Graph, *Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("bloodhound: open %s: %w", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("bloodhound: stat %s: %w", path, err)
	}
	if st.IsDir() {
		return loadDir(path)
	}
	if isZipFile(f, path) {
		return loadZip(path)
	}
	rpt := &Report{Source: path, ByFile: map[string]int{}, Skipped: map[string]int{}, UnknownRights: map[string]int{}}
	g, err := loadFiles([]namedReader{{name: filepath.Base(path), r: f}}, rpt)
	if err != nil {
		return nil, nil, err
	}
	return g, rpt, nil
}

func isZipFile(f *os.File, path string) bool {
	if strings.HasSuffix(strings.ToLower(path), ".zip") {
		return true
	}
	var head [4]byte
	n, _ := f.ReadAt(head[:], 0)
	return n == 4 && head[0] == 'P' && head[1] == 'K' && (head[2] == 3 || head[2] == 5)
}

func loadDir(dir string) (*model.Graph, *Report, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("bloodhound: glob %s: %w", dir, err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("bloodhound: no *.json files in %s (pass the .zip or its directory)", dir)
	}
	rpt := &Report{Source: dir, ByFile: map[string]int{}, Skipped: map[string]int{}, UnknownRights: map[string]int{}}
	nrs := make([]namedReader, 0, len(files))
	for _, path := range files {
		if isZipFileMust(path) {
			continue // nested archives are out of scope
		}
		nrs = append(nrs, namedReader{name: filepath.Base(path), path: path})
	}
	g, err := loadFiles(nrs, rpt)
	if err != nil {
		return nil, nil, err
	}
	return g, rpt, nil
}

func isZipFileMust(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return isZipFile(f, path)
}

func loadZip(path string) (*model.Graph, *Report, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, fmt.Errorf("bloodhound: open zip %s: %w", path, err)
	}
	defer zr.Close()

	var names []string
	byName := make(map[string]*zip.File, len(zr.File))
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || strings.HasPrefix(zf.Name, "__MACOSX") ||
			!strings.HasSuffix(strings.ToLower(zf.Name), ".json") {
			continue
		}
		names = append(names, zf.Name)
		byName[zf.Name] = zf
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("bloodhound: no JSON files inside %s", path)
	}

	rpt := &Report{Source: path, ByFile: map[string]int{}, Skipped: map[string]int{}, UnknownRights: map[string]int{}}
	nrs := make([]namedReader, 0, len(names))
	for _, name := range names {
		nrs = append(nrs, namedReader{name: name, zip: byName[name]})
	}
	g, err := loadFiles(nrs, rpt)
	if err != nil {
		return nil, nil, err
	}
	return g, rpt, nil
}

type namedReader struct {
	name string
	path string
	zip  *zip.File
	r    io.Reader
}

// loadFiles parses every source in deterministic order. It first collects
// nodes, edges and kind guesses, then synthesizes placeholder nodes for any
// edge endpoint that was not collected so the resulting graph passes
// referential-integrity validation.
func loadFiles(sources []namedReader, rpt *Report) (*model.Graph, error) {
	b := newBuilder(rpt)
	for _, sr := range sources {
		var r io.ReadCloser
		var err error
		switch {
		case sr.r != nil:
			r = io.NopCloser(sr.r)
		case sr.zip != nil:
			r, err = sr.zip.Open()
		case sr.path != "":
			r, err = os.Open(sr.path)
		}
		if err != nil {
			return nil, fmt.Errorf("bloodhound: open %s: %w", sr.name, err)
		}
		err = b.parseFile(r, sr.name)
		_ = r.Close()
		if err != nil {
			return nil, err
		}
		rpt.Files = append(rpt.Files, sr.name)
	}
	b.finish()
	g := b.graph()
	rpt.Nodes = len(g.Nodes)
	rpt.Edges = len(g.Edges)
	rpt.Placeholders = b.placeholders
	rpt.Domain = b.domain
	return g, nil
}
