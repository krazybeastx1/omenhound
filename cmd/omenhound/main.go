// Command omenhound is a BloodHound-style Active Directory attack-path tool:
// a collector, a graph API/server, and an export utility in one binary.
//
//	omenhound collect --collector ldap --domain corp.local --server dc01 --username svc --password-stdin --out graph.json
//	omenhound serve --collector sample --addr 127.0.0.1:8080
//	omenhound export --in graph.json --format json --out out.json
//
// WARNING: OmenHound is dual-use security tooling. Only use it against systems
// you own or have explicit written authorization to test.
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/krazybeastx1/omenhound/internal/act"
	"github.com/krazybeastx1/omenhound/internal/api"
	"github.com/krazybeastx1/omenhound/internal/audit"
	"github.com/krazybeastx1/omenhound/internal/collector"
	"github.com/krazybeastx1/omenhound/internal/graph"
	"github.com/krazybeastx1/omenhound/internal/ingest"
	"github.com/krazybeastx1/omenhound/internal/version"
	"github.com/krazybeastx1/omenhound/pkg/model"
)

func main() { os.Exit(run(os.Args[1:])) }

func usage() {
	fmt.Fprint(os.Stderr, `omenhound — BloodHound-style AD attack-path tool (Go)

Usage:
  omenhound collect [flags]     collect a graph and write Graph JSON
  omenhound serve   [flags]     run the ingestion API + web UI
  omenhound export  [flags]     convert a Graph JSON file (json|csv)
  omenhound version             print version

Run "omenhound <command> -h" for command flags.
Only use against systems you are authorized to test.
`)
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "collect":
		return cmdCollect(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "export":
		return cmdExport(args[1:])
	case "version", "-v", "--version":
		fmt.Println("omenhound", version.Version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

// ---- collect ----

func cmdCollect(args []string) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	var (
		collectorName = fs.String("collector", "sample", "collector to use: sample|ldap")
		domain        = fs.String("domain", "", "AD domain (e.g. corp.local)")
		server        = fs.String("server", "", "DC host (host or host:port)")
		baseDN        = fs.String("base-dn", "", "LDAP search base (default derived from --domain)")
		ldaps         = fs.Bool("ldaps", false, "use LDAPS (636)")
		insecure      = fs.Bool("insecure", false, "skip TLS verification (lab only)")
		username      = fs.String("username", "", "bind username")
		password      = fs.String("password", "", "bind password (prefer --password-stdin or $OMENHOUND_PASSWORD)")
		passwordStdin = fs.Bool("password-stdin", false, "read bind password from stdin")
		timeout       = fs.Duration("timeout", 60*time.Second, "collection timeout")
		out           = fs.String("out", "-", "output file, or - for stdout")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	pw, err := readPassword(*password, *passwordStdin)
	if err != nil {
		log.Printf("collect: %v", err)
		return 1
	}
	defer zero(pw)
	if *password != "" {
		log.Printf("WARNING: --password is visible in process listings; prefer --password-stdin or $OMENHOUND_PASSWORD")
	}

	c, err := collector.New(*collectorName)
	if err != nil {
		log.Printf("collect: %v", err)
		return 1
	}
	opts := collector.Options{
		Domain: *domain, Server: *server, BaseDN: *baseDN, UseLDAPS: *ldaps,
		InsecureSkipVerify: *insecure, Username: *username, Password: pw, Timeout: *timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.EffectiveTimeout())
	defer cancel()

	log.Printf("collect: using %q collector (timeout %s)", c.Name(), opts.EffectiveTimeout())
	g, err := c.Collect(ctx, opts)
	if err != nil {
		log.Printf("collect: %v", err)
		return 1
	}
	g.Meta.Version = version.Version
	if err := writeGraphFile(*out, g); err != nil {
		log.Printf("collect: %v", err)
		return 1
	}
	log.Printf("collect: wrote %d nodes, %d edges to %s", len(g.Nodes), len(g.Edges), *out)
	return 0
}

// ---- serve ----

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var (
		addr          = fs.String("addr", "127.0.0.1:8080", "listen address")
		collectorName = fs.String("collector", "sample", "collector to seed the graph with: sample|ldap|none")
		domain        = fs.String("domain", "", "AD domain (ldap collector)")
		server        = fs.String("server", "", "DC host (ldap collector)")
		baseDN        = fs.String("base-dn", "", "LDAP search base")
		ldaps         = fs.Bool("ldaps", false, "use LDAPS")
		insecure      = fs.Bool("insecure", false, "skip TLS verification (lab only)")
		username      = fs.String("username", "", "bind username")
		password      = fs.String("password", "", "bind password (prefer $OMENHOUND_PASSWORD)")
		timeout       = fs.Duration("timeout", 60*time.Second, "collection timeout")
		neo4jURI      = fs.String("neo4j-uri", "", "Neo4j URI (bolt://host:7687); empty = in-memory")
		neo4jUser     = fs.String("neo4j-user", "neo4j", "Neo4j user")
		neo4jDB       = fs.String("neo4j-database", "neo4j", "Neo4j database")
		apiToken      = fs.String("api-token", os.Getenv("OMENHOUND_API_TOKEN"), "bearer token enabling write endpoints (env OMENHOUND_API_TOKEN)")
		enableOps     = fs.Bool("enable-credential-ops", false, "enable the gated AD password-change endpoint (authorized lab only)")
		auditLog      = fs.String("audit-log", "", "audit log file (default stderr)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// audit sink
	var auditW io.Writer = os.Stderr
	if *auditLog != "" {
		f, err := os.OpenFile(*auditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Printf("serve: open audit log: %v", err)
			return 1
		}
		defer f.Close()
		auditW = f
	}
	auditLogger := audit.New(auditW)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// store
	var store graph.Store
	if *neo4jURI != "" {
		pass := os.Getenv("OMENHOUND_NEO4J_PASSWORD")
		s, err := graph.NewNeo4j(ctx, *neo4jURI, *neo4jUser, pass, *neo4jDB)
		if err != nil {
			log.Printf("serve: neo4j: %v", err)
			return 1
		}
		store = s
		log.Printf("serve: using Neo4j at %s (db %s)", *neo4jURI, *neo4jDB)
	} else {
		store = graph.NewMemory()
		log.Printf("serve: using in-memory graph store (no --neo4j-uri)")
	}
	defer store.Close(context.Background())

	// optional seed collection
	if *collectorName != "none" {
		c, err := collector.New(*collectorName)
		if err != nil {
			log.Printf("serve: %v", err)
			return 1
		}
		pw, _ := readPassword(*password, false)
		opts := collector.Options{Domain: *domain, Server: *server, BaseDN: *baseDN, UseLDAPS: *ldaps,
			InsecureSkipVerify: *insecure, Username: *username, Password: pw, Timeout: *timeout}
		cctx, ccancel := context.WithTimeout(ctx, opts.EffectiveTimeout())
		g, err := c.Collect(cctx, opts)
		ccancel()
		zero(pw)
		if err != nil {
			log.Printf("serve: seed collection with %q failed: %v", c.Name(), err)
		} else {
			res, err := ingest.Write(ctx, store, g)
			if err != nil {
				log.Printf("serve: ingest seed graph: %v", err)
			} else {
				log.Printf("serve: seeded %d nodes, %d edges (store now %d/%d)", res.Nodes, res.Edges, res.Stats.Nodes, res.Stats.Edges)
			}
		}
	}

	srvCfg := api.Config{
		StoreIface:            store,
		Audit:                 auditLogger,
		Version:               version.Version,
		APIToken:              *apiToken,
		EnableCredentialOps:   *enableOps,
		ActServer:             *server,
		ActInsecureSkipVerify: *insecure,
		ChangePassword: func(ctx context.Context, o act.Options, targetDN string, newPassword []byte) error {
			return act.ChangePassword(ctx, o, targetDN, newPassword)
		},
		Logger: log.New(os.Stderr, "http ", log.LstdFlags),
	}
	if !*enableOps {
		srvCfg.ChangePassword = nil
	}
	if *apiToken == "" {
		log.Printf("serve: write API DISABLED (set --api-token or $OMENHOUND_API_TOKEN to enable ingest/credential endpoints)")
	}
	if *enableOps {
		log.Printf("serve: WARNING credential-ops ENABLED — OmenHound can now change AD passwords; authorized use only")
	}

	hs := &http.Server{
		Addr:              *addr,
		Handler:           api.New(srvCfg).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("serve: listening on http://%s", *addr)
		errCh <- hs.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Printf("serve: shutting down")
		shutdownCtx, sc := context.WithTimeout(context.Background(), 10*time.Second)
		defer sc()
		_ = hs.Shutdown(shutdownCtx)
		return 0
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("serve: %v", err)
			return 1
		}
		return 0
	}
}

// ---- export ----

func cmdExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	var (
		in     = fs.String("in", "-", "input Graph JSON file, or - for stdin")
		out    = fs.String("out", "-", "output file, or - for stdout")
		format = fs.String("format", "json", "output format: json|csv")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	g, err := readGraphFile(*in)
	if err != nil {
		log.Printf("export: %v", err)
		return 1
	}
	switch strings.ToLower(*format) {
	case "json":
		if err := writeGraphFile(*out, g); err != nil {
			log.Printf("export: %v", err)
			return 1
		}
	case "csv":
		if err := writeCSV(*out, g); err != nil {
			log.Printf("export: %v", err)
			return 1
		}
	default:
		log.Printf("export: unknown format %q (want json|csv)", *format)
		return 2
	}
	log.Printf("export: %d nodes, %d edges -> %s (%s)", len(g.Nodes), len(g.Edges), *out, *format)
	return 0
}

// ---- io helpers ----

func readGraphFile(path string) (*model.Graph, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return ingest.Decode(r)
}

func writeGraphFile(path string, g *model.Graph) error {
	var w io.Writer
	if path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

func writeCSV(path string, g *model.Graph) error {
	var w io.Writer
	if path == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"record", "source", "target", "kind", "name", "sam", "dn"}); err != nil {
		return err
	}
	for _, n := range g.Nodes {
		if err := cw.Write([]string{"node", n.ID, "", string(n.Kind), n.Name, n.SAMAccountName, n.DN}); err != nil {
			return err
		}
	}
	for _, e := range g.Edges {
		if err := cw.Write([]string{"edge", e.Source, e.Target, string(e.Kind), "", "", ""}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func readPassword(pw string, fromStdin bool) ([]byte, error) {
	if fromStdin {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return nil, err
		}
		return bytes.TrimRight(b, "\r\n"), nil
	}
	if pw != "" {
		return []byte(pw), nil
	}
	if v := os.Getenv("OMENHOUND_PASSWORD"); v != "" {
		return []byte(v), nil
	}
	return nil, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
