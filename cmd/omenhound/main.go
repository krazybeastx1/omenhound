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
	"github.com/krazybeastx1/omenhound/internal/bloodhound"
	"github.com/krazybeastx1/omenhound/internal/collector"
	"github.com/krazybeastx1/omenhound/internal/creds"
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
  omenhound import  [flags]     import BloodHound CE JSON/zip into Graph JSON
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
	case "import":
		return cmdImport(args[1:])
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
		collectorName    = fs.String("collector", "sample", "collector to use: sample|ldap")
		domain           = fs.String("domain", "", "AD domain (e.g. corp.local)")
		domainShort      = fs.String("d", "", "alias of --domain")
		server           = fs.String("server", "", "DC host (host or host:port); overrides --dc/--ns")
		dcFlag           = fs.String("dc", "", "domain controller host")
		dcLong           = fs.String("domain-controller", "", "alias of --dc")
		nsFlag           = fs.String("ns", "", "DNS server used for DC SRV discovery")
		nsLong           = fs.String("nameserver", "", "alias of --ns")
		baseDN           = fs.String("base-dn", "", "LDAP search base (default derived from --domain)")
		ldaps            = fs.Bool("ldaps", false, "use LDAPS (636)")
		useLDAPS         = fs.Bool("use-ldaps", false, "alias of --ldaps")
		channelBinding   = fs.Bool("ldap-channel-binding", false, "LDAP channel binding (no-op for simple bind over LDAPS)")
		insecure         = fs.Bool("insecure", false, "skip TLS verification (lab only)")
		username         = fs.String("username", "", "bind username")
		usernameShort    = fs.String("u", "", "alias of --username")
		password         = fs.String("password", "", "bind password (prefer --password-stdin or $OMENHOUND_PASSWORD)")
		passwordShort    = fs.String("p", "", "alias of --password")
		passwordStdin    = fs.Bool("password-stdin", false, "read bind password from stdin")
		plaintext        = fs.Bool("allow-plaintext-ldap", false, "allow binding over unencrypted LDAP (lab only; refused by default)")
		timeout          = fs.Duration("timeout", 60*time.Second, "collection timeout")
		collection       = fs.String("c", "", "collection methods, comma-separated (group,objectprops,... | all | default | dc)")
		collectionLong   = fs.String("collectionmethod", "", "alias of --c")
		zipOut           = fs.Bool("zip", false, "write a BloodHound CE v5 zip archive instead of Graph JSON")
		outputPrefix     = fs.String("op", "", "output filename prefix for --zip")
		outputPrefixLong = fs.String("outputprefix", "", "alias of --op")
		out              = fs.String("out", "-", "output file, or - for stdout")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	domainVal := pick(*domain, *domainShort)
	userVal := pick(*username, *usernameShort)
	passVal := pick(*password, *passwordShort)
	nsVal := pick(*nsFlag, *nsLong)
	dcVal := pick(*dcFlag, *dcLong)
	collVal := pick(*collection, *collectionLong)
	prefixVal := pick(*outputPrefix, *outputPrefixLong)
	useTLSDial := *ldaps || *useLDAPS

	if *channelBinding && !useTLSDial {
		log.Printf("collect: --ldap-channel-binding has no effect with LDAP simple bind (channel binding applies to NTLM/Kerberos); use --ldaps")
	}

	serverVal := *server
	if serverVal == "" {
		serverVal = dcVal
	}
	if serverVal == "" && nsVal != "" {
		if domainVal == "" {
			log.Printf("collect: --ns requires --domain")
			return 2
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
		discovered, err := collector.ResolveDC(rctx, nsVal, domainVal)
		rcancel()
		if err != nil {
			log.Printf("collect: %v", err)
			return 1
		}
		log.Printf("collect: discovered DC %s for %s via %s", discovered, domainVal, nsVal)
		serverVal = discovered
	}

	plan, err := collector.PlanMethods(collVal)
	if err != nil {
		log.Printf("collect: %v", err)
		return 2
	}
	for _, m := range plan.Skipped {
		log.Printf("collect: WARNING: collection method %q is not implemented — skipped", m)
	}

	pw, err := readPassword(passVal, *passwordStdin)
	if err != nil {
		log.Printf("collect: %v", err)
		return 1
	}
	defer zero(pw)
	if passVal != "" {
		log.Printf("WARNING: --password is visible in process listings; prefer --password-stdin or $OMENHOUND_PASSWORD")
	}

	c, err := collector.New(*collectorName)
	if err != nil {
		log.Printf("collect: %v", err)
		return 1
	}
	opts := collector.Options{
		Domain: domainVal, Server: serverVal, BaseDN: *baseDN, UseLDAPS: useTLSDial,
		InsecureSkipVerify: *insecure, Username: userVal, Password: pw, Timeout: *timeout,
		AllowPlaintextLDAP: *plaintext, Methods: &plan,
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.EffectiveTimeout())
	defer cancel()

	log.Printf("collect: using %q collector (timeout %s, methods %v)", c.Name(), opts.EffectiveTimeout(), plan.Implemented)
	g, err := c.Collect(ctx, opts)
	if err != nil {
		log.Printf("collect: %v", err)
		return 1
	}
	g.Meta.Version = version.Version
	for _, w := range g.Meta.Warnings {
		log.Printf("collect: WARNING: %s", w)
	}

	if *zipOut {
		path := *out
		if path == "" || path == "-" || !flagSet(fs, "out") {
			path = prefixVal + time.Now().UTC().Format("20060102150405") + ".zip"
		}
		members, err := bloodhound.WriteCEZip(path, g, prefixVal)
		if err != nil {
			log.Printf("collect: %v", err)
			return 1
		}
		log.Printf("collect: wrote BloodHound CE archive %s (%d nodes, %d edges, members %v)",
			path, len(g.Nodes), len(g.Edges), members)
		return 0
	}

	if err := writeGraphFile(*out, g); err != nil {
		log.Printf("collect: %v", err)
		return 1
	}
	log.Printf("collect: wrote %d nodes, %d edges to %s", len(g.Nodes), len(g.Edges), *out)
	return 0
}

func pick(primary, alias string) string {
	if primary != "" {
		return primary
	}
	return alias
}

func flagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// ---- serve ----

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var (
		addr           = fs.String("addr", "127.0.0.1:8080", "listen address")
		collectorName  = fs.String("collector", "sample", "collector to seed the graph with: sample|ldap|none")
		domain         = fs.String("domain", "", "AD domain (ldap collector)")
		domainShort    = fs.String("d", "", "alias of --domain")
		server         = fs.String("server", "", "DC host (ldap collector); overrides --dc/--ns")
		dcFlag         = fs.String("dc", "", "domain controller host")
		dcLong         = fs.String("domain-controller", "", "alias of --dc")
		nsFlag         = fs.String("ns", "", "DNS server for DC SRV discovery")
		nsLong         = fs.String("nameserver", "", "alias of --ns")
		baseDN         = fs.String("base-dn", "", "LDAP search base")
		ldaps          = fs.Bool("ldaps", false, "use LDAPS")
		useLDAPS       = fs.Bool("use-ldaps", false, "alias of --ldaps")
		insecure       = fs.Bool("insecure", false, "skip TLS verification (lab only)")
		username       = fs.String("username", "", "bind username")
		usernameShort  = fs.String("u", "", "alias of --username")
		password       = fs.String("password", "", "bind password (prefer $OMENHOUND_PASSWORD)")
		passwordShort  = fs.String("p", "", "alias of --password")
		plaintext      = fs.Bool("allow-plaintext-ldap", false, "allow binding over unencrypted LDAP (lab only)")
		timeout        = fs.Duration("timeout", 60*time.Second, "collection timeout")
		collection     = fs.String("c", "", "collection methods (comma-separated | all | default | dc)")
		collectionLong = fs.String("collectionmethod", "", "alias of --c")
		neo4jURI       = fs.String("neo4j-uri", "", "Neo4j URI (bolt://host:7687); empty = in-memory")
		neo4jUser      = fs.String("neo4j-user", "neo4j", "Neo4j user")
		neo4jDB        = fs.String("neo4j-database", "neo4j", "Neo4j database")
		apiToken       = fs.String("api-token", os.Getenv("OMENHOUND_API_TOKEN"), "bearer token enabling write endpoints (env OMENHOUND_API_TOKEN)")
		enableOps      = fs.Bool("enable-credential-ops", false, "enable the gated AD password-change endpoint (authorized lab only)")
		auditLog       = fs.String("audit-log", "", "audit log file (default stderr)")
		writeRate      = fs.Int("write-rate-limit", 120, "max write requests per minute per client IP")
		writeBurst     = fs.Int("write-burst", 30, "write request burst per client IP")
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

	// Memory-only credential vault; a janitor zeroes secrets as soon as they expire.
	credStore := creds.NewStore(15*time.Minute, 64)
	defer credStore.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go credStore.Janitor(ctx, time.Minute)

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
		domainVal := pick(*domain, *domainShort)
		userVal := pick(*username, *usernameShort)
		passVal := pick(*password, *passwordShort)
		serverVal := *server
		if serverVal == "" {
			serverVal = pick(*dcFlag, *dcLong)
		}
		if serverVal == "" {
			if nsVal := pick(*nsFlag, *nsLong); nsVal != "" {
				rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
				discovered, derr := collector.ResolveDC(rctx, nsVal, domainVal)
				rcancel()
				if derr != nil {
					log.Printf("serve: %v", derr)
					return 1
				}
				log.Printf("serve: discovered DC %s for %s via %s", discovered, domainVal, nsVal)
				serverVal = discovered
			}
		}
		plan, perr := collector.PlanMethods(pick(*collection, *collectionLong))
		if perr != nil {
			log.Printf("serve: %v", perr)
			return 2
		}
		for _, m := range plan.Skipped {
			log.Printf("serve: WARNING: collection method %q is not implemented — skipped", m)
		}
		pw, _ := readPassword(passVal, false)
		opts := collector.Options{Domain: domainVal, Server: serverVal, BaseDN: *baseDN, UseLDAPS: *ldaps || *useLDAPS,
			InsecureSkipVerify: *insecure, Username: userVal, Password: pw, Timeout: *timeout,
			AllowPlaintextLDAP: *plaintext, Methods: &plan}
		cctx, ccancel := context.WithTimeout(ctx, opts.EffectiveTimeout())
		g, err := c.Collect(cctx, opts)
		ccancel()
		zero(pw)
		if err != nil {
			log.Printf("serve: seed collection with %q failed: %v", c.Name(), err)
		} else {
			for _, w := range g.Meta.Warnings {
				log.Printf("serve: WARNING: %s", w)
			}
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
		Creds:                 credStore,
		Audit:                 auditLogger,
		Version:               version.Version,
		APIToken:              *apiToken,
		EnableCredentialOps:   *enableOps,
		ActServer:             *server,
		ActInsecureSkipVerify: *insecure,
		WriteRatePerMinute:    *writeRate,
		WriteBurst:            *writeBurst,
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

// ---- import ----

func cmdImport(args []string) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	var (
		in       = fs.String("in", "", "BloodHound CE .zip, a directory of JSON files, or a single JSON file")
		out      = fs.String("out", "-", "output Graph JSON file, or - for stdout (ignored with --api)")
		apiURL   = fs.String("api", "", "base URL of a running omenhound server to push the graph into, e.g. http://127.0.0.1:8080")
		token    = fs.String("token", os.Getenv("OMENHOUND_API_TOKEN"), "bearer token for --api (env OMENHOUND_API_TOKEN)")
		validate = fs.Bool("validate", true, "run ingest validation before writing or pushing")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" {
		log.Print("import: --in is required (BloodHound CE .zip, a directory, or a JSON file)")
		return 2
	}
	g, rpt, err := bloodhound.Load(*in)
	if err != nil {
		log.Printf("import: %v", err)
		return 1
	}
	log.Printf("import: %d nodes, %d edges, %d placeholders from %d file(s) (domain %q)",
		rpt.Nodes, rpt.Edges, rpt.Placeholders, len(rpt.Files), rpt.Domain)
	if len(rpt.UnknownRights) > 0 {
		log.Printf("import: ACE right names with no OmenHound edge (skipped): %v", rpt.UnknownRights)
	}
	if len(rpt.Skipped) > 0 {
		log.Printf("import: skipped: %v", rpt.Skipped)
	}
	if *validate {
		if err := ingest.Validate(g); err != nil {
			log.Printf("import: validation failed: %v", err)
			return 1
		}
	}
	if *apiURL != "" {
		if *token == "" {
			log.Print("import: --api requires --token (or OMENHOUND_API_TOKEN)")
			return 2
		}
		if err := pushGraph(*apiURL, *token, g); err != nil {
			log.Printf("import: %v", err)
			return 1
		}
		log.Printf("import: pushed %d nodes / %d edges to %s", len(g.Nodes), len(g.Edges), *apiURL)
		return 0
	}
	if err := writeGraphFile(*out, g); err != nil {
		log.Printf("import: %v", err)
		return 1
	}
	return 0
}

func pushGraph(apiURL, token string, g *model.Graph) error {
	body, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("push: marshal: %w", err)
	}
	url := strings.TrimRight(apiURL, "/") + "/api/v1/ingest"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("push: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push: %s: %s", resp.Status, strings.TrimSpace(string(rb)))
	}
	log.Printf("import: server response: %s", strings.TrimSpace(string(rb)))
	return nil
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
