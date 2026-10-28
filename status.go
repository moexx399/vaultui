package main

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Thresholds from the original vault-replication-status script.
const (
	walLagWarn       = 100  // WAL entries behind the primary
	walLagCrit       = 1000 //
	heartbeatWarn    = 30 * time.Second
	heartbeatCrit    = 120 * time.Second
	tlsExpiryWarnDay = 30
	tlsExpiryCritDay = 7
)

// level is a health verdict; higher is worse.
type level int

const (
	levelOK level = iota
	levelUnknown
	levelWarn
	levelCrit
)

// verdict is a level and why.
type verdict struct {
	Level   level
	Reasons []string
}

func (v *verdict) add(l level, reason string) {
	v.Level = max(v.Level, l)
	v.Reasons = append(v.Reasons, reason)
}

// cluster is everything learnt from one Vault address that one or more
// vaultctx contexts point at. Contexts reaching the same cluster (by its
// sys/health cluster_id) are merged.
type cluster struct {
	Contexts []string
	Address  string
	Err      string // sys/replication/status failed; nothing else is known

	HealthCode  int // sys/health encodes the node state in its status code
	HealthErr   string
	Version     string
	ClusterName string
	ClusterID   string

	Modes map[string]*replication // "dr" and "performance", when enabled
	TLS   *certInfo
}

func (c *cluster) Name() string { return strings.Join(c.Contexts, ", ") }

// replication is one cluster's view of one replication mode.
type replication struct {
	Mode, Role, State, ClusterID, MerkleRoot string
	Corrupted                                bool
	Peers                                    []peer

	// Primaries.
	LastWAL          *int64
	KnownSecondaries []string

	// Secondaries.
	LastRemoteWAL      *int64
	SecondaryID        string
	ConnectionState    string
	PrimaryClusterAddr string

	// Secondaries, resolved across clusters by link.
	Primary       *cluster
	PrimaryName   string
	PrimaryWAL    *int64
	WALLag        *int64
	NeverStreamed bool
}

type peer struct {
	Name, NodeID, APIAddress, ConnectionStatus string
	HeartbeatAge                               *time.Duration
	ClockSkew, CanaryAge                       string // milliseconds, as reported
}

type certInfo struct {
	Host, Err           string
	Subject, Issuer     string
	NotAfter            time.Time
	Serial, Fingerprint string
	SANs                []string
	DaysRemaining       int
}

// topology is a set of clusters connected by replication, shown as one page.
type topology struct {
	Name     string
	Clusters []*cluster
}

// statusOptions control collection.
type statusOptions struct {
	Timeout time.Duration
	NoTLS   bool
}

// collectStatus queries every vaultctx context's address (unauthenticated)
// and groups the clusters into replication topologies.
func collectStatus(ctx context.Context, opts statusOptions) ([]topology, error) {
	names, _, err := listContexts(ctx)
	if err != nil {
		return nil, err
	}
	envs := make([]map[string]string, len(names))
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() { envs[i], errs[i] = contextEnv(ctx, name) })
	}
	wg.Wait()

	// One target per distinct address.
	type target struct {
		contexts []string
		env      map[string]string
	}
	var targets []*target
	byAddr := map[string]*target{}
	var clusters []*cluster
	for i, name := range names {
		if errs[i] != nil {
			clusters = append(clusters, &cluster{Contexts: []string{name}, Err: errs[i].Error()})
			continue
		}
		addr := strings.TrimRight(strings.ToLower(envs[i]["VAULT_ADDR"]), "/")
		if t, ok := byAddr[addr]; ok {
			t.contexts = append(t.contexts, name)
			continue
		}
		t := &target{contexts: []string{name}, env: envs[i]}
		byAddr[addr] = t
		targets = append(targets, t)
	}

	fetched := make([]*cluster, len(targets))
	for i, t := range targets {
		wg.Go(func() { fetched[i] = fetchCluster(ctx, t.contexts, t.env, opts) })
	}
	wg.Wait()
	return buildTopologies(append(clusters, fetched...)), nil
}

func fetchCluster(ctx context.Context, contexts []string, env map[string]string, opts statusOptions) *cluster {
	c := &cluster{Contexts: contexts, Address: env["VAULT_ADDR"]}
	cfg, err := vaultConfig(env)
	if err != nil {
		c.Err = err.Error()
		return c
	}
	httpc := *cfg.HttpClient
	httpc.Timeout = opts.Timeout

	var wg sync.WaitGroup
	if !opts.NoTLS && strings.HasPrefix(strings.ToLower(c.Address), "https://") {
		wg.Go(func() { c.TLS = fetchCert(ctx, c.Address, opts.Timeout) })
	}
	wg.Go(func() {
		code, body, err := getJSON(ctx, &httpc, c.Address+"/v1/sys/health")
		if err != nil && code == 0 {
			c.HealthErr = err.Error()
			return
		}
		c.HealthCode = code
		c.Version, c.ClusterName, c.ClusterID = str(body["version"]), str(body["cluster_name"]), str(body["cluster_id"])
	})
	code, body, err := getJSON(ctx, &httpc, c.Address+"/v1/sys/replication/status")
	wg.Wait()
	if err == nil && code != http.StatusOK {
		err = fmt.Errorf("HTTP %d", code)
	}
	if err != nil {
		c.Err = err.Error()
		return c
	}
	data, _ := body["data"].(map[string]any)
	c.Modes = map[string]*replication{}
	for _, mode := range []string{"dr", "performance"} {
		block, _ := data[mode].(map[string]any)
		if m := str(block["mode"]); m != "" && m != "disabled" {
			c.Modes[mode] = parseReplication(mode, block, time.Now())
		}
	}
	return c
}

// getJSON GETs url and decodes its JSON body, whatever the status code.
func getJSON(ctx context.Context, c *http.Client, url string) (int, map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("HTTP %d: %w", resp.StatusCode, err)
	}
	return resp.StatusCode, body, nil
}

func parseReplication(mode string, b map[string]any, now time.Time) *replication {
	r := &replication{
		Mode: mode, Role: str(b["mode"]), State: str(b["state"]),
		ClusterID: str(b["cluster_id"]), MerkleRoot: str(b["merkle_root"]),
	}
	r.Corrupted, _ = b["corrupted_merkle_tree"].(bool)
	peerFrom := func(p map[string]any, name string) peer {
		return peer{
			Name: name, NodeID: str(p["node_id"]), APIAddress: str(p["api_address"]),
			ConnectionStatus: str(p["connection_status"]),
			HeartbeatAge:     age(str(p["last_heartbeat"]), now),
			ClockSkew:        anyStr(p["clock_skew_ms"]),
			CanaryAge:        anyStr(p["replication_primary_canary_age_ms"]),
		}
	}
	if r.Role == "primary" {
		r.LastWAL = num(b["last_"+mode+"_wal"])
		if r.LastWAL == nil {
			r.LastWAL = num(b["last_wal"])
		}
		r.KnownSecondaries = strs(b["known_secondaries"])
		for _, s := range objects(b["secondaries"]) {
			name := shortName(str(s["api_address"]))
			if str(s["api_address"]) == "" {
				name = shortName(str(s["node_id"]))
			}
			r.Peers = append(r.Peers, peerFrom(s, name))
		}
		return r
	}
	r.LastRemoteWAL = num(b["last_remote_wal"])
	r.SecondaryID = str(b["secondary_id"])
	r.ConnectionState = str(b["connection_state"])
	r.PrimaryClusterAddr = str(b["primary_cluster_addr"])
	for _, p := range objects(b["primaries"]) {
		r.Peers = append(r.Peers, peerFrom(p, shortName(str(p["api_address"]))))
	}
	if len(r.Peers) == 0 {
		r.Peers = append(r.Peers, peer{Name: shortName(r.PrimaryClusterAddr), APIAddress: r.PrimaryClusterAddr, ConnectionStatus: r.ConnectionState})
	}
	return r
}

// buildTopologies merges clusters reached through several addresses, links
// each secondary to its primary, and groups linked clusters into topologies.
func buildTopologies(all []*cluster) []topology {
	var clusters []*cluster
	byID := map[string]*cluster{}
	for _, c := range all {
		if c.ClusterID != "" {
			if seen, ok := byID[c.ClusterID]; ok {
				seen.Contexts = append(seen.Contexts, c.Contexts...)
				continue
			}
			byID[c.ClusterID] = c
		}
		clusters = append(clusters, c)
	}

	parent := map[*cluster]*cluster{}
	var find func(*cluster) *cluster
	find = func(c *cluster) *cluster {
		if p, ok := parent[c]; ok && p != c {
			parent[c] = find(p)
			return parent[c]
		}
		return c
	}
	for _, s := range clusters {
		for _, r := range s.Modes {
			if r.Role != "secondary" {
				continue
			}
			p := findPrimary(clusters, s, r)
			r.Primary, r.PrimaryName = p, upstreamName(r)
			if p == nil {
				continue
			}
			r.PrimaryName = p.Name()
			parent[find(s)] = find(p)
			pr := p.Modes[r.Mode]
			if pr.LastWAL != nil && r.LastRemoteWAL != nil {
				r.PrimaryWAL = pr.LastWAL
				if *r.LastRemoteWAL == 0 {
					r.NeverStreamed = true // a connection problem, not a lag number
				} else {
					lag := *pr.LastWAL - *r.LastRemoteWAL
					r.WALLag = &lag
				}
			}
		}
	}

	groups := map[*cluster][]*cluster{}
	for _, c := range clusters {
		groups[find(c)] = append(groups[find(c)], c)
	}
	var tops []topology
	for _, members := range groups {
		slices.SortFunc(members, func(a, b *cluster) int { return strings.Compare(a.Name(), b.Name()) })
		name := members[0].Name()
		for _, c := range members { // name it after a root primary when there is one
			if isRoot(c) {
				name = c.Name()
				break
			}
		}
		tops = append(tops, topology{Name: name, Clusters: members})
	}
	slices.SortFunc(tops, func(a, b topology) int { return strings.Compare(a.Name, b.Name) })
	return tops
}

func isRoot(c *cluster) bool {
	primary := false
	for _, r := range c.Modes {
		if r.Role == "secondary" {
			return false
		}
		primary = true
	}
	return primary
}

// findPrimary finds the queried primary of secondary s in r's mode: the one
// sharing its replication cluster ID, else the one listing it as a peer, else
// the one its upstream address names.
func findPrimary(clusters []*cluster, s *cluster, r *replication) *cluster {
	var byPeer, byName *cluster
	upstream := upstreamName(r)
	for _, p := range clusters {
		pr := p.Modes[r.Mode]
		if p == s || pr == nil || pr.Role != "primary" {
			continue
		}
		if r.ClusterID != "" && pr.ClusterID == r.ClusterID {
			return p
		}
		if r.SecondaryID != "" && slices.ContainsFunc(pr.Peers, func(x peer) bool { return x.NodeID == r.SecondaryID }) {
			byPeer = p
		}
		if upstream != "?" && slices.Contains(identifiers(p), upstream) {
			byName = p
		}
	}
	return cmp.Or(byPeer, byName)
}

// upstreamName is the short name of the primary a secondary reports.
func upstreamName(r *replication) string {
	for _, p := range r.Peers {
		if p.Name != "" && p.Name != "?" {
			return p.Name
		}
	}
	return shortName(r.PrimaryClusterAddr)
}

// identifiers are the names a cluster may be referred to by in peers' reports.
func identifiers(c *cluster) []string {
	ids := append([]string{shortName(c.Address), c.ClusterName}, c.Contexts...)
	for _, r := range c.Modes {
		ids = append(ids, r.SecondaryID)
	}
	return ids
}

// children pairs a primary's reported secondaries with the queried ones:
// queried secondaries linked to it (with the primary's link record if it
// has one), then links to secondaries that were not queried, then known
// secondaries with no link at all.
type child struct {
	Name    string
	Cluster *cluster     // nil when not queried
	Repl    *replication // nil when not queried
	Link    *peer        // nil when the primary reports no link
}

func children(p *cluster, mode string, clusters []*cluster) []child {
	pr := p.Modes[mode]
	unclaimed := slices.Clone(pr.Peers)
	var out []child
	for _, s := range clusters {
		sr := s.Modes[mode]
		if sr == nil || sr.Role != "secondary" || sr.Primary != p {
			continue
		}
		ch := child{Name: s.Name(), Cluster: s, Repl: sr}
		ids := identifiers(s)
		for i, x := range unclaimed {
			if (x.NodeID != "" && x.NodeID == sr.SecondaryID) || slices.Contains(ids, x.Name) {
				ch.Link = &x
				unclaimed = slices.Delete(unclaimed, i, i+1)
				break
			}
		}
		out = append(out, ch)
	}
	for _, x := range unclaimed {
		out = append(out, child{Name: cmp.Or(x.Name, "?"), Link: &x})
	}
	for _, known := range pr.KnownSecondaries {
		if !slices.ContainsFunc(out, func(c child) bool {
			return c.Name == known || c.Link != nil && c.Link.NodeID == known || c.Repl != nil && c.Repl.SecondaryID == known
		}) {
			out = append(out, child{Name: known})
		}
	}
	return out
}

func syncHealth(r *replication) verdict {
	var v verdict
	if r.Role == "primary" {
		if r.State != "running" {
			v.add(levelWarn, "state="+r.State)
		}
	} else {
		if r.State != "stream-wals" {
			v.add(levelCrit, "state="+r.State)
		}
		if r.ConnectionState != "" && r.ConnectionState != "ready" {
			v.add(levelCrit, "connection="+r.ConnectionState)
		}
	}
	if r.Corrupted {
		v.add(levelCrit, "merkle tree corrupted")
	}
	switch lag := r.WALLag; {
	case r.NeverStreamed:
		v.add(levelCrit, "never streamed (remote_wal=0)")
	case lag != nil && abs(*lag) >= walLagCrit:
		v.add(levelCrit, fmt.Sprintf("WAL lag %d", *lag))
	case lag != nil && abs(*lag) >= walLagWarn:
		v.add(levelWarn, fmt.Sprintf("WAL lag %d", *lag))
	}
	for _, p := range r.Peers {
		if s := p.ConnectionStatus; s != "" && s != "connected" && s != "ready" {
			v.add(levelCrit, p.Name+" "+s)
		}
		if a := p.HeartbeatAge; a != nil && *a >= heartbeatWarn {
			l := levelWarn
			if *a >= heartbeatCrit {
				l = levelCrit
			}
			v.add(l, fmt.Sprintf("%s heartbeat %.0fs ago", p.Name, a.Seconds()))
		}
	}
	return v
}

var healthStates = map[int]string{
	200: "active", 429: "standby", 472: "dr-secondary",
	473: "performance-standby", 501: "not-initialized", 503: "sealed",
}

func healthState(code int) string {
	if s, ok := healthStates[code]; ok {
		return s
	}
	return fmt.Sprintf("unknown (%d)", code)
}

// nodeHealth judges the node a context's address reaches: anything but the
// active node means a failover or misrouted load balancer.
func nodeHealth(c *cluster) verdict {
	var v verdict
	switch {
	case c.HealthErr != "":
		v.add(levelCrit, c.HealthErr)
	case c.HealthCode == 200:
	case c.HealthCode == 429 || c.HealthCode == 472 || c.HealthCode == 473:
		v.add(levelWarn, "routed to "+healthState(c.HealthCode)+" node")
	default:
		v.add(levelCrit, "state="+healthState(c.HealthCode))
	}
	return v
}

func tlsHealth(t *certInfo) verdict {
	var v verdict
	switch d := t.DaysRemaining; {
	case t.Err != "":
		v.add(levelCrit, t.Err)
	case d < 0:
		v.add(levelCrit, fmt.Sprintf("expired %dd ago", -d))
	case d <= tlsExpiryCritDay:
		v.add(levelCrit, fmt.Sprintf("expires in %dd", d))
	case d <= tlsExpiryWarnDay:
		v.add(levelWarn, fmt.Sprintf("expires in %dd", d))
	}
	return v
}

// certConsistency flags clusters in a topology whose certificate differs
// from the majority's, usually a stale or wrongly installed certificate.
func certConsistency(clusters []*cluster) verdict {
	groups := map[string][]string{}
	for _, c := range clusters {
		if c.TLS != nil && c.TLS.Err == "" {
			groups[c.TLS.Fingerprint] = append(groups[c.TLS.Fingerprint], c.Name())
		}
	}
	var v verdict
	if len(groups) < 2 {
		return v
	}
	var sets [][]string
	for _, names := range groups {
		slices.Sort(names)
		sets = append(sets, names)
	}
	slices.SortFunc(sets, func(a, b []string) int {
		return cmp.Or(len(b)-len(a), strings.Compare(a[0], b[0]))
	})
	for _, names := range sets[1:] {
		v.add(levelCrit, fmt.Sprintf("%s cert differs from %s", strings.Join(names, ", "), strings.Join(sets[0], ", ")))
	}
	return v
}

// overall is the worst verdict on the page, ignoring unknowns.
func (t topology) overall() (level, bool) {
	worst, any := levelOK, false
	note := func(v verdict) {
		any = true
		if v.Level != levelUnknown {
			worst = max(worst, v.Level)
		}
	}
	for _, c := range t.Clusters {
		if c.Err != "" {
			note(verdict{Level: levelCrit})
			continue
		}
		note(nodeHealth(c))
		for _, r := range c.Modes {
			note(syncHealth(r))
		}
		if c.TLS != nil {
			note(tlsHealth(c.TLS))
		}
	}
	note(certConsistency(t.Clusters))
	return worst, any
}

func fetchCert(ctx context.Context, address string, timeout time.Duration) *certInfo {
	u, err := url.Parse(address)
	if err != nil {
		return &certInfo{Host: address, Err: err.Error()}
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	info := &certInfo{Host: host}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		// Inspect whatever is presented, even from internal or self-signed CAs.
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname()},
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		info.Err = err.Error()
		return info
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		info.Err = "no certificate presented"
		return info
	}
	describeCert(info, certs[0], time.Now())
	return info
}

func describeCert(info *certInfo, c *x509.Certificate, now time.Time) {
	sum := sha256.Sum256(c.Raw)
	hexes := make([]string, len(sum))
	for i, b := range sum {
		hexes[i] = fmt.Sprintf("%02X", b)
	}
	info.Subject, info.Issuer = c.Subject.String(), c.Issuer.String()
	info.NotAfter = c.NotAfter
	info.Serial = strings.ToUpper(c.SerialNumber.Text(16))
	info.Fingerprint = strings.Join(hexes, ":")
	info.DaysRemaining = int(c.NotAfter.Sub(now).Hours() / 24)
	for _, n := range c.DNSNames {
		info.SANs = append(info.SANs, "DNS:"+n)
	}
	for _, ip := range c.IPAddresses {
		info.SANs = append(info.SANs, "IP Address:"+ip.String())
	}
}

// shortName turns https://eastus2-prd-3.vault.example.com:8201 into eastus2-prd-3.
func shortName(addr string) string {
	if addr == "" {
		return "?"
	}
	host := addr
	if _, rest, ok := strings.Cut(addr, "://"); ok {
		host = rest
	}
	host, _, _ = strings.Cut(host, "/")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(host) != nil {
		return host
	}
	first, _, _ := strings.Cut(host, ".")
	return cmp.Or(first, host)
}

func age(ts string, now time.Time) *time.Duration {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return nil
	}
	d := now.Sub(t)
	return &d
}

func num(v any) *int64 {
	switch n := v.(type) {
	case float64:
		i := int64(n)
		return &i
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return &i
		}
	}
	return nil
}

func anyStr(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func objects(v any) []map[string]any {
	items, _ := v.([]any)
	var out []map[string]any
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
