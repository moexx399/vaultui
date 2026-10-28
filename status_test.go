package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func replicationFrom(t *testing.T, mode, js string) *replication {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal([]byte(js), &b); err != nil {
		t.Fatal(err)
	}
	return parseReplication(mode, b, time.Now())
}

func testTopology(t *testing.T, remoteWAL int) []topology {
	hb := time.Now().Add(-5 * time.Second).UTC().Format(time.RFC3339)
	primary := &cluster{
		Contexts: []string{"prd-cloud"}, Address: "https://centralus-prd-3.vault.example.com",
		HealthCode: 200, Version: "1.17.2", ClusterID: "c-primary",
		Modes: map[string]*replication{"dr": replicationFrom(t, "dr", `{
			"mode": "primary", "state": "running", "cluster_id": "dr-set", "merkle_root": "abcdef0123456789",
			"last_wal": 4800, "last_dr_wal": 5000, "known_secondaries": ["sec-a", "sec-gone"],
			"secondaries": [{"node_id": "sec-a", "api_address": "https://eastus2-prd-3.vault.example.com:8200",
				"connection_status": "connected", "last_heartbeat": "`+hb+`", "clock_skew_ms": "0"}]}`)},
	}
	// Reached through a load-balancer alias, so only the replication cluster
	// ID ties it to its primary.
	secondary := &cluster{
		Contexts: []string{"prd-cloud-dr"}, Address: "https://vault-dr.example.com",
		HealthCode: 472, Version: "1.17.2", ClusterID: "c-secondary",
		Modes: map[string]*replication{"dr": replicationFrom(t, "dr", `{
			"mode": "secondary", "state": "stream-wals", "cluster_id": "dr-set", "secondary_id": "sec-a",
			"connection_state": "ready", "last_remote_wal": `+itoa(remoteWAL)+`,
			"primary_cluster_addr": "https://10.0.0.1:8201",
			"primaries": [{"api_address": "https://10.0.0.1:8200", "connection_status": "connected", "last_heartbeat": "`+hb+`"}]}`)},
	}
	alias := &cluster{Contexts: []string{"prd-cloud-alias"}, Address: "https://vault-prod.example.com", HealthCode: 200, ClusterID: "c-primary"}
	lone := &cluster{Contexts: []string{"lab"}, Address: "https://lab.example.com", HealthCode: 200, ClusterID: "c-lab", Modes: map[string]*replication{}}
	down := &cluster{Contexts: []string{"down"}, Err: "dial tcp: connection refused"}
	return buildTopologies([]*cluster{secondary, lone, primary, alias, down})
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestTopologyLinksAndHealth(t *testing.T) {
	tops := testTopology(t, 4950)
	var names []string
	for _, tp := range tops {
		names = append(names, tp.Name)
	}
	if strings.Join(names, "|") != "down|lab|prd-cloud, prd-cloud-alias" {
		t.Fatalf("topologies %q", names)
	}
	prd := tops[2]
	if len(prd.Clusters) != 2 {
		t.Fatalf("clusters %d (alias should merge into the primary)", len(prd.Clusters))
	}
	var sec *replication
	for _, c := range prd.Clusters {
		if r := c.Modes["dr"]; r.Role == "secondary" {
			sec = r
		}
	}
	if sec.Primary == nil || sec.WALLag == nil || *sec.WALLag != 50 {
		t.Fatalf("secondary not linked: %+v", sec)
	}
	if v := syncHealth(sec); v.Level != levelOK {
		t.Fatalf("secondary health %+v", v)
	}
	// The secondary is reached via a DR-secondary node, which is a warning.
	if lvl, _ := prd.overall(); lvl != levelWarn {
		t.Fatalf("overall %v", lvl)
	}

	page := renderTopology(prd, 120)
	for _, s := range []string{"[PRIMARY]", "wal=5,000", "├─▶", "lag=+50", "link: connected", "└─▶", "sec-gone", "routed to dr-secondary node", "Overall: WARNING"} {
		if !strings.Contains(page, s) {
			t.Errorf("page missing %q:\n%s", s, page)
		}
	}
	if !strings.Contains(renderTopology(tops[0], 120), "connection refused") {
		t.Error("unreachable context not shown")
	}
}

func TestWALLagLevels(t *testing.T) {
	for remote, want := range map[int]level{4950: levelOK, 4800: levelWarn, 1000: levelCrit, 0: levelCrit} {
		tops := testTopology(t, remote)
		for _, c := range tops[2].Clusters {
			if r := c.Modes["dr"]; r.Role == "secondary" {
				if got := syncHealth(r).Level; got != want {
					t.Errorf("remote_wal %d: level %v, want %v (%v)", remote, got, want, syncHealth(r).Reasons)
				}
			}
		}
	}
}

func TestCertChecks(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xBEEF), Subject: pkix.Name{CommonName: "vault.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 24 * time.Hour), DNSNames: []string{"vault.example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	info := &certInfo{}
	describeCert(info, cert, now)
	if info.Serial != "BEEF" || info.SANs[0] != "DNS:vault.example.com" || info.DaysRemaining != 9 {
		t.Fatalf("cert %+v", info)
	}
	if v := tlsHealth(info); v.Level != levelWarn {
		t.Fatalf("10-day cert: %+v", v)
	}

	a := &cluster{Contexts: []string{"a"}, TLS: &certInfo{Fingerprint: "X"}}
	b := &cluster{Contexts: []string{"b"}, TLS: &certInfo{Fingerprint: "X"}}
	c := &cluster{Contexts: []string{"c"}, TLS: &certInfo{Fingerprint: "Y"}}
	v := certConsistency([]*cluster{a, b, c})
	if v.Level != levelCrit || v.Reasons[0] != "c cert differs from a, b" {
		t.Fatalf("consistency %+v", v)
	}
}

func TestShortName(t *testing.T) {
	for in, want := range map[string]string{
		"https://eastus2-prd-3.vault.example.com:8201": "eastus2-prd-3",
		"https://10.0.0.1:8201":                        "10.0.0.1",
		"":                                             "?",
	} {
		if got := shortName(in); got != want {
			t.Errorf("shortName(%q) = %q, want %q", in, got, want)
		}
	}
}
