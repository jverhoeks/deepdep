package advisory_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jverhoeks/deepdep/internal/advisory"
	"github.com/jverhoeks/deepdep/internal/graph"
)

// stub serves the two-stage OSV shape: querybatch returns ids only, details come
// from /v1/vulns/{id}.
func stub(t *testing.T, hits map[string][]string, recs map[string]map[string]any) (*httptest.Server, *int) {
	t.Helper()
	var batchCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		batchCalls++
		var body struct {
			Queries []struct {
				Package struct {
					PURL string `json:"purl"`
				} `json:"package"`
			} `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		out := map[string]any{}
		var results []any
		for _, q := range body.Queries {
			var vulns []any
			for _, id := range hits[q.Package.PURL] {
				vulns = append(vulns, map[string]any{"id": id, "modified": "2026-01-01T00:00:00Z"})
			}
			results = append(results, map[string]any{"vulns": vulns})
		}
		out["results"] = results
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/v1/vulns/"):]
		rec, ok := recs[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(rec)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &batchCalls
}

func TestCheckMapsAdvisoriesToPackages(t *testing.T) {
	srv, _ := stub(t,
		map[string][]string{
			"pkg:npm/lodash@4.17.15": {"GHSA-a", "GHSA-b"},
			"pkg:pypi/requests@2.0":  {"GHSA-a"},
		},
		map[string]map[string]any{
			"GHSA-a": {"id": "GHSA-a", "summary": "bad thing", "published": "2020-01-01T00:00:00Z",
				"aliases": []string{"CVE-2020-1111"}, "database_specific": map[string]any{"severity": "HIGH"}},
			"GHSA-b": {"id": "GHSA-b", "summary": "other", "published": "2021-01-01T00:00:00Z",
				"database_specific": map[string]any{"severity": "LOW"}},
		})

	got, err := advisory.New(srv.URL, srv.Client()).Check(context.Background(),
		[]graph.NodeID{"pkg:npm/lodash@4.17.15", "pkg:pypi/requests@2.0", "pkg:npm/clean@1.0.0"},
		time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("findings = %d, want 3", len(got))
	}
	var sawCVE bool
	for _, f := range got {
		if f.Advisory.ID == "GHSA-a" && f.Advisory.CVE() == "CVE-2020-1111" {
			sawCVE = true
		}
	}
	if !sawCVE {
		t.Error("the CVE alias must be surfaced; OSV ids are usually GHSA")
	}
}

// Knowledge time is the whole point of the bitemporal design: an advisory that
// did not exist yet is not something we could have known.
func TestCheckFiltersByKnowledgeTime(t *testing.T) {
	srv, _ := stub(t,
		map[string][]string{"pkg:npm/x@1.0.0": {"OLD", "NEW", "GONE"}},
		map[string]map[string]any{
			"OLD":  {"id": "OLD", "published": "2020-01-01T00:00:00Z"},
			"NEW":  {"id": "NEW", "published": "2026-01-01T00:00:00Z"},
			"GONE": {"id": "GONE", "published": "2019-01-01T00:00:00Z", "withdrawn": "2021-01-01T00:00:00Z"},
		})

	at2022 := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := advisory.New(srv.URL, srv.Client()).Check(context.Background(),
		[]graph.NodeID{"pkg:npm/x@1.0.0"}, at2022)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Advisory.ID != "OLD" {
		t.Fatalf("got %+v, want only OLD: NEW was not published yet and GONE was withdrawn", got)
	}

	all, _ := advisory.New(srv.URL, srv.Client()).Check(context.Background(),
		[]graph.NodeID{"pkg:npm/x@1.0.0"}, time.Now())
	if len(all) != 2 {
		t.Errorf("today should know OLD and NEW (GONE stays withdrawn), got %d", len(all))
	}
}

// querybatch is capped at 1000 queries, so a larger set must be chunked or the
// tail is silently dropped.
func TestCheckChunksLargeInputs(t *testing.T) {
	hits := map[string][]string{}
	var purls []graph.NodeID
	for i := 0; i < 2500; i++ {
		p := graph.NodeID("pkg:npm/p" + string(rune('a'+i%26)) + "@" + time.Duration(i).String())
		purls = append(purls, p)
	}
	srv, calls := stub(t, hits, nil)
	if _, err := advisory.New(srv.URL, srv.Client()).Check(context.Background(), purls, time.Now()); err != nil {
		t.Fatal(err)
	}
	if *calls != 3 {
		t.Errorf("batch calls = %d, want 3 for 2500 queries at 1000 per request", *calls)
	}
}
