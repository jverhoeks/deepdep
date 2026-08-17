// Package forge lists what a code host holds, so a scan can cover an
// organisation rather than one repository at a time.
package forge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Repo is the little a scan needs to know before it clones.
type Repo struct {
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
	Stars    int    `json:"stargazers_count"`
	Language string `json:"language"`
	Archived bool   `json:"archived"`
	Fork     bool   `json:"fork"`
	Size     int    `json:"size"` // KB, as GitHub reports it
	Pushed   string `json:"pushed_at"`
}

// Options narrow what an organisation scan covers.
//
// Forks and archived repositories are excluded by default because including
// them answers a different question: a fork's risk belongs to whoever it was
// forked from, and an archived repository is not something anyone is going to
// fix. Both are one flag away when the question really is "everything we host".
type Options struct {
	IncludeForks    bool
	IncludeArchived bool
	Limit           int // 0 = no limit
}

// Client reads a code host. Only GitHub for now; the type exists so a second
// host lands as another constructor rather than as a second call site
// everywhere.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

func New(base, token string, hc *http.Client) *Client {
	if base == "" {
		base = "https://api.github.com"
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, hc: hc}
}

// Token finds a GitHub credential without asking the user to plumb one through.
//
// Unauthenticated GitHub is 60 requests an hour, which one org listing can
// exhaust, so an available token is worth looking for. `gh` is consulted last
// and only as a read: it is the tool most developers already have logged in,
// and shelling out to it is cheaper than making them export a variable they
// have already given to something else.
func Token() string {
	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ErrNoSuchOwner is returned when GitHub has no such organisation or user. It is
// the ONLY condition that justifies trying the other endpoint.
var ErrNoSuchOwner = errors.New("no such organisation or user")

// ErrSAML marks a refusal that no retry and no scope change will fix: the token
// exists and is valid, and the organisation has not authorised it. Only a
// browser round-trip clears it, so the error has to say so.
var ErrSAML = errors.New("organisation SAML enforcement")

// samlError carries GitHub's own sentence so the caller can print it once and
// append the organisation-specific fix, rather than concatenating two
// overlapping explanations of the same refusal.
type samlError struct{ msg string }

func (e *samlError) Error() string        { return e.msg }
func (e *samlError) Is(target error) bool { return target == ErrSAML }

// Org lists an organisation's repositories, newest activity first.
//
// It falls back to the user endpoint when the name is a user rather than an
// organisation, because people type `deepdep org torvalds` and being told "not
// an org" helps nobody.
//
// The fallback fires ONLY on 404. It used to fire on any error, which made a
// rate limit indistinguishable from a wrong name: a listing that died on page
// three came back as whatever the user endpoint happened to return, and the
// fleet report printed that as the organisation's size. One scan of
// schubergphilis reported 186 repositories and the next 144, with nothing said
// about the 42 — every fleet total silently measuring a different fleet.
//
// A partial list is worse here than no list. Every number downstream is a sum
// over the repositories in it.
func (c *Client) Org(ctx context.Context, name string, o Options) ([]Repo, error) {
	repos, err := c.list(ctx, fmt.Sprintf("/orgs/%s/repos", name), o)
	if err == nil {
		if len(repos) > 0 {
			return repos, nil
		}
	} else if errors.Is(err, ErrSAML) {
		// Named here rather than in decodePage, which knows the URL it fetched but
		// not the organisation the reader has to click through for.
		return nil, fmt.Errorf(
			"%s Run `gh auth refresh -h github.com -s read:org`, then authorise the token at "+
				"https://github.com/orgs/%s/sso", err, name)
	} else if !errors.Is(err, ErrNoSuchOwner) {
		return nil, err
	}
	userRepos, userErr := c.list(ctx, fmt.Sprintf("/users/%s/repos", name), o)
	if userErr == nil && len(userRepos) > 0 {
		return userRepos, nil
	}
	if userErr != nil && !errors.Is(userErr, ErrNoSuchOwner) {
		return nil, userErr
	}
	return nil, fmt.Errorf("no repositories found for %q", name)
}

func (c *Client) list(ctx context.Context, path string, o Options) ([]Repo, error) {
	var out []Repo
	for page := 1; page <= 20; page++ { // 20 * 100 = 2000, well past any sane org
		url := fmt.Sprintf("%s%s?per_page=100&page=%d&sort=pushed&direction=desc",
			c.base, path, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, err
		}
		// Named `batch` rather than `page`: the loop variable is the page NUMBER,
		// and shadowing it with the page CONTENTS reads as a bug even when it
		// is not one.
		batch, err := decodePage(resp)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			if r.Fork && !o.IncludeForks {
				continue
			}
			if r.Archived && !o.IncludeArchived {
				continue
			}
			out = append(out, r)
			if o.Limit > 0 && len(out) >= o.Limit {
				return out, nil
			}
		}
		if len(batch) < 100 {
			break // a short page is the last page
		}
	}
	return out, nil
}

func decodePage(resp *http.Response) ([]Repo, error) {
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		// A 403 is at least three different problems with three different fixes,
		// and GitHub sends X-RateLimit-Reset on EVERY response — so keying the
		// message off that header alone reported SAML enforcement as a rate limit
		// and sent the reader to `gh auth login`, which cannot fix it. Exhaustion
		// is signalled by Remaining, not by the presence of Reset.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		if msg := githubMessage(body); strings.Contains(msg, "SAML") {
			return nil, &samlError{msg: msg}
		}
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			if ts, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
				return nil, fmt.Errorf(
					"github rate limit reached (resets %s). Set GITHUB_TOKEN or run `gh auth login`: "+
						"unauthenticated is 60 requests an hour, authenticated is 5000",
					time.Unix(ts, 0).Format(time.Kitchen))
			}
			return nil, fmt.Errorf("github rate limit reached. Set GITHUB_TOKEN or run `gh auth login`")
		}
		if msg := githubMessage(body); msg != "" {
			return nil, fmt.Errorf("github refused the request: %s", msg)
		}
		return nil, fmt.Errorf("github refused the request (%s); a token is probably needed", resp.Status)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoSuchOwner
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: %s", resp.Status)
	}
	var page []Repo
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, err
	}
	return page, nil
}

// githubMessage pulls the human-readable reason out of an error body.
//
// GitHub explains a 403 in the body and nowhere else — the status line is the
// same three digits whether the token is exhausted, unauthorised for a
// SAML-protected organisation, or missing a scope. Passing that sentence through
// is the difference between a fix and a guess.
func githubMessage(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return ""
	}
	return strings.TrimSpace(e.Message)
}
