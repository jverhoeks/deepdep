// Package forge lists what a code host holds, so a scan can cover an
// organisation rather than one repository at a time.
package forge

import (
	"context"
	"encoding/json"
	"fmt"
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

// Org lists an organisation's repositories, newest activity first.
//
// It falls back to the user endpoint when the name is a user rather than an
// organisation, because people type `deepdep org torvalds` and being told "not
// an org" helps nobody.
func (c *Client) Org(ctx context.Context, name string, o Options) ([]Repo, error) {
	repos, err := c.list(ctx, fmt.Sprintf("/orgs/%s/repos", name), o)
	if err == nil && len(repos) > 0 {
		return repos, nil
	}
	userRepos, userErr := c.list(ctx, fmt.Sprintf("/users/%s/repos", name), o)
	if userErr == nil && len(userRepos) > 0 {
		return userRepos, nil
	}
	if err != nil {
		return nil, err
	}
	if userErr != nil {
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
		// Rate limiting is the failure people actually hit, and "403" tells them
		// nothing about the fix. Reset time comes back as a unix timestamp.
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			if ts, err := strconv.ParseInt(reset, 10, 64); err == nil {
				return nil, fmt.Errorf(
					"github rate limit reached (resets %s). Set GITHUB_TOKEN or run `gh auth login`: "+
						"unauthenticated is 60 requests an hour, authenticated is 5000",
					time.Unix(ts, 0).Format(time.Kitchen))
			}
		}
		return nil, fmt.Errorf("github refused the request (%s); a token is probably needed", resp.Status)
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
