package main

import (
	"context"

	"github.com/jverhoeks/deepdep/internal/store"
)

// alreadyScanned reports which clone URLs the store already holds a run for.
//
// Resumability is not a nicety at organisation scale: scanning fifty
// repositories is tens of minutes of cloning and registry traffic, and a
// transient failure part-way through must not mean starting again.
func alreadyScanned(ctx context.Context, dbPath string) (map[string]bool, error) {
	db, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	runs, err := db.Runs(ctx, 5000)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(runs))
	for _, r := range runs {
		seen[r.Target] = true
	}
	return seen, nil
}

// latestRunFor finds the newest run for one target.
//
// An organisation scan puts many repositories in one database, so `report` can
// no longer be handed "the last run" — that would report whichever repository
// happened to finish last, for every row in the table.
func latestRunFor(dbPath, target string) (string, error) {
	db, err := store.Open(dbPath)
	if err != nil {
		return "", err
	}
	defer db.Close()
	runs, err := db.Runs(context.Background(), 5000)
	if err != nil {
		return "", err
	}
	for _, r := range runs { // Runs is newest-first
		if r.Target == target {
			return r.RunID, nil
		}
	}
	return "", nil
}
