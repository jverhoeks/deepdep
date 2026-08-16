package extract

// distTags are the moving references a package manager accepts where a version
// is expected. They name "whatever is newest right now", which is a promise
// about the future rather than a fact about a build.
//
// They must never become a version node. OSV, asked about `npm/npm@latest`,
// cannot order that against any fixed range and answers with every npm advisory
// ever published — CVE-2013-4116 against an image whose npm is current. Six
// CRITICAL and 36 HIGH findings across a 163-repository fleet rested on
// versions that do not exist.
var distTags = map[string]bool{
	"latest": true, "next": true, "stable": true, "edge": true, "lts": true,
	"nightly": true, "preview": true, "canary": true, "experimental": true,
	"beta": true, "alpha": true, "rc": true, "dev": true,
	"main": true, "master": true, "head": true,
}

// isDistTag reports whether a parsed version token is really a moving tag.
func isDistTag(v string) bool { return distTags[v] }
