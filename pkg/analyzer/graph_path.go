package analyzer

import (
	"sort"
	"strings"
)

// A consumer asking "how does this endpoint reach that function" had no way to
// ask it. GetReachableFiles answers at file granularity, GetRecursiveCallsForCallback
// returns a set with no routes in it, and GetCallees returns a set too. So
// consumers were breadth-first searching cg.CallsFrom from outside the package,
// which is wrong twice over: the map is keyed by the spelling the DECLARATION
// had while extractCalls strips the class prefix from most call sites, and the
// map is guarded by an unexported mutex, so reading it from another package is
// unsynchronised by construction.
//
// This file is the answer to that question and the minimum surface that stops
// anyone needing to reach into the maps to ask it.

// PathFromCallbackInFile returns one route through the call graph from an
// endpoint's callback to target, and false when the walk from that callback
// never arrives at it.
//
// The route is a shortest one. The path is inclusive at both ends: the first
// element is the node the callback resolved to, which is not always the string
// that was passed -- a callback written "Class::widget()" loses its empty
// argument list, one that names a .php file becomes that file's load-time key,
// and an anonymous one stays the sentinel it arrived as -- and the last element
// is the graph's own spelling of the target, which is how a caller that asked
// for a bare name learns WHICH declaration was reached.
//
// Adjacent elements are an edge extractCalls recorded, not necessarily a call
// written in the source. A callback registered for a hook is recorded as a
// callee of the function that fires that hook, so a route through a do_action
// reads fires_it -> the_registered_callback with no node for the hook in
// between: the hook name is not in the graph at all, and nothing records which
// firing produced which edge, so no API can show it today.
//
// The route is also an over-approximate one, as every walk in this package is.
// A $this->$method() site enumerates the receiver's methods, a hook name
// composed at the call site links to a whole family of registrations, and a
// bare token may denote any declaration of that name. A returned path is
// evidence worth reading, not proof of a live call.
//
// endpointFile and fileContent are the endpoint's own file and its
// comment-stripped contents, and both earn their place: a direct endpoint's
// callback names a FILE rather than a function and resolves through the path,
// and an anonymous callback has no name at all and is seeded from the
// registration closures in that content. Pass endpointFile in the spelling the
// files map given to BuildCallGraph used -- separators are normalised, but a
// graph built from absolute paths needs an absolute endpointFile.
//
// The walk stops expanding where the callee walk stops: it does not expand a
// PHP keyword, nor a WordPress core name, unless the plugin declares a function
// of that name itself. The target is tested BEFORE that guard, so a plugin's own
// update_option is still reported as reached.
func (cg *PluginCallGraph) PathFromCallbackInFile(callback, target, endpointFile, fileContent string) ([]string, bool) {
	want := strings.TrimSuffix(strings.TrimSpace(target), "()")
	if callback == "" || want == "" {
		return nil, false
	}

	s := cg.callbackStart(callback, endpointFile, fileContent)
	if s.Declined() {
		return nil, false
	}
	if matchesPathTarget(s.Node, want) {
		return []string{s.Node}, true
	}

	// prev is write-once, so a node's parent is the first node that reached it,
	// and a breadth-first walk reaches it first at its minimum depth. It doubles
	// as the visited set, which bounds the walk to the number of distinct tokens
	// in the graph. The root is pre-seeded so no chain can walk past it and so
	// it cannot appear in a path twice.
	prev := map[string]string{s.Node: s.Node}

	// The first hop is the seed the flat walk expands, body tokens included, so
	// that this function and GetRecursiveCallsForCallbackInFile cannot disagree
	// about what is reachable.
	level := make([]string, 0, len(s.Body)+len(s.Aliases)+len(s.Calls))
	for _, v := range rankedPathNodes(s.Union()) {
		if _, seen := prev[v]; seen {
			continue
		}
		prev[v] = s.Node
		level = append(level, v)
	}

	for len(level) > 0 {
		if hit, ok := pickPathTarget(level, want); ok {
			return reconstructPath(prev, s.Node, hit), true
		}

		next := make([]string, 0, len(level))
		for _, u := range level {
			if cg.skipCallee(u) {
				continue
			}
			calls, aliases := cg.outgoingCalls(u)
			// An alias is a reachable function in its own right, so it is a
			// frontier node and not merely a route; dedupKeepFirst builds a
			// fresh slice rather than appending into either one's spare
			// capacity.
			for _, v := range rankedPathNodes(dedupKeepFirst(len(aliases)+len(calls), aliases, calls)) {
				if _, seen := prev[v]; seen {
					continue
				}
				prev[v] = u
				next = append(next, v)
			}
		}
		level = next
	}

	return nil, false
}

// PathFromCallback is PathFromCallbackInFile without the endpoint's file.
//
// It is the right form for a callback that names a function and the wrong form
// for the two kinds that do not. A direct endpoint's callback is its own file,
// which resolves here only when exactly one file in the tree carries that
// basename -- 164 of the 618 direct-endpoint files in the corpus share one --
// and an anonymous callback has no content to read a closure body out of, so it
// reaches nothing. GetRecursiveCallsForCallback stands in the same relation to
// GetRecursiveCallsForCallbackInFile, for the same reason.
func (cg *PluginCallGraph) PathFromCallback(callback, target string) ([]string, bool) {
	return cg.PathFromCallbackInFile(callback, target, "", "")
}

// OutgoingCalls returns the edges leaving one call-graph name: the functions it
// calls, and the qualified keys a bare name may itself denote.
//
// This is the resolver every walk in this package goes through, exported so
// that a consumer writing its own walk -- a different stopping rule, a
// different output shape -- does not have to read CallsFrom to do it. Reading
// that map directly means keying on the declaration's spelling rather than the
// call site's, missing both the same-name fold and PHP's method resolution
// order, and touching state an unexported mutex guards.
//
// aliases are returned separately because they are reachable functions in their
// own right and belong in a callee set, not merely as a route to further edges.
// Their own callees are already merged into calls, so a walk that wants only
// edges can ignore them. Both slices are freshly built and share no state with
// the graph.
func (cg *PluginCallGraph) OutgoingCalls(name string) (calls, aliases []string) {
	return cg.outgoingCalls(name)
}

// reconstructPath walks the predecessor map back from hit to root.
//
// It stops on reaching the root rather than on a sentinel value, because a
// sentinel would have to be a string no token can be and that is not a property
// worth having to prove about every branch of extractCalls.
func reconstructPath(prev map[string]string, root, hit string) []string {
	out := []string{hit}
	for n := hit; n != root; {
		n = prev[n]
		out = append(out, n)
		if len(out) > len(prev) {
			// Unreachable while prev is write-once; cheaper than trusting it.
			return nil
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// pickPathTarget finds the target in one frontier, preferring the spelling that
// matches outright over one that matches only by its method part, so that
// Customer::save is returned ahead of Order::save when both are one hop away.
func pickPathTarget(level []string, want string) (string, bool) {
	for _, n := range level {
		if strings.EqualFold(normalizePathToken(n), normalizePathToken(want)) {
			return n, true
		}
	}
	for _, n := range level {
		if matchesPathTarget(n, want) {
			return n, true
		}
	}
	return "", false
}

// matchesPathTarget reports whether a graph token denotes the function a caller
// asked for.
//
// Both spellings have to be normalised, not just the caller's. A caller passing
// a bare name must match a qualified declaration, because that is how a
// function declared in a class is keyed; a caller passing Customer::save must
// match the bare token save, because extractCalls strips the class prefix at
// most call sites and the bare token is frequently the only spelling on the
// route. The cost of the second clause is that Customer::save also matches
// Order::save -- the library's standing may-reach posture -- and a caller who
// needs to know which one it got reads the last element of the path.
//
// Comparison folds case because PHP function and method names are
// case-insensitive.
func matchesPathTarget(token, want string) bool {
	if strings.EqualFold(normalizePathToken(token), normalizePathToken(want)) {
		return true
	}
	return strings.EqualFold(pathMethodPart(token), pathMethodPart(want))
}

// normalizePathToken strips the parts of a token that say how a name was
// written rather than which name it is: a $this or -> receiver, and a
// namespace. A file path is left alone, because its separators are not
// namespace separators.
func normalizePathToken(s string) string {
	s = strings.TrimSpace(s)
	if isFileKey(s) {
		return strings.ReplaceAll(s, "\\", "/")
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "$this"), "->")
	if i := strings.LastIndex(s, "\\"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// pathMethodPart is the name alone, with any receiver or file qualification
// removed.
func pathMethodPart(s string) string {
	s = normalizePathToken(s)
	if i := strings.LastIndex(s, "::"); i >= 0 {
		return s[i+2:]
	}
	return s
}

// pathNodeRank orders the spellings of one call site by how much each tells a
// reader.
//
// One $this->step() site inside class Klass produces three tokens -- step,
// $this->step and Klass::step -- all at the same depth and all leading to the
// same successors, so which one a path reports is decided by the frontier's
// order. Left to lexicographic order it would be $this->step, because $ sorts
// ahead of letters, and every returned path would be full of receiver prefixes.
//
// This only ever reorders. A receiver-prefixed token stays in the frontier,
// because for a method whose name collides with a WordPress core function it
// can be the only edge there is.
func pathNodeRank(name string) int {
	switch {
	case strings.HasPrefix(name, "$this->"):
		return 4
	case strings.HasPrefix(name, "->"):
		return 5
	}
	if i := strings.LastIndex(name, "::"); i >= 0 {
		if strings.HasSuffix(strings.ToLower(name[:i]), ".php") {
			return 1
		}
		return 0
	}
	if isFileKey(name) {
		return 2
	}
	return 3
}

// rankedPathNodes deduplicates a frontier and puts it in a stable, informative
// order. The underlying data is already deterministic -- BuildCallGraph
// processes its files in sorted order and extractCalls sorts its result -- so
// this is about which spelling represents a call site, not about repairing a
// nondeterminism.
func rankedPathNodes(names []string) []string {
	out := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := pathNodeRank(out[i]), pathNodeRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}
