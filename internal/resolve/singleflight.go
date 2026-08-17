package resolve

import "sync"

// singleflight coalesces concurrent work on the same key.
//
// It exists to let the registry resolvers hold their state mutex only while
// touching state, instead of across the HTTP request. Both of them used to take
// one mutex and defer the unlock over the whole of fetch, which made every
// packument download strictly sequential — --concurrency 32 bought nothing, and
// a few-thousand-package closure cost a few-thousand round trips end to end.
//
// Simply narrowing the lock would have lost the property that made the wide one
// tempting: eight goroutines reaching the same uncached package would each fetch
// it. This keeps that guarantee — the first caller for a key does the work, the
// rest wait and share its result — while callers for DIFFERENT keys proceed in
// parallel.
//
// Written here rather than taken from golang.org/x/sync: it is twenty lines, and
// a tool whose subject is dependency weight should not add a module to avoid
// them.
type singleflight struct {
	mu sync.Mutex
	m  map[string]*flight
}

type flight struct {
	wg  sync.WaitGroup
	val any
	err error
}

// Do runs fn for key unless it is already in flight, in which case it waits and
// returns that call's result.
//
// The entry is removed once the call completes, so this coalesces concurrent
// callers rather than caching — the resolvers keep their own memo for that, and
// conflating the two would make a failed fetch permanent.
func (s *singleflight) Do(key string, fn func() (any, error)) (any, error) {
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[string]*flight)
	}
	if f, ok := s.m[key]; ok {
		s.mu.Unlock()
		f.wg.Wait()
		return f.val, f.err
	}
	f := new(flight)
	f.wg.Add(1)
	s.m[key] = f
	s.mu.Unlock()

	f.val, f.err = fn()
	f.wg.Done()

	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
	return f.val, f.err
}
