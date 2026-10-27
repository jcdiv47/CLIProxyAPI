package auth

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	// leastUsedTieTolerance is the score gap within which candidates are treated as equal
	// and rotated round-robin, so near-identical accounts do not flip-flop on every
	// small utilization change.
	leastUsedTieTolerance = 0.05
	// leastUsedExhaustedUtilization marks a usage window as effectively exhausted. Routing
	// away slightly before the hard limit avoids burning a request on a 429.
	leastUsedExhaustedUtilization = 0.98
	// leastUsedExhaustedScore ranks exhausted credentials below every usable one while
	// still allowing them as a last resort.
	leastUsedExhaustedScore = -1.0
)

// claudeUsageWindow describes one credential-wide Anthropic unified rate-limit window.
type claudeUsageWindow struct {
	name   string
	length time.Duration
}

var (
	claudeFiveHourWindow = claudeUsageWindow{name: "5h", length: 5 * time.Hour}
	claudeSevenDayWindow = claudeUsageWindow{name: "7d", length: 7 * 24 * time.Hour}
)

// LeastUsedSelector routes each request to the credential with the most headroom left in
// its short upstream usage window, using the passive quota snapshot observed from upstream
// response headers (Claude's 5h unified window). Headroom is scaled by the credential weight
// so larger plans absorb proportionally more traffic. Credentials whose 5h or 7d window is
// exhausted are used only when nothing else is available. Credentials without a usable
// snapshot count as fully available, so providers that report no usage degrade to
// round-robin.
type LeastUsedSelector struct {
	mu         sync.Mutex
	lastPicked map[string]string
	maxKeys    int
	nowFunc    func() time.Time
}

// Pick selects the available auth with the most remaining short-window headroom, rotating
// among candidates whose scores are within leastUsedTieTolerance of the best.
func (s *LeastUsedSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	if s.nowFunc != nil {
		now = s.nowFunc()
	}
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	best := leastUsedCandidates(available, now)
	key := provider + ":" + canonicalModelKey(model)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPicked == nil {
		s.lastPicked = make(map[string]string)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.lastPicked[key]; !ok && len(s.lastPicked) >= limit {
		s.lastPicked = make(map[string]string)
	}
	picked := best[successorIndex(best, s.lastPicked[key])]
	s.lastPicked[key] = picked.ID
	return picked, nil
}

// leastUsedCandidates returns the candidates whose score is within leastUsedTieTolerance of
// the best score, preserving the input (ID-sorted) order.
func leastUsedCandidates(available []*Auth, now time.Time) []*Auth {
	var maxWeight int64 = 1
	for _, auth := range available {
		if weight := authWeight(auth); weight > maxWeight {
			maxWeight = weight
		}
	}
	scores := make([]float64, len(available))
	bestScore := math.Inf(-1)
	for i, auth := range available {
		scores[i] = leastUsedScore(auth, now, maxWeight)
		if scores[i] > bestScore {
			bestScore = scores[i]
		}
	}
	best := make([]*Auth, 0, len(available))
	for i, auth := range available {
		if scores[i] >= bestScore-leastUsedTieTolerance {
			best = append(best, auth)
		}
	}
	return best
}

// leastUsedScore returns the credential's weighted 5h headroom normalized to [0, 1], or
// leastUsedExhaustedScore when its 5h or 7d window is exhausted.
func leastUsedScore(auth *Auth, now time.Time, maxWeight int64) float64 {
	if auth == nil {
		return leastUsedExhaustedScore
	}
	quota := auth.Quota
	if claudeWindowExhausted(quota, claudeFiveHourWindow, now) || claudeWindowExhausted(quota, claudeSevenDayWindow, now) {
		return leastUsedExhaustedScore
	}
	headroom := 1.0
	if used, ok := claudeWindowUtilization(quota, claudeFiveHourWindow, now); ok {
		headroom = 1 - used
	}
	weight := authWeight(auth)
	if weight <= 0 {
		weight = 1
	}
	return headroom * float64(weight) / float64(maxWeight)
}

// claudeWindowExhausted reports whether the observed window is rejected or at its limit.
func claudeWindowExhausted(quota QuotaState, window claudeUsageWindow, now time.Time) bool {
	if !claudeWindowActive(quota, window, now) {
		return false
	}
	if status, ok := quotaSignalValue(quota.Signals, "anthropic-ratelimit-unified-"+window.name+"-status"); ok && strings.EqualFold(status, "rejected") {
		return true
	}
	used, ok := claudeWindowUtilization(quota, window, now)
	return ok && used >= leastUsedExhaustedUtilization
}

// claudeWindowUtilization returns the observed utilization fraction for a window that has
// not rolled over since the snapshot was taken. Values are clamped to [0, 1].
func claudeWindowUtilization(quota QuotaState, window claudeUsageWindow, now time.Time) (float64, bool) {
	if !claudeWindowActive(quota, window, now) {
		return 0, false
	}
	raw, ok := quotaSignalValue(quota.Signals, "anthropic-ratelimit-unified-"+window.name+"-utilization")
	if !ok {
		return 0, false
	}
	used, errParse := strconv.ParseFloat(raw, 64)
	if errParse != nil || math.IsNaN(used) {
		return 0, false
	}
	return math.Min(math.Max(used, 0), 1), true
}

// claudeWindowActive reports whether the snapshot still describes the current window. A
// snapshot is stale once the window's reset time has passed, or, when no reset time was
// reported, once a full window length has elapsed since the observation. Credentials that
// receive no traffic never refresh their snapshot, so this is what lets them recover.
func claudeWindowActive(quota QuotaState, window claudeUsageWindow, now time.Time) bool {
	if raw, ok := quotaSignalValue(quota.Signals, "anthropic-ratelimit-unified-"+window.name+"-reset"); ok {
		if resetUnix, errParse := strconv.ParseInt(raw, 10, 64); errParse == nil && resetUnix > 0 {
			return now.Before(time.Unix(resetUnix, 0))
		}
	}
	if quota.ObservedAt.IsZero() {
		return false
	}
	return now.Before(quota.ObservedAt.Add(window.length))
}

// quotaSignalValue looks up an observed signal by header name, case-insensitively.
func quotaSignalValue(signals map[string]string, name string) (string, bool) {
	if len(signals) == 0 {
		return "", false
	}
	if value, ok := signals[http.CanonicalHeaderKey(name)]; ok {
		return strings.TrimSpace(value), true
	}
	for key, value := range signals {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}
