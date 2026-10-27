package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

var leastUsedTestNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func leastUsedTestAuth(id string, signals map[string]string) *Auth {
	return &Auth{
		ID:       id,
		Provider: "claude",
		Quota:    QuotaState{ObservedAt: leastUsedTestNow.Add(-time.Minute), Signals: signals},
	}
}

func claudeUsageSignals(fiveHourUsed string, fiveHourReset time.Time) map[string]string {
	return map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-5h-Utilization": fiveHourUsed,
		"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(fiveHourReset.Unix(), 10),
	}
}

func leastUsedPickIDs(t *testing.T, selector *LeastUsedSelector, auths []*Auth, picks int) []string {
	t.Helper()
	ids := make([]string, 0, picks)
	for i := 0; i < picks; i++ {
		got, errPick := selector.Pick(context.Background(), "claude", "claude-opus", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("Pick() #%d error = %v", i, errPick)
		}
		ids = append(ids, got.ID)
	}
	return ids
}

func assertAllPicks(t *testing.T, ids []string, want string) {
	t.Helper()
	for i, id := range ids {
		if id != want {
			t.Fatalf("pick #%d = %q, want %q; all=%v", i, id, want, ids)
		}
	}
}

func TestLeastUsedSelectorPrefersMostFiveHourHeadroom(t *testing.T) {
	selector := &LeastUsedSelector{nowFunc: func() time.Time { return leastUsedTestNow }}
	reset := leastUsedTestNow.Add(2 * time.Hour)
	auths := []*Auth{
		leastUsedTestAuth("a", claudeUsageSignals("0.80", reset)),
		leastUsedTestAuth("b", claudeUsageSignals("0.30", reset)),
	}

	assertAllPicks(t, leastUsedPickIDs(t, selector, auths, 4), "b")
}

func TestLeastUsedSelectorRotatesNearEqualCandidates(t *testing.T) {
	selector := &LeastUsedSelector{nowFunc: func() time.Time { return leastUsedTestNow }}
	reset := leastUsedTestNow.Add(2 * time.Hour)
	auths := []*Auth{
		leastUsedTestAuth("a", claudeUsageSignals("0.40", reset)),
		leastUsedTestAuth("b", claudeUsageSignals("0.42", reset)),
		leastUsedTestAuth("c", claudeUsageSignals("0.90", reset)),
	}

	got := leastUsedPickIDs(t, selector, auths, 4)
	want := []string{"a", "b", "a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("picks = %v, want %v", got, want)
		}
	}
}

func TestLeastUsedSelectorWithoutSignalsBehavesLikeRoundRobin(t *testing.T) {
	selector := &LeastUsedSelector{nowFunc: func() time.Time { return leastUsedTestNow }}
	auths := []*Auth{{ID: "a", Provider: "codex"}, {ID: "b", Provider: "codex"}}

	got := leastUsedPickIDs(t, selector, auths, 4)
	want := []string{"a", "b", "a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("picks = %v, want %v", got, want)
		}
	}
}

func TestLeastUsedSelectorTreatsRolledOverWindowAsFresh(t *testing.T) {
	selector := &LeastUsedSelector{nowFunc: func() time.Time { return leastUsedTestNow }}
	auths := []*Auth{
		// Exhausted snapshot whose 5h window already reset: the account is idle and fresh.
		leastUsedTestAuth("a", map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Status":      "rejected",
			"Anthropic-Ratelimit-Unified-5h-Utilization": "1.00",
			"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(leastUsedTestNow.Add(-time.Minute).Unix(), 10),
		}),
		leastUsedTestAuth("b", claudeUsageSignals("0.50", leastUsedTestNow.Add(time.Hour))),
	}

	assertAllPicks(t, leastUsedPickIDs(t, selector, auths, 3), "a")
}

func TestLeastUsedSelectorExpiresSnapshotWithoutResetAfterWindowLength(t *testing.T) {
	selector := &LeastUsedSelector{nowFunc: func() time.Time { return leastUsedTestNow }}
	stale := leastUsedTestAuth("a", map[string]string{"Anthropic-Ratelimit-Unified-5h-Utilization": "0.95"})
	stale.Quota.ObservedAt = leastUsedTestNow.Add(-6 * time.Hour)
	fresh := leastUsedTestAuth("b", map[string]string{"Anthropic-Ratelimit-Unified-5h-Utilization": "0.50"})

	assertAllPicks(t, leastUsedPickIDs(t, selector, []*Auth{stale, fresh}, 3), "a")
}

func TestLeastUsedSelectorUsesExhaustedCredentialsOnlyAsLastResort(t *testing.T) {
	selector := &LeastUsedSelector{nowFunc: func() time.Time { return leastUsedTestNow }}
	fiveHourReset := leastUsedTestNow.Add(time.Hour)
	weekly := claudeUsageSignals("0.05", fiveHourReset)
	weekly["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.99"
	weekly["Anthropic-Ratelimit-Unified-7d-Reset"] = strconv.FormatInt(leastUsedTestNow.Add(48*time.Hour).Unix(), 10)
	rejected := claudeUsageSignals("0.10", fiveHourReset)
	rejected["Anthropic-Ratelimit-Unified-5h-Status"] = "rejected"
	auths := []*Auth{
		leastUsedTestAuth("a-weekly-exhausted", weekly),
		leastUsedTestAuth("b-rejected", rejected),
		leastUsedTestAuth("c-busy", claudeUsageSignals("0.90", fiveHourReset)),
	}

	assertAllPicks(t, leastUsedPickIDs(t, selector, auths, 3), "c-busy")

	got := leastUsedPickIDs(t, selector, auths[:2], 2)
	if got[0] == got[1] {
		t.Fatalf("all-exhausted picks = %v, want rotation across exhausted credentials", got)
	}
}

func TestLeastUsedSelectorIgnoresModelScopedRejection(t *testing.T) {
	selector := &LeastUsedSelector{nowFunc: func() time.Time { return leastUsedTestNow }}
	reset := leastUsedTestNow.Add(time.Hour)
	overage := claudeUsageSignals("0.10", reset)
	overage["Anthropic-Ratelimit-Unified-Status"] = "rejected"
	overage["Anthropic-Ratelimit-Unified-Overage-Status"] = "rejected"
	auths := []*Auth{
		leastUsedTestAuth("a", overage),
		leastUsedTestAuth("b", claudeUsageSignals("0.60", reset)),
	}

	assertAllPicks(t, leastUsedPickIDs(t, selector, auths, 3), "a")
}

func TestLeastUsedSelectorScalesHeadroomByWeight(t *testing.T) {
	selector := &LeastUsedSelector{nowFunc: func() time.Time { return leastUsedTestNow }}
	reset := leastUsedTestNow.Add(time.Hour)
	large := leastUsedTestAuth("a-large", claudeUsageSignals("0.60", reset))
	large.Attributes = map[string]string{AttributeWeight: "4"}
	small := leastUsedTestAuth("b-small", claudeUsageSignals("0.10", reset))

	// 0.4 * 4 = 1.6 effective headroom beats 0.9 * 1.
	assertAllPicks(t, leastUsedPickIDs(t, selector, []*Auth{large, small}, 3), "a-large")
}

func TestManagerLeastUsedSelectorPicksMostHeadroom(t *testing.T) {
	manager := NewManager(nil, &LeastUsedSelector{}, nil)
	manager.executors["claude"] = schedulerTestExecutor{}

	reset := time.Now().Add(2 * time.Hour)
	auths := []*Auth{
		{ID: "least-used-busy", Provider: "claude", Quota: QuotaState{ObservedAt: time.Now(), Signals: claudeUsageSignals("0.95", reset)}},
		{ID: "least-used-idle", Provider: "claude", Quota: QuotaState{ObservedAt: time.Now(), Signals: claudeUsageSignals("0.20", reset)}},
	}
	for _, auth := range auths {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
		}
	}
	registerSchedulerModels(t, "claude", "claude-opus-least-used", "least-used-busy", "least-used-idle")

	for i := 0; i < 3; i++ {
		got, _, errPick := manager.pickNext(context.Background(), "claude", "claude-opus-least-used", cliproxyexecutor.Options{}, nil)
		if errPick != nil {
			t.Fatalf("pickNext() #%d error = %v", i, errPick)
		}
		if got.ID != "least-used-idle" {
			t.Fatalf("pickNext() #%d = %q, want least-used-idle", i, got.ID)
		}
	}
}
