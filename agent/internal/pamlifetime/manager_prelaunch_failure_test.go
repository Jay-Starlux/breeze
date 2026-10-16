package pamlifetime

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/breeze-rmm/agent/internal/logging"
)

// captureLogs redirects the package logger into a buffer for one test.
// logging.Init is global, so tests using it must not run in parallel.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	logging.Init("text", "debug", buf)
	t.Cleanup(func() { logging.Init("text", "info", nil) })
	return buf
}

func TestPreLaunchFailureLogsUnderlyingError(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*fakeWindowsPrimitives, *fakeAccountLifecycle)
		wantCode string
		wantErr  string
	}{
		{
			name: "promote fails",
			setup: func(_ *fakeWindowsPrimitives, a *fakeAccountLifecycle) {
				a.promoteErr = errors.New("NetUserSetInfo: user name could not be found (2221)")
			},
			wantCode: "account_promotion_failed",
			wantErr:  "user name could not be found (2221)",
		},
		{
			name: "create process fails",
			setup: func(w *fakeWindowsPrimitives, _ *fakeAccountLifecycle) {
				w.createProcessErr = errors.New("CreateProcessAsUser: access denied")
			},
			wantCode: "create_process_failed",
			wantErr:  "CreateProcessAsUser: access denied",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			var order []string
			win := &fakeWindowsPrimitives{order: &order}
			account := &fakeAccountLifecycle{order: &order}
			tt.setup(win, account)
			manager := newLifecycleManager(NewStore(filepath.Join(t.TempDir(), "ledger.json")), win, account, nil)

			result := manager.Apply(context.Background(), validApply(1))

			// The wire contract is unchanged: same state and failure code.
			if result.State != ResultFailed || result.FailureCode != tt.wantCode {
				t.Fatalf("Apply = %s/%s, want failed/%s", result.State, result.FailureCode, tt.wantCode)
			}
			out := logs.String()
			for _, want := range []string{
				"PAM apply failed before launch",
				"failureCode=" + tt.wantCode,
				"actuationId=" + testActuationID,
				tt.wantErr,
			} {
				if !strings.Contains(out, want) {
					t.Errorf("log missing %q\nlog:\n%s", want, out)
				}
			}
			// The credential must never reach a log line.
			if strings.Contains(out, "ephemeral") {
				t.Errorf("log leaked the elevation password:\n%s", out)
			}
		})
	}
}

func TestPromoteFailureStillDeprovisionsAccount(t *testing.T) {
	var order []string
	win := &fakeWindowsPrimitives{order: &order}
	account := &fakeAccountLifecycle{
		order:      &order,
		promoteErr: errors.New("NetLocalGroupAddMembers: access denied"),
	}
	manager := newLifecycleManager(NewStore(filepath.Join(t.TempDir(), "ledger.json")), win, account, nil)

	result := manager.Apply(context.Background(), validApply(1))

	if result.State != ResultFailed || result.FailureCode != "account_promotion_failed" {
		t.Fatalf("Apply = %s/%s, want failed/account_promotion_failed", result.State, result.FailureCode)
	}
	if account.deprovisionCount != 1 {
		t.Fatalf("Deprovision ran %d times after a failed Promote, want 1; order: %v", account.deprovisionCount, order)
	}
	// Cleanup must follow the promote attempt, never precede it.
	promoteAt, deprovisionAt := indexOf(order, "promote dormant account"), indexOf(order, "rotate password, remove Administrators, disable account")
	if promoteAt < 0 || deprovisionAt < promoteAt {
		t.Fatalf("want promote before deprovision; order: %v", order)
	}
}

func indexOf(items []string, want string) int {
	for i, item := range items {
		if item == want {
			return i
		}
	}
	return -1
}
