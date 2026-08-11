package credential

import (
	"os/exec"
	"testing"
)

func TestItemNotFoundUsesStableExitStatus(t *testing.T) {
	err := exec.Command("/bin/sh", "-c", "exit 44").Run()
	if !isItemNotFound(err) {
		t.Fatalf("exit status 44 was not recognized: %v", err)
	}
	err = exec.Command("/bin/sh", "-c", "exit 1").Run()
	if isItemNotFound(err) {
		t.Fatalf("unrelated exit status was treated as not found: %v", err)
	}
}
