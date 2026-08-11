package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
)

var ErrNotFound = errors.New("credential not found in macOS Keychain")

type Store struct {
	service string
	label   string
}

func New(router string) *Store {
	sum := sha256.Sum256([]byte(router))
	id := hex.EncodeToString(sum[:8])
	return &Store{
		service: "io.github.ijemin.iptime-cli." + id,
		label:   "iptime-cli router credential",
	}
}

func ensureDarwin() error {
	if runtime.GOOS != "darwin" {
		return errors.New("macOS Keychain support requires macOS")
	}
	return nil
}

func (s *Store) Get(account string) (string, error) {
	if err := ensureDarwin(); err != nil {
		return "", err
	}
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-a", account, "-s", s.service, "-w")
	out, err := cmd.Output()
	if err != nil {
		if isItemNotFound(err) {
			return "", ErrNotFound
		}
		return "", errors.New("read macOS Keychain failed")
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

// SetInteractive lets the macOS security tool prompt for the password. The
// password is never placed in this process's arguments or environment.
func (s *Store) SetInteractive(account string, stdin io.Reader, stdout, stderr io.Writer) error {
	if err := ensureDarwin(); err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/security", "add-generic-password", "-U", "-a", account, "-s", s.service, "-l", s.label, "-w")
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("store credential in macOS Keychain: %w", err)
	}
	return nil
}

func (s *Store) Delete(account string) error {
	if err := ensureDarwin(); err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-a", account, "-s", s.service)
	if err := cmd.Run(); err != nil {
		if isItemNotFound(err) {
			return ErrNotFound
		}
		return errors.New("delete macOS Keychain credential failed")
	}
	return nil
}

func (s *Store) Exists(account string) (bool, error) {
	if err := ensureDarwin(); err != nil {
		return false, err
	}
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-a", account, "-s", s.service)
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if isItemNotFound(err) {
		return false, nil
	}
	return false, errors.New("check macOS Keychain credential failed")
}

// macOS security(1) returns the low byte of errSecItemNotFound (-25300), 44.
func isItemNotFound(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 44
}
