package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	root := t.TempDir()
	st, err := Open(filepath.Join(root, "lc.db"), filepath.Join(root, "files"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return st
}

func TestQueuePushPullIsAtomic(t *testing.T) {
	st := newTestStore(t)
	payloads := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	for _, payload := range payloads {
		if err := st.Push("recipient", payload); err != nil {
			t.Fatalf("Push: %v", err)
		}
	}

	got, err := st.Pull("recipient")
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(got) != len(payloads) {
		t.Fatalf("pulled %d payloads, want %d", len(got), len(payloads))
	}
	for i := range payloads {
		if !bytes.Equal(got[i], payloads[i]) {
			t.Fatalf("payload %d = %q, want %q", i, got[i], payloads[i])
		}
	}

	again, err := st.Pull("recipient")
	if err != nil {
		t.Fatalf("second Pull: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second Pull returned %d payloads, want 0", len(again))
	}
}

func TestQueueLimit(t *testing.T) {
	st := newTestStore(t)
	for i := 0; i < MaxMessagesPerRecipient; i++ {
		if err := st.Push("full", []byte("x")); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}
	if err := st.Push("full", []byte("overflow")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("overflow Push = %v, want ErrQueueFull", err)
	}
	if err := st.Push("other", []byte("x")); err != nil {
		t.Fatalf("other recipient should be unaffected: %v", err)
	}
}

func TestQueueTTLGC(t *testing.T) {
	st := newTestStore(t)
	if err := st.Push("expiring", []byte("payload")); err != nil {
		t.Fatalf("Push: %v", err)
	}
	removed, err := st.PurgeExpiredMessages(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("PurgeExpiredMessages: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d messages, want 1", removed)
	}
	got, err := st.Pull("expiring")
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expired message survived: %d", len(got))
	}
}

func TestNonceReplayAndIdentityScope(t *testing.T) {
	st := newTestStore(t)
	expiry := time.Now().Add(time.Minute)
	if err := st.Consume("identity-a", "nonce", expiry); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if err := st.Consume("identity-a", "nonce", expiry); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("replay = %v, want ErrNonceReplayed", err)
	}
	if err := st.Consume("identity-b", "nonce", expiry); err != nil {
		t.Fatalf("same nonce for another identity should be accepted: %v", err)
	}
}

func TestNonceStoreFailsClosedAndPurges(t *testing.T) {
	st := newTestStore(t)
	expiry := time.Now().Add(time.Hour)
	for i := 0; i < MaxNoncesPerIdentity; i++ {
		nonce := fmt.Sprintf("nonce-%d", i)
		if err := st.Consume("identity", nonce, expiry); err != nil {
			t.Fatalf("Consume %d: %v", i, err)
		}
	}
	if err := st.Consume("identity", "one-too-many", expiry); !errors.Is(err, ErrNonceStoreFull) {
		t.Fatalf("overflow = %v, want ErrNonceStoreFull", err)
	}

	removed, err := st.PurgeExpiredNonces(time.Now().Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("PurgeExpiredNonces: %v", err)
	}
	if removed != MaxNoncesPerIdentity {
		t.Fatalf("removed %d nonces, want %d", removed, MaxNoncesPerIdentity)
	}
}

func TestFileLifecycle(t *testing.T) {
	st := newTestStore(t)
	data := []byte("file contents")
	sum := sha256.Sum256(data)
	id := hex.EncodeToString(sum[:])

	temp, err := st.CreateTemp()
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tempPath := temp.Name()
	if _, err := temp.Write(data); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := temp.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}
	if err := st.Commit(id, tempPath, int64(len(data)), time.Now().UTC()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	meta, err := st.Take(id)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if meta.Size != int64(len(data)) {
		t.Fatalf("meta size = %d", meta.Size)
	}

	file, err := st.Open(id)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	read, err := os.ReadFile(file.Name())
	file.Close()
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Equal(read, data) {
		t.Fatalf("file contents = %q", read)
	}

	if err := st.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := st.Open(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open after Remove = %v, want ErrNotFound", err)
	}
}

func TestFileTTLGC(t *testing.T) {
	st := newTestStore(t)
	data := []byte("expiring")
	sum := sha256.Sum256(data)
	id := hex.EncodeToString(sum[:])

	temp, err := st.CreateTemp()
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := temp.Write(data); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := temp.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}
	if err := st.Commit(id, temp.Name(), int64(len(data)), time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	removed, err := st.PurgeExpiredFiles(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("PurgeExpiredFiles: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d files, want 1", removed)
	}
	if _, err := st.Open(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired file still openable: %v", err)
	}
}

func TestFileIDValidation(t *testing.T) {
	valid := make([]byte, 32)
	for i := range valid {
		valid[i] = byte(i)
	}
	if !ValidFileID(hex.EncodeToString(valid)) {
		t.Fatal("valid lowercase hex id rejected")
	}
	for _, id := range []string{"", "abc", "A" + hex.EncodeToString(valid)[1:], "../etc/passwd"} {
		if ValidFileID(id) {
			t.Fatalf("invalid id accepted: %q", id)
		}
	}
}

func TestConcurrentPushAndPull(t *testing.T) {
	st := newTestStore(t)
	const workers = 40

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := st.Push("shared", []byte("payload")); err != nil {
				t.Errorf("Push: %v", err)
			}
		}()
	}
	wg.Wait()

	var pulled atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payloads, err := st.Pull("shared")
			if err != nil {
				t.Errorf("Pull: %v", err)
				return
			}
			pulled.Add(int64(len(payloads)))
		}()
	}
	wg.Wait()

	if got := int(pulled.Load()); got != workers {
		t.Fatalf("pulled %d payloads, want %d", got, workers)
	}
}

func TestStartupRemovesOrphansAndTempFiles(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "lc.db")
	fileDir := filepath.Join(root, "files")
	if err := os.MkdirAll(fileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(fileDir, hex.EncodeToString(make([]byte, 32)))
	temp := filepath.Join(fileDir, ".upload-123")
	for _, path := range []string{orphan, temp} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	st, err := Open(dbPath, fileDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	for _, path := range []string{orphan, temp} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was not removed", filepath.Base(path))
		}
	}
}
