// Package store defines the persistence interfaces and their bbolt-backed
// implementation used by the relay and file listeners.
package store

import (
	"errors"
	"os"
	"time"
)

const (
	// MaxMessagesPerRecipient caps a single recipient queue.
	MaxMessagesPerRecipient = 100
	// MaxNoncesPerIdentity caps replay protection state per identity.
	MaxNoncesPerIdentity = 1024
)

var (
	// ErrQueueFull is returned when a recipient's queue is at capacity.
	ErrQueueFull = errors.New("queue full")
	// ErrNotFound is returned for an unknown file id.
	ErrNotFound = errors.New("not found")
	// ErrNonceReplayed is returned for a nonce that is still live.
	ErrNonceReplayed = errors.New("nonce replayed")
	// ErrNonceStoreFull is returned when replay state is at capacity.
	ErrNonceStoreFull = errors.New("nonce store full")
)

// QueueStore is the text-message queue.
type QueueStore interface {
	Push(recipient string, payload []byte) error
	Pull(recipient string) ([][]byte, error)
	PurgeExpiredMessages(before time.Time) (int, error)
}

// NonceStore is the replay-protection store.
type NonceStore interface {
	Consume(identity, nonce string, expiresAt time.Time) error
	PurgeExpiredNonces(now time.Time) (int, error)
}

// FileMeta is the metadata kept in bbolt for an uploaded file.
type FileMeta struct {
	Size      int64
	CreatedAt time.Time
}

// FileStore manages upload metadata and the file bodies on disk.
type FileStore interface {
	CreateTemp() (*os.File, error)
	Commit(id, tempPath string, size int64, createdAt time.Time) error
	Take(id string) (FileMeta, error)
	Restore(id string, meta FileMeta) error
	Open(id string) (*os.File, error)
	Remove(id string) error
	PurgeExpiredFiles(before time.Time) (int, error)
}
