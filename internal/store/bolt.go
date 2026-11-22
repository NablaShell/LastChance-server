package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	queuesBucket = []byte("queues")
	noncesBucket = []byte("nonces")
	filesBucket  = []byte("files_meta")
)

// Store is a bbolt-backed implementation of QueueStore, NonceStore and
// FileStore. bbolt serialises write transactions, which gives atomic Pull and
// Take without additional locking.
type Store struct {
	db      *bolt.DB
	fileDir string
}

// Open creates the database, buckets and file directory, then removes leftover
// temp uploads and orphaned file bodies from a previous run.
func Open(dbPath, fileDir string) (*Store, error) {
	dbPath = strings.TrimSpace(dbPath)
	fileDir = strings.TrimSpace(fileDir)
	if dbPath == "" || fileDir == "" {
		return nil, errors.New("store: db path and file directory are required")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	if err := os.MkdirAll(fileDir, 0o700); err != nil {
		return nil, fmt.Errorf("create file directory: %w", err)
	}

	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt database: %w", err)
	}

	st := &Store{db: db, fileDir: fileDir}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{queuesBucket, noncesBucket, filesBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := st.cleanupFiles(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return st, nil
}

// Close closes the underlying bbolt database.
func (s *Store) Close() error {
	return s.db.Close()
}

// --- QueueStore ---

// Push appends one payload to a recipient's queue. The queue is capped at
// MaxMessagesPerRecipient.
func (s *Store) Push(recipient string, payload []byte) error {
	if strings.TrimSpace(recipient) == "" {
		return errors.New("store: recipient is required")
	}
	prefix := queuePrefix(recipient)

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(queuesBucket)
		count := 0
		cursor := bucket.Cursor()
		for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
			count++
		}
		if count >= MaxMessagesPerRecipient {
			return ErrQueueFull
		}

		sequence, err := bucket.NextSequence()
		if err != nil {
			return fmt.Errorf("allocate queue sequence: %w", err)
		}
		value := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint64(value[:8], uint64(time.Now().Unix()))
		copy(value[8:], payload)
		return bucket.Put(queueKey(recipient, sequence), value)
	})
}

// Pull atomically removes and returns every queued payload for a recipient.
func (s *Store) Pull(recipient string) ([][]byte, error) {
	if strings.TrimSpace(recipient) == "" {
		return nil, errors.New("store: recipient is required")
	}
	prefix := queuePrefix(recipient)
	var payloads [][]byte
	var keys [][]byte

	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(queuesBucket)
		cursor := bucket.Cursor()
		for key, value := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, value = cursor.Next() {
			if len(value) < 8 {
				return fmt.Errorf("corrupt queue value for %q", recipient)
			}
			payload := make([]byte, len(value)-8)
			copy(payload, value[8:])
			payloads = append(payloads, payload)

			keyCopy := make([]byte, len(key))
			copy(keyCopy, key)
			keys = append(keys, keyCopy)
		}
		for _, key := range keys {
			if err := bucket.Delete(key); err != nil {
				return fmt.Errorf("delete queued payload: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return payloads, nil
}

// PurgeExpiredMessages deletes queued messages created before the cutoff.
func (s *Store) PurgeExpiredMessages(before time.Time) (int, error) {
	cutoff := before.Unix()
	removed := 0

	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(queuesBucket)
		cursor := bucket.Cursor()
		var keys [][]byte
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			if len(value) < 8 {
				continue
			}
			created := int64(binary.BigEndian.Uint64(value[:8]))
			if created < cutoff {
				keyCopy := make([]byte, len(key))
				copy(keyCopy, key)
				keys = append(keys, keyCopy)
			}
		}
		for _, key := range keys {
			if err := bucket.Delete(key); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// --- NonceStore ---

// Consume records a nonce exactly once per identity. Expired entries are
// pruned lazily; a full identity cache fails closed instead of evicting a live
// nonce.
func (s *Store) Consume(identity, nonce string, expiresAt time.Time) error {
	if strings.TrimSpace(identity) == "" || nonce == "" {
		return errors.New("store: identity and nonce are required")
	}
	prefix := append([]byte(identity), 0)
	key := nonceKey(identity, nonce)
	now := time.Now().Unix()
	expiry := expiresAt.Unix()

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(noncesBucket)
		cursor := bucket.Cursor()
		count := 0
		var expired [][]byte

		for current, value := cursor.Seek(prefix); current != nil && bytes.HasPrefix(current, prefix); current, value = cursor.Next() {
			if len(value) < 8 {
				continue
			}
			if int64(binary.BigEndian.Uint64(value)) <= now {
				keyCopy := make([]byte, len(current))
				copy(keyCopy, current)
				expired = append(expired, keyCopy)
				continue
			}
			if bytes.Equal(current, key) {
				return ErrNonceReplayed
			}
			count++
		}
		for _, expiredKey := range expired {
			if err := bucket.Delete(expiredKey); err != nil {
				return err
			}
		}
		if count >= MaxNoncesPerIdentity {
			return ErrNonceStoreFull
		}

		value := make([]byte, 8)
		binary.BigEndian.PutUint64(value, uint64(expiry))
		return bucket.Put(key, value)
	})
}

// PurgeExpiredNonces deletes nonce entries whose expiry is at or before now.
func (s *Store) PurgeExpiredNonces(now time.Time) (int, error) {
	cutoff := now.Unix()
	removed := 0

	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(noncesBucket)
		cursor := bucket.Cursor()
		var keys [][]byte
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			if len(value) < 8 {
				continue
			}
			if int64(binary.BigEndian.Uint64(value)) <= cutoff {
				keyCopy := make([]byte, len(key))
				copy(keyCopy, key)
				keys = append(keys, keyCopy)
			}
		}
		for _, key := range keys {
			if err := bucket.Delete(key); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

// --- FileStore ---

// CreateTemp creates a private temp file inside the file directory.
func (s *Store) CreateTemp() (*os.File, error) {
	return os.CreateTemp(s.fileDir, ".upload-*")
}

// Commit moves an authenticated temp upload into place and records its
// metadata.
func (s *Store) Commit(id, tempPath string, size int64, createdAt time.Time) error {
	if !ValidFileID(id) {
		return fmt.Errorf("store: invalid file id %q", id)
	}
	finalPath := filepath.Join(s.fileDir, id)
	if err := os.Rename(tempPath, finalPath); err != nil {
		return fmt.Errorf("commit upload: %w", err)
	}
	if err := os.Chmod(finalPath, 0o600); err != nil {
		_ = os.Remove(finalPath)
		return fmt.Errorf("chmod upload: %w", err)
	}

	value, err := json.Marshal(fileMetaValue{Size: size, CreatedAt: createdAt.Unix()})
	if err != nil {
		_ = os.Remove(finalPath)
		return fmt.Errorf("encode file metadata: %w", err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(filesBucket).Put([]byte(id), value)
	}); err != nil {
		_ = os.Remove(finalPath)
		return fmt.Errorf("store file metadata: %w", err)
	}
	return nil
}

// Take atomically removes and returns a file's metadata.
func (s *Store) Take(id string) (FileMeta, error) {
	if !ValidFileID(id) {
		return FileMeta{}, ErrNotFound
	}
	var meta FileMeta
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(filesBucket)
		value := bucket.Get([]byte(id))
		if value == nil {
			return ErrNotFound
		}
		decoded, err := decodeFileMeta(value)
		if err != nil {
			return err
		}
		meta = decoded
		return bucket.Delete([]byte(id))
	})
	if err != nil {
		return FileMeta{}, err
	}
	return meta, nil
}

// Restore puts metadata back after a download failed before any bytes were
// sent.
func (s *Store) Restore(id string, meta FileMeta) error {
	if !ValidFileID(id) {
		return fmt.Errorf("store: invalid file id %q", id)
	}
	value, err := json.Marshal(fileMetaValue{Size: meta.Size, CreatedAt: meta.CreatedAt.Unix()})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(filesBucket)
		if bucket.Get([]byte(id)) != nil {
			return nil
		}
		return bucket.Put([]byte(id), value)
	})
}

// Open opens the file body for reading.
func (s *Store) Open(id string) (*os.File, error) {
	if !ValidFileID(id) {
		return nil, ErrNotFound
	}
	file, err := os.Open(filepath.Join(s.fileDir, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return file, err
}

// Remove unlinks a file body. Missing files are not an error.
func (s *Store) Remove(id string) error {
	if !ValidFileID(id) {
		return ErrNotFound
	}
	err := os.Remove(filepath.Join(s.fileDir, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// PurgeExpiredFiles deletes metadata and bodies created before the cutoff.
func (s *Store) PurgeExpiredFiles(before time.Time) (int, error) {
	cutoff := before.Unix()
	var ids [][]byte

	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(filesBucket)
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			meta, err := decodeFileMeta(value)
			if err != nil {
				continue
			}
			if meta.CreatedAt.Unix() < cutoff {
				keyCopy := make([]byte, len(key))
				copy(keyCopy, key)
				ids = append(ids, keyCopy)
			}
		}
		for _, id := range ids {
			if err := bucket.Delete(id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	for _, id := range ids {
		_ = s.Remove(string(id))
	}
	return len(ids), nil
}

// ValidFileID reports whether id is a lowercase hex SHA-256 (64 characters).
func ValidFileID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
			continue
		}
		return false
	}
	return true
}

func (s *Store) cleanupFiles() error {
	entries, err := os.ReadDir(s.fileDir)
	if err != nil {
		return fmt.Errorf("read file directory: %w", err)
	}

	known := make(map[string]struct{})
	if err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(filesBucket).ForEach(func(key, _ []byte) error {
			known[string(key)] = struct{}{}
			return nil
		})
	}); err != nil {
		return fmt.Errorf("list file metadata: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".upload-") {
			_ = os.Remove(filepath.Join(s.fileDir, name))
			continue
		}
		if ValidFileID(name) {
			if _, ok := known[name]; !ok {
				_ = os.Remove(filepath.Join(s.fileDir, name))
			}
		}
	}
	return nil
}

type fileMetaValue struct {
	Size      int64 `json:"size"`
	CreatedAt int64 `json:"created_at"`
}

func decodeFileMeta(value []byte) (FileMeta, error) {
	var raw fileMetaValue
	if err := json.Unmarshal(value, &raw); err != nil {
		return FileMeta{}, fmt.Errorf("decode file metadata: %w", err)
	}
	return FileMeta{Size: raw.Size, CreatedAt: time.Unix(raw.CreatedAt, 0).UTC()}, nil
}

func queuePrefix(recipient string) []byte {
	prefix := make([]byte, len(recipient)+1)
	copy(prefix, recipient)
	return prefix
}

func queueKey(recipient string, sequence uint64) []byte {
	key := make([]byte, len(recipient)+1+8)
	copy(key, recipient)
	binary.BigEndian.PutUint64(key[len(recipient)+1:], sequence)
	return key
}

func nonceKey(identity, nonce string) []byte {
	key := make([]byte, len(identity)+1+len(nonce))
	copy(key, identity)
	copy(key[len(identity)+1:], nonce)
	return key
}
