package api

import "sync"

// Notifier wakes up long-polling pulls when a packet is queued for a
// recipient. Channels are created lazily and removed when the last waiter
// leaves, so idle recipients do not leak memory.
type Notifier struct {
	mu      sync.Mutex
	buckets map[string]*notifyBucket
}

type notifyBucket struct {
	ch      chan struct{}
	waiters int
}

// NewNotifier returns an empty registry.
func NewNotifier() *Notifier {
	return &Notifier{buckets: make(map[string]*notifyBucket)}
}

// Subscribe registers interest in a recipient. The returned cancel function
// must be called when the waiter stops waiting.
func (n *Notifier) Subscribe(recipient string) (<-chan struct{}, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()

	bucket, ok := n.buckets[recipient]
	if !ok {
		bucket = &notifyBucket{ch: make(chan struct{}, 1)}
		n.buckets[recipient] = bucket
	}
	bucket.waiters++

	cancel := func() {
		n.mu.Lock()
		defer n.mu.Unlock()

		bucket.waiters--
		if bucket.waiters <= 0 {
			if current, ok := n.buckets[recipient]; ok && current == bucket {
				delete(n.buckets, recipient)
			}
		}
	}
	return bucket.ch, cancel
}

// Notify performs a non-blocking wake-up signal for a recipient.
func (n *Notifier) Notify(recipient string) {
	n.mu.Lock()
	bucket, ok := n.buckets[recipient]
	n.mu.Unlock()
	if !ok {
		return
	}

	select {
	case bucket.ch <- struct{}{}:
	default:
		// A signal is already pending; waiters re-check the queue anyway.
	}
}

// Waiters reports how many pull requests currently wait on a recipient.
func (n *Notifier) Waiters(recipient string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if bucket, ok := n.buckets[recipient]; ok {
		return bucket.waiters
	}
	return 0
}
