package tunnel

import (
	"sync"
	"testing"
	"time"
)

func TestHeavyHostSetMarkAndExpire(t *testing.T) {
	hh := NewHeavyHostSet(50 * time.Millisecond)
	defer hh.Close()

	if hh.IsHeavy("video.example.com") {
		t.Fatal("unmarked host should not be heavy")
	}

	hh.Mark("video.example.com")
	if !hh.IsHeavy("video.example.com") {
		t.Fatal("just-marked host should be heavy")
	}

	// Refresh before expiry — should still be heavy after original TTL.
	time.Sleep(30 * time.Millisecond)
	hh.Mark("video.example.com")
	time.Sleep(30 * time.Millisecond)
	if !hh.IsHeavy("video.example.com") {
		t.Fatal("refreshed mark should keep host heavy")
	}

	// Wait past TTL, no refresh.
	time.Sleep(70 * time.Millisecond)
	if hh.IsHeavy("video.example.com") {
		t.Fatal("expired mark should no longer report heavy")
	}
}

func TestHeavyHostSetEmptyHostNoop(t *testing.T) {
	hh := NewHeavyHostSet(time.Second)
	defer hh.Close()
	hh.Mark("")
	if hh.IsHeavy("") {
		t.Fatal("empty host must never be heavy")
	}
	if got := hh.Snapshot(); len(got) != 0 {
		t.Fatalf("snapshot of empty set: %v", got)
	}
}

func TestHeavyHostSetConcurrent(t *testing.T) {
	hh := NewHeavyHostSet(time.Second)
	defer hh.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				hh.Mark("h1")
				_ = hh.IsHeavy("h1")
			}
		}()
	}
	wg.Wait()
	if !hh.IsHeavy("h1") {
		t.Fatal("h1 should still be heavy after concurrent stress")
	}
}

func TestHostOnly(t *testing.T) {
	cases := map[string]string{
		"example.com:443":     "example.com",
		"video.cdn.com:80":    "video.cdn.com",
		"127.0.0.1:8080":      "127.0.0.1",
		"[::1]:443":           "[::1]",
		"[2001:db8::1]:8443":  "[2001:db8::1]",
		"no-port-here":        "no-port-here",
		"":                    "",
	}
	for in, want := range cases {
		if got := HostOnly(in); got != want {
			t.Errorf("HostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
