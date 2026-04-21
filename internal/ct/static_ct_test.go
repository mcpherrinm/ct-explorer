package ct

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseCheckpoint(t *testing.T) {
	body := "log.example.com/2026h1\n" +
		"910258989\n" +
		"/AHht6JkOP0KbcN8BAA3ZBwu2Pyd7INj6vmfMraG1Xc=\n" +
		"\n" +
		"— grease.invalid SWDvLQDV...\n"
	cp, err := parseCheckpoint(body)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Origin != "log.example.com/2026h1" {
		t.Fatalf("origin = %q", cp.Origin)
	}
	if cp.TreeSize != 910258989 {
		t.Fatalf("tree size = %d", cp.TreeSize)
	}
	if len(cp.RootHash) != 32 {
		t.Fatalf("root hash length = %d", len(cp.RootHash))
	}
	if cp.Raw != body {
		t.Fatalf("raw body did not round-trip")
	}
}

func TestParseCheckpointRejectsMissingBlank(t *testing.T) {
	if _, err := parseCheckpoint("origin\n1\nAAAA"); err == nil {
		t.Fatalf("expected error for missing blank line")
	}
}

func TestExtractLeafIndex(t *testing.T) {
	// leaf_index extension with value 1 << 32 | 2 = 0x100000002 (5 bytes big-endian).
	ext := []byte{0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x02}
	idx, ok := ExtractLeafIndex(ext)
	if !ok {
		t.Fatalf("extension not found")
	}
	if idx != (uint64(1)<<32)|2 {
		t.Fatalf("leaf index = %d", idx)
	}
}

func TestExtractLeafIndexMissing(t *testing.T) {
	if _, ok := ExtractLeafIndex(nil); ok {
		t.Fatalf("empty extensions should not match")
	}
	// Some other extension type is present but no leaf_index.
	other := []byte{0x07, 0x00, 0x02, 0xaa, 0xbb}
	if _, ok := ExtractLeafIndex(other); ok {
		t.Fatalf("non-leaf-index extension should not match")
	}
}

func TestTilePath(t *testing.T) {
	cases := []struct {
		level uint
		idx   uint64
		width uint
		want  string
	}{
		{0, 0, 256, "tile/0/000"},
		{0, 0, 0, "tile/0/000"},
		{0, 1, 256, "tile/0/001"},
		{1, 42, 17, "tile/1/042.p/17"},
		{0, 1234067, 256, "tile/0/x001/x234/067"},
		{0, 1234067, 15, "tile/0/x001/x234/067.p/15"},
		{0, 3555699, 45, "tile/0/x003/x555/699.p/45"},
	}
	for _, c := range cases {
		got := TilePath(c.level, c.idx, c.width)
		if got != c.want {
			t.Errorf("TilePath(%d, %d, %d) = %q, want %q", c.level, c.idx, c.width, got, c.want)
		}
	}
}

func TestDataTilePath(t *testing.T) {
	if got := DataTilePath(1234067, 15); got != "tile/data/x001/x234/067.p/15" {
		t.Fatalf("DataTilePath = %q", got)
	}
}

func TestTileWidth(t *testing.T) {
	cases := []struct {
		level uint
		idx   uint64
		size  uint64
		want  uint
	}{
		// tree size 70000: 273 full L0 tiles + partial L0 width 112
		// one full L1 tile + partial L1 width 17, partial L2 width 1.
		{0, 0, 70000, 256},
		{0, 272, 70000, 256},
		{0, 273, 70000, 112},
		{0, 274, 70000, 0},
		{1, 0, 70000, 256},
		{1, 1, 70000, 17},
		{1, 2, 70000, 0},
		{2, 0, 70000, 1},
		{2, 1, 70000, 0},
		// tree size 256: full L0 + partial L1 of width 1
		{0, 0, 256, 256},
		{1, 0, 256, 1},
	}
	for _, c := range cases {
		got := TileWidth(c.level, c.idx, c.size)
		if got != c.want {
			t.Errorf("TileWidth(%d, %d, size %d) = %d, want %d", c.level, c.idx, c.size, got, c.want)
		}
	}
}

func TestMTHOfHashes(t *testing.T) {
	h0 := leafHash([]byte("a"))
	h1 := leafHash([]byte("b"))
	h2 := leafHash([]byte("c"))
	got := mthOfHashes([][]byte{h0, h1, h2})
	// RFC 6962: MTH of 3 = HASH(0x01 || MTH(0..2) || h2) where MTH(0..2) = HASH(0x01 || h0 || h1)
	want := merkleParent(merkleParent(h0, h1), h2)
	if !bytes.Equal(got, want) {
		t.Fatalf("mthOfHashes mismatch")
	}
}

// TestBuildAuditPathAgainstInMemoryTree generates a Merkle tree of random-ish
// leaves, slices it into Static CT tiles, and verifies BuildAuditPath produces
// an audit path that VerifyAuditPath accepts.
func TestBuildAuditPathAgainstInMemoryTree(t *testing.T) {
	sizes := []uint64{1, 2, 3, 5, 7, 100, 256, 257, 511, 512, 1023, 1024, 70000}
	for _, s := range sizes {
		t.Run(fmt.Sprintf("size=%d", s), func(t *testing.T) {
			leaves := make([][]byte, s)
			for i := range leaves {
				leaves[i] = leafHash([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
			}
			root := mthOfHashes(leaves)
			rootB64 := base64.StdEncoding.EncodeToString(root)

			server := newTileTestServer(t, leaves)
			defer server.Close()

			// Pick a handful of indexes including edges.
			idxs := []uint64{0, s / 2, s - 1}
			if s > 3 {
				idxs = append(idxs, s/3)
			}
			for _, i := range idxs {
				cache := NewTileCache(server.Client(), server.URL)
				path, err := BuildAuditPath(context.Background(), cache, i, s)
				if err != nil {
					t.Fatalf("i=%d: %v", i, err)
				}
				b64Path := make([]string, len(path))
				for k, h := range path {
					b64Path[k] = base64.StdEncoding.EncodeToString(h)
				}
				ok, _ := VerifyAuditPath(leaves[i], b64Path, i, s, rootB64)
				if !ok {
					t.Fatalf("i=%d: audit path did not verify", i)
				}
			}
		})
	}
}

// newTileTestServer serves Static CT tiles for a tree whose leaves are the given
// pre-hashed leaf hashes. It handles tile levels 0..5 and partial tiles.
func newTileTestServer(t *testing.T, leaves [][]byte) *httptest.Server {
	t.Helper()
	s := uint64(len(leaves))
	// Pre-compute tile contents for each level.
	levels := make(map[uint][][]byte) // flat hashes at this tile level in order.
	levels[0] = leaves
	// At level l > 0, entry i = MTH of the level-(l-1) tile at index i (full 256 subtree rooted).
	// In our flat representation: at Merkle level 8*l, subtree index i covers leaves
	// [i * 256^l, (i+1) * 256^l) clipped. We compute MTH of that slice of leaves recursively.
	for l := uint(1); l <= 5; l++ {
		base := uint64(1)
		for k := uint(0); k < l; k++ {
			base *= 256
		}
		if base >= s {
			break
		}
		count := (s + base - 1) / base
		flat := make([][]byte, 0, count)
		for i := uint64(0); i < count; i++ {
			start := i * base
			end := start + base
			if end > s {
				end = s
			}
			flat = append(flat, mthOfHashes(leaves[start:end]))
		}
		levels[l] = flat
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse "/tile/<L>/..." URL.
		path := strings.TrimPrefix(r.URL.Path, "/tile/")
		var levelStr, rest string
		slash := strings.IndexByte(path, '/')
		if slash < 0 {
			http.NotFound(w, r)
			return
		}
		levelStr = path[:slash]
		rest = path[slash+1:]
		if levelStr == "data" {
			http.NotFound(w, r)
			return
		}
		var level uint
		switch levelStr {
		case "0":
			level = 0
		case "1":
			level = 1
		case "2":
			level = 2
		case "3":
			level = 3
		case "4":
			level = 4
		case "5":
			level = 5
		default:
			http.NotFound(w, r)
			return
		}
		// Parse index (3-digit path components) and optional .p/<W>.
		var width uint = 256
		if pIdx := strings.Index(rest, ".p/"); pIdx >= 0 {
			ws := rest[pIdx+3:]
			rest = rest[:pIdx]
			var parsed uint
			for _, c := range ws {
				if c < '0' || c > '9' {
					http.NotFound(w, r)
					return
				}
				parsed = parsed*10 + uint(c-'0')
			}
			width = parsed
		}
		parts := strings.Split(rest, "/")
		var idx uint64
		for _, p := range parts {
			p = strings.TrimPrefix(p, "x")
			if len(p) != 3 {
				http.NotFound(w, r)
				return
			}
			for _, c := range p {
				if c < '0' || c > '9' {
					http.NotFound(w, r)
					return
				}
				idx = idx*10 + uint64(c-'0')
			}
		}
		expected := TileWidth(level, idx, s)
		if expected == 0 {
			http.NotFound(w, r)
			return
		}
		// Served width:
		served := width
		if served >= 256 {
			served = 256
		}
		if served != expected {
			// Only serve the exact expected width (full or partial).
			http.NotFound(w, r)
			return
		}
		flat, ok := levels[level]
		if !ok {
			http.NotFound(w, r)
			return
		}
		start := int(idx) * 256
		end := start + int(expected)
		if start >= len(flat) {
			http.NotFound(w, r)
			return
		}
		if end > len(flat) {
			end = len(flat)
		}
		body := make([]byte, 0, (end-start)*32)
		for _, h := range flat[start:end] {
			body = append(body, h...)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(body)
	}))
	return server
}

