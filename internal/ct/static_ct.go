package ct

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Checkpoint is a parsed Static CT API signed tree head.
type Checkpoint struct {
	Origin   string
	TreeSize uint64
	RootHash []byte
	Raw      string
	URL      string
}

// FetchCheckpoint fetches and parses <monitoringURL>/checkpoint.
func FetchCheckpoint(ctx context.Context, client *http.Client, monitoringURL string) (*Checkpoint, error) {
	u := strings.TrimRight(monitoringURL, "/") + "/checkpoint"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("checkpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	cp, err := parseCheckpoint(string(body))
	if err != nil {
		return nil, err
	}
	cp.URL = u
	return cp, nil
}

func parseCheckpoint(body string) (*Checkpoint, error) {
	idx := strings.Index(body, "\n\n")
	if idx < 0 {
		return nil, errors.New("checkpoint missing blank line separator")
	}
	head := body[:idx]
	lines := strings.Split(head, "\n")
	if len(lines) < 3 {
		return nil, errors.New("checkpoint must have origin, size, and root hash lines")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid checkpoint size %q: %w", lines[1], err)
	}
	rootHash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("invalid checkpoint root hash: %w", err)
	}
	if len(rootHash) != 32 {
		return nil, fmt.Errorf("checkpoint root hash length %d, want 32", len(rootHash))
	}
	return &Checkpoint{
		Origin:   lines[0],
		TreeSize: size,
		RootHash: rootHash,
		Raw:      body,
	}, nil
}

// ExtractLeafIndex decodes a Static CT API leaf_index (extension type 0)
// from the raw CtExtensions bytes of an SCT.
func ExtractLeafIndex(extensions []byte) (uint64, bool) {
	data := extensions
	for len(data) >= 3 {
		extType := data[0]
		extLen := int(binary.BigEndian.Uint16(data[1:3]))
		if 3+extLen > len(data) {
			return 0, false
		}
		extData := data[3 : 3+extLen]
		if extType == 0 { // leaf_index
			if len(extData) != 5 {
				return 0, false
			}
			var idx uint64
			for _, b := range extData {
				idx = (idx << 8) | uint64(b)
			}
			return idx, true
		}
		data = data[3+extLen:]
	}
	return 0, false
}

// TilePath encodes the path of a Merkle tile at the given level/index.
// A width of 256 (or 0) means a full tile with no ".p/<W>" suffix.
func TilePath(level uint, index uint64, width uint) string {
	return "tile/" + strconv.FormatUint(uint64(level), 10) + "/" + encodeTileIndex(index) + partialSuffix(width)
}

// DataTilePath encodes the data-tile path.
func DataTilePath(index uint64, width uint) string {
	return "tile/data/" + encodeTileIndex(index) + partialSuffix(width)
}

func encodeTileIndex(index uint64) string {
	if index == 0 {
		return "000"
	}
	var chunks []string
	for n := index; n > 0; n /= 1000 {
		chunks = append([]string{fmt.Sprintf("%03d", n%1000)}, chunks...)
	}
	for i := 0; i < len(chunks)-1; i++ {
		chunks[i] = "x" + chunks[i]
	}
	return strings.Join(chunks, "/")
}

func partialSuffix(width uint) string {
	if width == 0 || width >= 256 {
		return ""
	}
	return ".p/" + strconv.FormatUint(uint64(width), 10)
}

// TileWidth returns the width of tile (level, index) for a tree of the given
// size. 256 means the tile is full. 1..255 means the tile is partial. 0 means
// the tile does not exist in this tree.
func TileWidth(level uint, index uint64, treeSize uint64) uint {
	base := uint64(1)
	for i := uint(0); i < level; i++ {
		// Avoid overflow: levels are 0..5 in practice, so base stays small.
		base *= 256
	}
	if base == 0 {
		return 0
	}
	entries := treeSize / base
	fullTiles := entries / 256
	if index < fullTiles {
		return 256
	}
	if index == fullTiles {
		if w := uint(entries % 256); w > 0 {
			return w
		}
	}
	return 0
}

// TileCache fetches and caches static CT tiles for a single checkpoint.
type TileCache struct {
	client  *http.Client
	monitor string

	mu    sync.Mutex
	tiles map[string][][]byte
	order []string
}

// NewTileCache returns a cache that fetches tiles from the given monitoring URL.
func NewTileCache(client *http.Client, monitoringURL string) *TileCache {
	return &TileCache{
		client:  client,
		monitor: strings.TrimRight(monitoringURL, "/"),
		tiles:   make(map[string][][]byte),
	}
}

// Tile fetches and returns the (level, index) tile, falling back from a
// partial width to a full tile if the partial is unavailable.
func (c *TileCache) Tile(ctx context.Context, level uint, index uint64, treeSize uint64) ([][]byte, error) {
	key := fmt.Sprintf("%d/%d", level, index)
	c.mu.Lock()
	if h, ok := c.tiles[key]; ok {
		c.mu.Unlock()
		return h, nil
	}
	c.mu.Unlock()

	width := TileWidth(level, index, treeSize)
	if width == 0 {
		return nil, fmt.Errorf("tile level %d index %d does not exist in tree size %d", level, index, treeSize)
	}

	candidates := make([]string, 0, 2)
	if width < 256 {
		candidates = append(candidates, c.monitor+"/"+TilePath(level, index, width))
		candidates = append(candidates, c.monitor+"/"+TilePath(level, index, 256))
	} else {
		candidates = append(candidates, c.monitor+"/"+TilePath(level, index, 256))
	}

	var lastErr error
	for _, u := range candidates {
		data, err := fetchBytes(ctx, c.client, u)
		if err != nil {
			lastErr = err
			continue
		}
		if len(data) == 0 || len(data)%32 != 0 {
			lastErr = fmt.Errorf("tile body length %d not a multiple of 32", len(data))
			continue
		}
		hashes := make([][]byte, 0, len(data)/32)
		for off := 0; off < len(data); off += 32 {
			buf := make([]byte, 32)
			copy(buf, data[off:off+32])
			hashes = append(hashes, buf)
		}
		c.mu.Lock()
		c.tiles[key] = hashes
		c.order = append(c.order, u)
		c.mu.Unlock()
		return hashes, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no tile URL candidates fetched")
	}
	return nil, lastErr
}

// URLs returns the tile URLs fetched so far, in fetch order.
func (c *TileCache) URLs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.order))
	copy(out, c.order)
	return out
}

// SubtreeHash returns the RFC 6962 MTH of the subtree at Merkle tree level L,
// subtree index sibIdx, clipped to the given tree size. It uses and caches
// the relevant tile from the log.
func (c *TileCache) SubtreeHash(ctx context.Context, L uint, sibIdx uint64, treeSize uint64) ([]byte, error) {
	start := sibIdx << L
	if start >= treeSize {
		return nil, fmt.Errorf("subtree start %d beyond tree size %d", start, treeSize)
	}
	size := uint64(1) << L
	if start+size > treeSize {
		size = treeSize - start
	}
	return c.rangeMTH(ctx, start, size, treeSize)
}

// rangeMTH returns the RFC 6962 MTH of leaves [start, start+size) in a tree
// of the given size. When size is a power of two and the range is aligned,
// it tries to read directly from a higher-level tile. Otherwise it splits
// on the RFC 6962 largest-power-of-two boundary and recurses.
func (c *TileCache) rangeMTH(ctx context.Context, start, size, treeSize uint64) ([]byte, error) {
	if size == 0 {
		return nil, errors.New("empty range has no MTH")
	}
	if isPowerOf2(size) && start%size == 0 {
		L := log2Pow2(size)
		if L <= 5*8 {
			tileLevel := L / 8
			inTileLevel := L % 8
			sib := start >> L
			tileIdx := sib >> (8 - inTileLevel)
			startPos := uint((sib << inTileLevel) & 0xff)
			count := uint(1) << inTileLevel
			tile, err := c.Tile(ctx, tileLevel, tileIdx, treeSize)
			if err == nil && int(startPos)+int(count) <= len(tile) {
				slice := tile[startPos : startPos+count]
				if len(slice) == 1 {
					out := make([]byte, len(slice[0]))
					copy(out, slice[0])
					return out, nil
				}
				return mthOfHashes(slice), nil
			}
			if err != nil && size > 1 {
				// Fall through: split into smaller ranges and try lower tiles.
			} else if err != nil {
				return nil, err
			}
		}
	}
	if size == 1 {
		return nil, fmt.Errorf("could not locate leaf at index %d", start)
	}
	k := largestPow2BelowU(size)
	left, err := c.rangeMTH(ctx, start, k, treeSize)
	if err != nil {
		return nil, err
	}
	right, err := c.rangeMTH(ctx, start+k, size-k, treeSize)
	if err != nil {
		return nil, err
	}
	return merkleParent(left, right), nil
}

func isPowerOf2(n uint64) bool {
	return n > 0 && (n&(n-1)) == 0
}

// log2Pow2 returns the exponent e such that 2^e == n. Caller must ensure n is a power of two.
func log2Pow2(n uint64) uint {
	e := uint(0)
	for n > 1 {
		n >>= 1
		e++
	}
	return e
}

// largestPow2BelowU returns the largest power of two strictly less than n, for n >= 2.
func largestPow2BelowU(n uint64) uint64 {
	k := uint64(1)
	for k*2 < n {
		k *= 2
	}
	return k
}

// BuildAuditPath constructs an RFC 6962 audit path for leaf index i in a tree
// of size s, using hashes fetched through the given tile cache.
func BuildAuditPath(ctx context.Context, cache *TileCache, i, s uint64) ([][]byte, error) {
	if s == 0 || i >= s {
		return nil, fmt.Errorf("leaf index %d out of range for tree size %d", i, s)
	}
	var path [][]byte
	sn := i
	fn := s - 1
	level := uint(0)
	for fn > 0 {
		if sn == fn && sn%2 == 0 {
			// Rightmost partial subtree carries up without a sibling.
		} else {
			var sib uint64
			if sn%2 == 1 {
				sib = sn - 1
			} else {
				sib = sn + 1
			}
			h, err := cache.SubtreeHash(ctx, level, sib, s)
			if err != nil {
				return nil, fmt.Errorf("merkle level %d sibling %d: %w", level, sib, err)
			}
			path = append(path, h)
		}
		sn /= 2
		fn /= 2
		level++
	}
	return path, nil
}

// mthOfHashes computes the RFC 6962 MTH of a non-empty sequence of subtree hashes.
// The inputs are already-hashed (level-0 leaf hashes, or any subtree hashes);
// internal nodes are combined with the standard 0x01 prefix.
func mthOfHashes(hashes [][]byte) []byte {
	if len(hashes) == 1 {
		out := make([]byte, len(hashes[0]))
		copy(out, hashes[0])
		return out
	}
	k := largestPow2Below(len(hashes))
	return merkleParent(mthOfHashes(hashes[:k]), mthOfHashes(hashes[k:]))
}

// largestPow2Below returns the largest power of two strictly less than n, for n >= 2.
func largestPow2Below(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func fetchBytes(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
