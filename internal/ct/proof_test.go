package ct

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyAuditPathBuildsRootAndTranscript(t *testing.T) {
	leaves := [][]byte{
		leafHash([]byte("leaf-0")),
		leafHash([]byte("leaf-1")),
		leafHash([]byte("leaf-2")),
		leafHash([]byte("leaf-3")),
	}
	leftParent := merkleParent(leaves[0], leaves[1])
	rightParent := merkleParent(leaves[2], leaves[3])
	root := merkleParent(leftParent, rightParent)

	ok, steps := VerifyAuditPath(leaves[2], []string{
		base64.StdEncoding.EncodeToString(leaves[3]),
		base64.StdEncoding.EncodeToString(leftParent),
	}, 2, 4, base64.StdEncoding.EncodeToString(root))
	if !ok {
		t.Fatalf("VerifyAuditPath returned false")
	}
	if len(steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(steps))
	}
	if steps[0].SiblingSide != "right" {
		t.Fatalf("step 0 side = %s, want right", steps[0].SiblingSide)
	}
	if steps[1].SiblingSide != "left" {
		t.Fatalf("step 1 side = %s, want left", steps[1].SiblingSide)
	}
	if steps[1].ParentHash != base64.StdEncoding.EncodeToString(root) {
		t.Fatalf("final parent = %s, want root", steps[1].ParentHash)
	}

	badRoot := sha256.Sum256([]byte("bad root"))
	ok, _ = VerifyAuditPath(leaves[2], []string{
		base64.StdEncoding.EncodeToString(leaves[3]),
		base64.StdEncoding.EncodeToString(leftParent),
	}, 2, 4, base64.StdEncoding.EncodeToString(badRoot[:]))
	if ok {
		t.Fatalf("VerifyAuditPath accepted a bad root")
	}
}

func TestCTHTTPHelpers(t *testing.T) {
	leafHash := []byte{1, 2, 3}
	var sawHash, sawTreeSize bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			w.Write([]byte(`{
				"tree_size": 9,
				"timestamp": 1396609800587,
				"sha256_root_hash": "SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo=",
				"tree_head_signature": "BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="
			}`))
		case "/ct/v1/get-proof-by-hash":
			sawHash = r.URL.Query().Get("hash") == base64.StdEncoding.EncodeToString(leafHash)
			sawTreeSize = r.URL.Query().Get("tree_size") == "9"
			w.Write([]byte(`{
				"leaf_index": 3,
				"audit_path": [
					"pMumx96PIUB3TX543ljlpQ/RgZRqitRfykupIZrXq0Q=",
					"5s2NQWkjmesu+Kqgp70TCwVLwq8obpHw/JyMGwN56pQ="
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	sth, err := GetSTH(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if sth.TreeSize != 9 {
		t.Fatalf("tree size = %d, want 9", sth.TreeSize)
	}

	leafIndex, auditPath, err := GetProofByHash(context.Background(), server.Client(), server.URL, leafHash, sth.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if !sawHash || !sawTreeSize {
		t.Fatalf("GetProofByHash did not send expected query: sawHash=%v sawTreeSize=%v", sawHash, sawTreeSize)
	}
	if leafIndex != 3 || len(auditPath) != 2 {
		t.Fatalf("unexpected proof: leafIndex=%d auditPath=%v", leafIndex, auditPath)
	}
}

func leafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}
