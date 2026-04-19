package ct

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestGetProofByHashSnapshotForCTJordanWrightDotCom(t *testing.T) {
	leafHash, err := base64.StdEncoding.DecodeString("mtPLaiiDzbtvBS8vUQdI5QPjib1PG+YCEnwqkW1CShk=")
	if err != nil {
		t.Fatal(err)
	}

	var sawEncodedHash bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			w.Write([]byte(`{
				"tree_size": 411874972,
				"timestamp": 1776606087040,
				"sha256_root_hash": "Ea118S5hElAyD/LJxmDBA+tG7CWHkxcupPd+qKBBVZk=",
				"tree_head_signature": "BAMARzBFAiEAjiKHrqZ4xXChXx7UOjeDUC+0s8nfSE4GWRpo+MJdXpgCIGr1s3b46y5UbF5mYqtgwagpaTI0bT2e5iJvl78nR8bw"
			}`))
		case "/ct/v1/get-proof-by-hash":
			sawEncodedHash = r.URL.Query().Get("hash") == base64.StdEncoding.EncodeToString(leafHash) &&
				strings.Contains(r.URL.RawQuery, "PG%2BYC") &&
				strings.Contains(r.URL.RawQuery, "%3D")
			if r.URL.Query().Get("tree_size") != "411874972" {
				t.Fatalf("tree_size query = %q, want 411874972", r.URL.Query().Get("tree_size"))
			}
			w.Write([]byte(`{
				"leaf_index": 248956215,
				"audit_path": [
					"EAdx5FN8WNK2TtAQ2O/AWL5wwBA+QmZ35pv0di6+P8g=",
					"W07QJq2l4s3gK+UCJRfRuEJjHxHFxIseW4orfeTg8R0=",
					"HR2VY45vZ+G3dHiEJtLsAOIcKnelK5SVxwHvmRNpAqg=",
					"5+lB7BUTtpQNnOmec0pGwzy3WLM2HsbxTYA3Meyrwj4=",
					"AzS6yippdSJ2dvjHzseKohVvx/N3C9+zreRXwqskguc=",
					"r1UQKIipD3CO+nVm7D40s5Eo1yTItGDQDnNzWFM2+7s=",
					"Q/DLeMIxXe1nDhhIF0RwPZa/a1JnbO/xnlC4XSVo/Vw=",
					"n2mrwju+zsvYDNoc7vXa3zDXefT1KzpAXA0pNHyz69s=",
					"LkNkhyIaBkL+LZGW5K0feJw0/juEIaSosPbNwIngQm0=",
					"cCc/p2IrZBFpR9Reqt69RaGRqrzmisaOWB/WYDZ/V38=",
					"zpPna1+NbKAniHREK7n2taw525dLd/Spw9cIydLcjnk=",
					"4Sd/SIsKQCclBb0992ieqXR2UoV8OIqOazmg8sJTQrg=",
					"Op37E4azjSFgJpFvxKQ2pdDouogSlNeAtNOLzECFKHw=",
					"JmdeDm9aJQ+u4RoEydf2ARuk//ZaQPslstLJLfv4iIk=",
					"CHPLqNbjpMPrgD0ifKGpOgaBu1WQYUlaTQUvIk69F80=",
					"WEuumgAHLw14HNocgRTLo4XXqTHou5X9Q7hcdD6Lc4Y=",
					"Vcq2bspNGndcRBd/WaHD5DjxcdFp2qN+FIosn57j/yQ=",
					"GGqgB2U6hphEFy9aNPO/33MYeg3M7G/pIzUVgqAgng4=",
					"SzcrwHzCvbckCf/Vsq2n+jDWr/2iUSL34HMf0lC+hF0=",
					"RcwDnBNMD+S9ehXNlaTBRdJGEFDcIkgCOSGZMHshypA=",
					"hYYo6vakzTXCQm9cj6NZ+1NyJ+svFlvqy0SLSBuJrAU=",
					"SWZodQuiOtrc1wqxgpi+6sjRZBLAQlf2HhZftzpdUVg=",
					"o5DBrkYs3XR2UQsTA+qylBlFNt2BqoDjbe7uXKDvizM=",
					"GvsHZlfHilA3lY+uhH7KwPItc5s3kb16lpMBAXBZfmc=",
					"KTZPG8Vo6PehQsYnxFmj8l7tqQ/sb9mQ5JGnX9BDSwo=",
					"kN7CtcxrelDzgiwJFomBtzMBQvllkIVShOl9QOradxo=",
					"+cTo+p25Ltp1Aj5irVRSBpr8wm9/FBPJFb4w/gSVtDY=",
					"dxS+qEdPjGCEAtbLVsS+rpUD8Imy89yRIv3jMoNrHdo=",
					"JONrHvNawwfi1DYkp+dWam1u2QIQKIh4PKkU2nUX5yo="
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
	leafIndex, auditPath, err := GetProofByHash(context.Background(), server.Client(), server.URL, leafHash, sth.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if !sawEncodedHash {
		t.Fatalf("GetProofByHash did not preserve the base64 hash in the query")
	}
	if leafIndex != 248956215 || len(auditPath) != 29 {
		t.Fatalf("unexpected proof: leafIndex=%d auditPathLen=%d", leafIndex, len(auditPath))
	}
	if ok, steps := VerifyAuditPath(leafHash, auditPath, leafIndex, sth.TreeSize, sth.SHA256RootHash.Base64String()); !ok {
		t.Fatalf("snapshot audit path did not verify; steps=%d", len(steps))
	}
}

func leafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}
