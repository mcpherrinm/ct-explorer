package ct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	cttypes "github.com/google/certificate-transparency-go"
	ctclient "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

func GetSTH(ctx context.Context, client *http.Client, logURL string) (*cttypes.SignedTreeHead, error) {
	logClient, err := ctclient.New(logURL, client, jsonclient.Options{})
	if err != nil {
		return nil, err
	}
	return logClient.GetSTH(ctx)
}

func GetProofByHash(ctx context.Context, client *http.Client, logURL string, leafHash []byte, treeSize uint64) (uint64, []string, error) {
	logClient, err := ctclient.New(logURL, client, jsonclient.Options{})
	if err != nil {
		return 0, nil, err
	}
	proof, err := logClient.GetProofByHash(ctx, leafHash, treeSize)
	if err != nil {
		return 0, nil, err
	}
	if proof.LeafIndex < 0 {
		return 0, nil, fmt.Errorf("log returned negative leaf index %d", proof.LeafIndex)
	}

	auditPath := make([]string, 0, len(proof.AuditPath))
	for _, node := range proof.AuditPath {
		auditPath = append(auditPath, base64.StdEncoding.EncodeToString(node))
	}
	return uint64(proof.LeafIndex), auditPath, nil
}

func sha256Base64(in []byte) string {
	sum := sha256.Sum256(in)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func VerifyAuditPath(leafHash []byte, auditPath []string, leafIndex uint64, treeSize uint64, rootHashB64 string) (bool, []AuditStep) {
	rootHash, err := base64.StdEncoding.DecodeString(rootHashB64)
	if err != nil || len(rootHash) != sha256.Size || treeSize == 0 || leafIndex >= treeSize {
		return false, nil
	}

	steps := make([]AuditStep, 0, len(auditPath))
	calculated := append([]byte(nil), leafHash...)
	sn := leafIndex
	fn := treeSize - 1
	for level, nodeB64 := range auditPath {
		node, err := base64.StdEncoding.DecodeString(nodeB64)
		if err != nil || len(node) != sha256.Size {
			return false, steps
		}
		if sn%2 == 1 || sn == fn {
			calculated = merkleParent(node, calculated)
			steps = append(steps, AuditStep{
				Level:       level,
				SiblingSide: "left",
				SiblingHash: nodeB64,
				ParentHash:  base64.StdEncoding.EncodeToString(calculated),
			})
			if sn%2 == 0 {
				for sn%2 == 0 && sn != 0 {
					sn /= 2
					fn /= 2
				}
			}
		} else {
			calculated = merkleParent(calculated, node)
			steps = append(steps, AuditStep{
				Level:       level,
				SiblingSide: "right",
				SiblingHash: nodeB64,
				ParentHash:  base64.StdEncoding.EncodeToString(calculated),
			})
		}
		sn /= 2
		fn /= 2
	}
	return bytes.Equal(calculated, rootHash), steps
}

func merkleParent(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}
