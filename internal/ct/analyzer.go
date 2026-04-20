package ct

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	cttypes "github.com/google/certificate-transparency-go"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

const defaultHTTPSPort = "443"

type Analyzer struct {
	client *http.Client
	logs   *LogDirectory
}

func NewAnalyzer(client *http.Client) *Analyzer {
	if client == nil {
		client = DefaultHTTPClient()
	}
	return &Analyzer{client: client, logs: NewLogDirectory(client)}
}

func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			DialContext: safeDialer(8 * time.Second).DialContext,
		},
	}
}

func (a *Analyzer) Analyze(ctx context.Context, rawURL string) (*Report, error) {
	target, err := normalizeTarget(rawURL)
	if err != nil {
		return nil, err
	}
	if err := validatePublicHost(ctx, target.Host); err != nil {
		return nil, err
	}

	certs, tlsSCTs, verifiedChains, verifyErr, err := fetchPeerCertificates(ctx, target)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("server did not present a certificate")
	}

	leaf := certs[0]
	embeddedSCTs := ParseEmbeddedSCTs(leaf)
	tlsSCTReports := ParseTLSSCTs(tlsSCTs)
	sctSources := append(
		sourcedSCTs(embeddedSCTs, "embedded certificate extension"),
		sourcedSCTs(tlsSCTReports, "TLS handshake extension")...,
	)
	logs, logErr := a.logs.Load(ctx)
	logMap := logs.ByID()

	report := &Report{
		Target: Target{
			Input:    rawURL,
			Host:     target.Host,
			Port:     target.Port,
			Server:   net.JoinHostPort(target.Host, target.Port),
			Fetched:  time.Now().UTC(),
			LogError: errorString(logErr),
		},
		Certificate: certificateSummary(leaf, len(embeddedSCTs), len(tlsSCTReports)),
		Chain:       chainSummary(certs),
		Validation:  validationSummary(leaf, target.Host, verifiedChains, verifyErr),
		SCTs:        make([]SCTReport, 0, len(sctSources)),
		ProofNotes: []string{
			"Certificate Transparency logs prove inclusion of a Merkle tree leaf, not a domain name.",
			"SCTs delivered through the TLS handshake can refer directly to the final certificate; embedded SCTs usually refer to the logged precertificate.",
			"TLS-delivered SCTs usually point at the final certificate. Embedded SCTs usually point at a precertificate, so this explorer rebuilds that leaf before checking inclusion.",
		},
	}

	report.SCTs = a.analyzeSCTs(ctx, sctSources, logMap, certs)

	if len(report.SCTs) == 0 {
		report.ProofNotes = append(report.ProofNotes, "No SCTs were found in the certificate or TLS handshake. Some deployments deliver SCTs through stapled OCSP; this prototype does not parse OCSP SCTs yet.")
	}

	return report, nil
}

func (a *Analyzer) analyzeSCTs(ctx context.Context, sctSources []sourcedSCT, logMap map[string]LogInfo, certs []*x509.Certificate) []SCTReport {
	reports := make([]SCTReport, len(sctSources))
	var wg sync.WaitGroup

	for i, sourced := range sctSources {
		sct := sourced.SCT
		reports[i] = SCTReport{
			Source:       sourced.Source,
			Version:      int(sct.Version),
			LogID:        base64.StdEncoding.EncodeToString(sct.LogID[:]),
			LogIDHex:     hex.EncodeToString(sct.LogID[:]),
			Timestamp:    sct.Timestamp.UTC(),
			Extensions:   base64.StdEncoding.EncodeToString(sct.Extensions),
			Signature:    base64.StdEncoding.EncodeToString(sct.Signature),
			SignatureAlg: sct.SignatureAlgorithm,
			HashAlg:      sct.HashAlgorithm,
		}

		logInfo, ok := logMap[reports[i].LogID]
		if !ok {
			reports[i].Proof = &ProofReport{
				Status:      "unknown-log",
				Explanation: "the SCT log ID was not found in the current Chrome CT log list fetched by the backend",
			}
			continue
		}

		reports[i].Log = &LogSummary{
			Description: logInfo.Description,
			URL:         logInfo.URL,
			Operator:    logInfo.Operator,
			State:       logInfo.State,
		}

		wg.Add(1)
		go func(i int, sourced sourcedSCT, logInfo LogInfo) {
			defer wg.Done()

			proof, err := a.tryProof(ctx, logInfo.URL, certs, sourced.SCT, sourced.Source)
			if err != nil {
				reports[i].Proof = &ProofReport{
					Status:      "not-proven",
					Explanation: err.Error(),
				}
				return
			}
			reports[i].Proof = proof
		}(i, sourced, logInfo)
	}

	wg.Wait()
	return reports
}

func (a *Analyzer) tryProof(ctx context.Context, logURL string, chain []*x509.Certificate, sct SignedCertificateTimestamp, source string) (*ProofReport, error) {
	sth, err := GetSTH(ctx, a.client, logURL)
	if err != nil {
		return nil, fmt.Errorf("could not fetch signed tree head from %s: %w", logURL, err)
	}

	candidate, err := proofCandidateForSCT(chain, sct, source)
	if err != nil {
		return nil, err
	}

	hash := candidate.leafHash[:]
	leafIndex, auditPath, err := GetProofByHash(ctx, a.client, logURL, hash, sth.TreeSize)
	if err != nil {
		return nil, fmt.Errorf("inclusion proof was not returned by this log: %w", err)
	}

	treeHead := sth.SHA256RootHash.Base64String()
	rootOK, auditSteps := VerifyAuditPath(hash, auditPath, leafIndex, sth.TreeSize, treeHead)
	proofURL, err := ProofByHashURL(logURL, hash, sth.TreeSize)
	if err != nil {
		return nil, fmt.Errorf("could not build inclusion proof URL: %w", err)
	}
	return &ProofReport{
		Status:      candidate.status,
		Explanation: candidate.explanation,
		LeafHash:    base64.StdEncoding.EncodeToString(hash),
		ProofURL:    proofURL,
		TreeSize:    sth.TreeSize,
		TreeHead:    treeHead,
		LeafIndex:   leafIndex,
		AuditPath:   auditPath,
		RootOK:      rootOK,
		AuditSteps:  auditSteps,
	}, nil
}

type proofCandidate struct {
	status      string
	explanation string
	leafHash    [32]byte
}

func proofCandidateForSCT(chain []*x509.Certificate, sct SignedCertificateTimestamp, source string) (proofCandidate, error) {
	ctChain, err := parseCTChain(chain)
	if err != nil {
		return proofCandidate{}, err
	}

	timestamp := uint64(sct.Timestamp.UnixMilli())
	if source != "embedded certificate extension" {
		leaf, err := cttypes.MerkleTreeLeafFromChain(ctChain, cttypes.X509LogEntryType, timestamp)
		if err != nil {
			return proofCandidate{}, fmt.Errorf("could not build X.509 CT leaf: %w", err)
		}
		leaf.TimestampedEntry.Extensions = cttypes.CTExtensions(sct.Extensions)
		hash, err := cttypes.LeafHashForLeaf(leaf)
		if err != nil {
			return proofCandidate{}, fmt.Errorf("could not hash X.509 CT leaf: %w", err)
		}
		return proofCandidate{
			status:      "proven-x509-leaf",
			explanation: "the log returned an inclusion proof for the final certificate leaf",
			leafHash:    hash,
		}, nil
	}

	leaf, err := cttypes.MerkleTreeLeafForEmbeddedSCT(ctChain, timestamp)
	if err != nil {
		return proofCandidate{}, fmt.Errorf("could not build embedded-SCT precertificate leaf: %w", err)
	}
	leaf.TimestampedEntry.Extensions = cttypes.CTExtensions(sct.Extensions)
	hash, err := cttypes.LeafHashForLeaf(leaf)
	if err != nil {
		return proofCandidate{}, fmt.Errorf("could not hash embedded-SCT precertificate leaf: %w", err)
	}
	return proofCandidate{
		status:      "proven-precert-leaf",
		explanation: "the log returned an inclusion proof for the rebuilt precertificate leaf",
		leafHash:    hash,
	}, nil
}

func parseCTChain(chain []*x509.Certificate) ([]*ctx509.Certificate, error) {
	ctChain := make([]*ctx509.Certificate, 0, len(chain))
	for i, cert := range chain {
		parsed, err := ctx509.ParseCertificate(cert.Raw)
		if err != nil && ctx509.IsFatal(err) {
			return nil, fmt.Errorf("parse CT chain certificate %d: %w", i, err)
		}
		ctChain = append(ctChain, parsed)
	}
	return ctChain, nil
}

func normalizeTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, errors.New("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return Target{}, errors.New("only https URLs are supported")
	}
	if parsed.Hostname() == "" {
		return Target{}, errors.New("URL must include a hostname")
	}

	port := parsed.Port()
	if port == "" {
		port = defaultHTTPSPort
	}
	if _, err := strconv.Atoi(port); err != nil {
		return Target{}, fmt.Errorf("invalid port %q", port)
	}

	return Target{Input: raw, Host: parsed.Hostname(), Port: port}, nil
}

func fetchPeerCertificates(ctx context.Context, target Target) ([]*x509.Certificate, [][]byte, [][]*x509.Certificate, error, error) {
	dialer := safeDialer(8 * time.Second)
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(target.Host, target.Port), &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, nil, nil, nil, nil
	}

	roots, _ := x509.SystemCertPool()
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	chains, verifyErr := certs[0].Verify(x509.VerifyOptions{
		DNSName:       target.Host,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	})
	return certs, state.SignedCertificateTimestamps, chains, verifyErr, nil
}

type sourcedSCT struct {
	SCT    SignedCertificateTimestamp
	Source string
}

func sourcedSCTs(scts []SignedCertificateTimestamp, source string) []sourcedSCT {
	out := make([]sourcedSCT, 0, len(scts))
	for _, sct := range scts {
		out = append(out, sourcedSCT{SCT: sct, Source: source})
	}
	return out
}

func certificateSummary(cert *x509.Certificate, embeddedSCTCount, tlsSCTCount int) CertificateSummary {
	rawHash := sha256.Sum256(cert.Raw)
	tbsHash := sha256.Sum256(cert.RawTBSCertificate)
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	return CertificateSummary{
		Subject:                     cert.Subject.String(),
		Issuer:                      cert.Issuer.String(),
		SerialNumber:                cert.SerialNumber.String(),
		NotBefore:                   cert.NotBefore.UTC(),
		NotAfter:                    cert.NotAfter.UTC(),
		DNSNames:                    append([]string(nil), cert.DNSNames...),
		SHA256:                      hex.EncodeToString(rawHash[:]),
		SHA256Base64:                base64.StdEncoding.EncodeToString(rawHash[:]),
		TBSSHA256:                   hex.EncodeToString(tbsHash[:]),
		SPKISHA256:                  hex.EncodeToString(spkiHash[:]),
		SignatureAlgo:               cert.SignatureAlgorithm.String(),
		PublicKeyAlgo:               cert.PublicKeyAlgorithm.String(),
		EmbeddedSCTExtensionPresent: embeddedSCTCount > 0,
		EmbeddedSCTCount:            embeddedSCTCount,
		TLSSCTCount:                 tlsSCTCount,
	}
}

func chainSummary(certs []*x509.Certificate) []ChainCertificate {
	chain := make([]ChainCertificate, 0, len(certs))
	for i, cert := range certs {
		hash := sha256.Sum256(cert.Raw)
		chain = append(chain, ChainCertificate{
			Position:     i,
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			SHA256:       hex.EncodeToString(hash[:]),
			NotBefore:    cert.NotBefore.UTC(),
			NotAfter:     cert.NotAfter.UTC(),
		})
	}
	return chain
}

func validationSummary(cert *x509.Certificate, host string, chains [][]*x509.Certificate, verifyErr error) Validation {
	hostErr := cert.VerifyHostname(host)
	validation := Validation{
		HostnameOK: hostErr == nil,
		ChainOK:    verifyErr == nil,
		Chains:     len(chains),
	}
	if hostErr != nil {
		validation.HostnameError = hostErr.Error()
	}
	if verifyErr != nil {
		validation.ChainError = verifyErr.Error()
	}
	return validation
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
