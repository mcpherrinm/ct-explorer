package ct

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"

	cttypes "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

var embeddedSCTOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

type SignedCertificateTimestamp struct {
	Version            byte
	LogID              [32]byte
	Timestamp          time.Time
	Extensions         []byte
	HashAlgorithm      string
	SignatureAlgorithm string
	Signature          []byte
}

func ParseEmbeddedSCTs(cert *x509.Certificate) []SignedCertificateTimestamp {
	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(embeddedSCTOID) {
			raw = ext.Value
			break
		}
	}
	if len(raw) < 2 {
		return nil
	}

	if scts := parseSCTList(raw); len(scts) > 0 {
		return scts
	}

	var inner []byte
	rest, err := asn1.Unmarshal(raw, &inner)
	if err == nil && len(rest) == 0 {
		return parseSCTList(inner)
	}

	return nil
}

func parseSCTList(raw []byte) []SignedCertificateTimestamp {
	var list ctx509.SignedCertificateTimestampList
	rest, err := cttls.Unmarshal(raw, &list)
	if err != nil || len(rest) != 0 {
		return nil
	}
	scts := make([]SignedCertificateTimestamp, 0, len(list.SCTList))
	for _, serialized := range list.SCTList {
		sct, err := parseSCT(serialized.Val)
		if err == nil {
			scts = append(scts, sct)
		}
	}
	return scts
}

func ParseTLSSCTs(rawSCTs [][]byte) []SignedCertificateTimestamp {
	scts := make([]SignedCertificateTimestamp, 0, len(rawSCTs))
	for _, raw := range rawSCTs {
		sct, err := parseSCT(raw)
		if err == nil {
			scts = append(scts, sct)
		}
	}
	return scts
}

func parseSCT(raw []byte) (SignedCertificateTimestamp, error) {
	var parsed cttypes.SignedCertificateTimestamp
	rest, err := cttls.Unmarshal(raw, &parsed)
	if err != nil {
		return SignedCertificateTimestamp{}, err
	}
	if len(rest) != 0 {
		return SignedCertificateTimestamp{}, errors.New("trailing data after SCT")
	}

	var sct SignedCertificateTimestamp
	sct.Version = byte(parsed.SCTVersion)
	sct.LogID = parsed.LogID.KeyID
	sct.Timestamp = time.UnixMilli(int64(parsed.Timestamp))
	sct.Extensions = append([]byte(nil), parsed.Extensions...)
	sct.HashAlgorithm = parsed.Signature.Algorithm.Hash.String()
	sct.SignatureAlgorithm = parsed.Signature.Algorithm.Signature.String()
	sct.Signature = append([]byte(nil), parsed.Signature.Signature...)
	return sct, nil
}
