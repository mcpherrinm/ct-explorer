package ct

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"testing"
	"time"
)

func TestParseEmbeddedSCTsUnwrapsASN1Extension(t *testing.T) {
	rawSCT := testSCT(7, 123456789, []byte{0xaa, 0xbb}, []byte{0x30, 0x31, 0x32})
	list := testSCTList(rawSCT)
	wrapped, err := asn1.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}

	cert := &x509.Certificate{
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x00}},
			{Id: embeddedSCTOID, Value: wrapped},
		},
	}

	scts := ParseEmbeddedSCTs(cert)
	if len(scts) != 1 {
		t.Fatalf("got %d SCTs, want 1", len(scts))
	}
	got := scts[0]
	if got.Version != 0 {
		t.Fatalf("version = %d, want 0", got.Version)
	}
	if got.LogID[0] != 7 || got.LogID[31] != 38 {
		t.Fatalf("unexpected log ID boundary bytes: %d %d", got.LogID[0], got.LogID[31])
	}
	if got.Timestamp != time.Unix(0, 123456789*int64(time.Millisecond)) {
		t.Fatalf("timestamp = %s", got.Timestamp)
	}
	if got.HashAlgorithm != "SHA256" || got.SignatureAlgorithm != "ECDSA" {
		t.Fatalf("algorithms = %s/%s, want SHA256/ECDSA", got.HashAlgorithm, got.SignatureAlgorithm)
	}
	if string(got.Extensions) != string([]byte{0xaa, 0xbb}) {
		t.Fatalf("extensions = %x", got.Extensions)
	}
	if string(got.Signature) != "012" {
		t.Fatalf("signature = %x", got.Signature)
	}
}

func TestParseTLSSCTsSkipsMalformedEntries(t *testing.T) {
	valid := testSCT(1, 99, nil, []byte{0x01})
	scts := ParseTLSSCTs([][]byte{
		{0x00, 0x01},
		valid,
	})
	if len(scts) != 1 {
		t.Fatalf("got %d SCTs, want 1", len(scts))
	}
	if scts[0].LogID[0] != 1 {
		t.Fatalf("log ID first byte = %d, want 1", scts[0].LogID[0])
	}
}

func testSCT(logIDStart byte, millis int64, extensions []byte, signature []byte) []byte {
	var raw []byte
	raw = append(raw, 0)
	for i := range 32 {
		raw = append(raw, logIDStart+byte(i))
	}
	raw = binary.BigEndian.AppendUint64(raw, uint64(millis))
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(extensions)))
	raw = append(raw, extensions...)
	raw = append(raw, 4, 3) // sha256, ecdsa.
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(signature)))
	raw = append(raw, signature...)
	return raw
}

func testSCTList(scts ...[]byte) []byte {
	var body []byte
	for _, sct := range scts {
		body = binary.BigEndian.AppendUint16(body, uint16(len(sct)))
		body = append(body, sct...)
	}
	var list []byte
	list = binary.BigEndian.AppendUint16(list, uint16(len(body)))
	return append(list, body...)
}
