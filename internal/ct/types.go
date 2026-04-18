package ct

import "time"

type Report struct {
	Target      Target             `json:"target"`
	Certificate CertificateSummary `json:"certificate"`
	Chain       []ChainCertificate `json:"chain"`
	Validation  Validation         `json:"validation"`
	SCTs        []SCTReport        `json:"scts"`
	ProofNotes  []string           `json:"proof_notes"`
}

type Target struct {
	Input    string    `json:"input"`
	Host     string    `json:"host"`
	Port     string    `json:"port"`
	Server   string    `json:"server"`
	Fetched  time.Time `json:"fetched"`
	LogError string    `json:"log_error,omitempty"`
}

type CertificateSummary struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DNSNames      []string  `json:"dns_names"`
	SHA256        string    `json:"sha256"`
	SHA256Base64  string    `json:"sha256_base64"`
	TBSSHA256     string    `json:"tbs_sha256"`
	SPKISHA256    string    `json:"spki_sha256"`
	SignatureAlgo string    `json:"signature_algo"`
	PublicKeyAlgo string    `json:"public_key_algo"`
}

type ChainCertificate struct {
	Position     int       `json:"position"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	SHA256       string    `json:"sha256"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
}

type Validation struct {
	HostnameOK    bool   `json:"hostname_ok"`
	HostnameError string `json:"hostname_error,omitempty"`
	ChainOK       bool   `json:"chain_ok"`
	ChainError    string `json:"chain_error,omitempty"`
	Chains        int    `json:"chains"`
}

type SCTReport struct {
	Source       string       `json:"source"`
	Version      int          `json:"version"`
	LogID        string       `json:"log_id"`
	LogIDHex     string       `json:"log_id_hex"`
	Timestamp    time.Time    `json:"timestamp"`
	Extensions   string       `json:"extensions"`
	Signature    string       `json:"signature"`
	HashAlg      string       `json:"hash_alg"`
	SignatureAlg string       `json:"signature_alg"`
	Log          *LogSummary  `json:"log,omitempty"`
	Proof        *ProofReport `json:"proof,omitempty"`
}

type LogSummary struct {
	Description string `json:"description"`
	URL         string `json:"url"`
	Operator    string `json:"operator"`
	State       string `json:"state"`
}

type ProofReport struct {
	Status      string      `json:"status"`
	Explanation string      `json:"explanation"`
	LeafHash    string      `json:"leaf_hash,omitempty"`
	TreeSize    uint64      `json:"tree_size,omitempty"`
	TreeHead    string      `json:"tree_head,omitempty"`
	LeafIndex   uint64      `json:"leaf_index,omitempty"`
	AuditPath   []string    `json:"audit_path,omitempty"`
	RootOK      bool        `json:"root_ok"`
	AuditSteps  []AuditStep `json:"audit_steps,omitempty"`
}

type AuditStep struct {
	Level       int    `json:"level"`
	SiblingSide string `json:"sibling_side"`
	SiblingHash string `json:"sibling_hash"`
	ParentHash  string `json:"parent_hash"`
}

type LogList struct {
	Logs []LogInfo
}

type LogInfo struct {
	Description string
	URL         string
	Operator    string
	Key         string
	LogID       string
	State       string
}
