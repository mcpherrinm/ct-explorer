package ct

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/certificate-transparency-go/loglist3"
)

func TestLogListByID(t *testing.T) {
	list := LogList{Logs: []LogInfo{
		{LogID: "a", URL: "https://a.example"},
		{LogID: "b", URL: "https://b.example"},
	}}
	byID := list.ByID()
	if byID["b"].URL != "https://b.example" {
		t.Fatalf("ByID[b] = %+v", byID["b"])
	}
}

func TestLogState(t *testing.T) {
	if got := logState(&loglist3.LogStates{Usable: &loglist3.LogState{}}); got != "usable" {
		t.Fatalf("logState = %q, want usable", got)
	}
	if got := logState(nil); got != "unknown" {
		t.Fatalf("empty logState = %q, want unknown", got)
	}
}

func TestLogDirectoryLoadCachesAndNormalizesLogs(t *testing.T) {
	key := []byte("test public key")
	logID := sha256.Sum256(key)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"operators": [{
				"name": "Example Operator",
				"logs": [{
					"description": "Example Log",
					"url": "https://log.example/",
					"log_id": "` + base64.StdEncoding.EncodeToString(logID[:]) + `",
					"key": "` + base64.StdEncoding.EncodeToString(key) + `",
					"state": {"usable": {"timestamp": "2026-01-01T00:00:00Z"}}
				}]
			}]
		}`))
	}))
	defer server.Close()

	oldURL := chromeLogListURL
	chromeLogListURL = server.URL
	defer func() { chromeLogListURL = oldURL }()

	dir := NewLogDirectory(server.Client())
	first, err := dir.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := dir.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if requests != 1 {
		t.Fatalf("requests = %d, want cached single request", requests)
	}
	if len(first.Logs) != 1 || len(second.Logs) != 1 {
		t.Fatalf("logs = %d/%d, want 1/1", len(first.Logs), len(second.Logs))
	}
	log := first.Logs[0]
	if log.URL != "https://log.example" {
		t.Fatalf("URL = %q, want trimmed URL", log.URL)
	}
	if log.Operator != "Example Operator" || log.State != "usable" {
		t.Fatalf("log metadata = %+v", log)
	}
	if log.LogID != base64.StdEncoding.EncodeToString(logID[:]) {
		t.Fatalf("log ID = %q, want sha256 key ID", log.LogID)
	}
}
