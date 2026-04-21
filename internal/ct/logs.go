package ct

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
)

var chromeLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

type LogDirectory struct {
	client *http.Client
	mu     sync.Mutex
	cached LogList
	loaded time.Time
}

func NewLogDirectory(client *http.Client) *LogDirectory {
	return &LogDirectory{client: client}
}

func (d *LogDirectory) Load(ctx context.Context) (LogList, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if time.Since(d.loaded) < 6*time.Hour && len(d.cached.Logs) > 0 {
		return d.cached, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chromeLogListURL, nil)
	if err != nil {
		return LogList{}, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return LogList{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return LogList{}, fmt.Errorf("log list returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return LogList{}, err
	}
	raw, err := loglist3.NewFromJSON(body)
	if err != nil {
		return LogList{}, err
	}

	list := LogList{Logs: make([]LogInfo, 0)}
	for _, operator := range raw.Operators {
		for _, log := range operator.Logs {
			u := strings.TrimRight(log.URL, "/")
			list.Logs = append(list.Logs, LogInfo{
				Description:   log.Description,
				URL:           u,
				SubmissionURL: u,
				MonitoringURL: u,
				Operator:      operator.Name,
				Key:           base64.StdEncoding.EncodeToString(log.Key),
				LogID:         base64.StdEncoding.EncodeToString(log.LogID),
				State:         logState(log.State),
				Type:          "rfc6962",
			})
		}
		for _, log := range operator.TiledLogs {
			submission := strings.TrimRight(log.SubmissionURL, "/")
			monitoring := strings.TrimRight(log.MonitoringURL, "/")
			list.Logs = append(list.Logs, LogInfo{
				Description:   log.Description,
				URL:           monitoring,
				SubmissionURL: submission,
				MonitoringURL: monitoring,
				Operator:      operator.Name,
				Key:           base64.StdEncoding.EncodeToString(log.Key),
				LogID:         base64.StdEncoding.EncodeToString(log.LogID),
				State:         logState(log.State),
				Type:          "static-ct-api",
			})
		}
	}

	d.cached = list
	d.loaded = time.Now()
	return list, nil
}

func (l LogList) ByID() map[string]LogInfo {
	byID := make(map[string]LogInfo, len(l.Logs))
	for _, log := range l.Logs {
		byID[log.LogID] = log
	}
	return byID
}

func logState(raw *loglist3.LogStates) string {
	if raw == nil {
		return "unknown"
	}
	switch raw.LogStatus() {
	case loglist3.PendingLogStatus:
		return "pending"
	case loglist3.QualifiedLogStatus:
		return "qualified"
	case loglist3.UsableLogStatus:
		return "usable"
	case loglist3.ReadOnlyLogStatus:
		return "readonly"
	case loglist3.RetiredLogStatus:
		return "retired"
	case loglist3.RejectedLogStatus:
		return "rejected"
	default:
		return "unknown"
	}
}
