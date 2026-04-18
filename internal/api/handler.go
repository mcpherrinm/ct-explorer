package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"transparency/internal/ct"
)

type Handler struct {
	analyzer *ct.Analyzer
}

func NewHandler(analyzer *ct.Analyzer) *Handler {
	if analyzer == nil {
		analyzer = ct.NewAnalyzer(nil)
	}
	return &Handler{analyzer: analyzer}
}

func (h *Handler) ServeAnalyze(w http.ResponseWriter, r *http.Request) {
	writeCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("use GET"))
		return
	}

	target := strings.TrimSpace(r.URL.Query().Get("url"))
	if target == "" {
		writeError(w, http.StatusBadRequest, errors.New("missing url query parameter"))
		return
	}

	report, err := h.analyzer.Analyze(r.Context(), target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	writeJSON(w, status, payload)
}

func ErrorBody(err error) map[string]string {
	return map[string]string{"error": err.Error()}
}

func CORSHeaders() map[string]string {
	return map[string]string{
		"access-control-allow-origin":  "*",
		"access-control-allow-methods": "GET, OPTIONS",
		"access-control-allow-headers": "content-type",
		"content-type":                 "application/json; charset=utf-8",
	}
}

func writeCORSHeaders(w http.ResponseWriter) {
	for key, value := range CORSHeaders() {
		w.Header().Set(key, value)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	writeCORSHeaders(w)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorBody(err))
}
