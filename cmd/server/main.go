package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"transparency/internal/api"
)

func main() {
	addr := env("ADDR", ":8080")
	mux := http.NewServeMux()

	handler := api.NewHandler(nil)
	mux.HandleFunc("/api/analyze", handler.ServeAnalyze)
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("/", http.FileServer(http.Dir("web")))

	log.Printf("certificate transparency microsite listening on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, logRequests(mux)); err != nil {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
