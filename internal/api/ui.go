package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui
var uiFiles embed.FS

func (s *Server) routeUI(mux *http.ServeMux) {
	static, _ := fs.Sub(uiFiles, "ui")
	page := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, err := fs.ReadFile(static, name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			securityHeaders(w)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(b)
		}
	}
	mux.HandleFunc("GET /{$}", page("index.html"))
	mux.HandleFunc("GET /privacy", page("privacy.html"))
	mux.HandleFunc("GET /terms", page("terms.html"))
	files := http.FileServerFS(static)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		files.ServeHTTP(w, r)
	})))
}

func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}
