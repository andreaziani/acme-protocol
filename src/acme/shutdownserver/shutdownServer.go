package shutdownserver

import (
	"context"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func StartShutDownServer() {
	log.Info("HTTP SHUTDOWN SERVER - Server Started on Port 5003")
	m := http.NewServeMux()
	s := http.Server{Addr: ":5003", Handler: m}
	m.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		_ = s.Shutdown(context.Background())
	})
	if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	log.Printf("Finished")
}
