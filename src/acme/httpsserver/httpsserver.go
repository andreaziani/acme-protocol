package httpsserver

import (
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func StartHttpsServer() {
	http.HandleFunc("/", handler)

	log.Info("HTTPS SERVER - Server Started on Port 5001")
	err := http.ListenAndServeTLS(":5001", "/builds/COURSE-NETSEC-ACME-AS-2019/aziani-acme-project-netsec-fall-19/src/certificate.pem", "/builds/COURSE-NETSEC-ACME-AS-2019/aziani-acme-project-netsec-fall-19/src/private_key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}
