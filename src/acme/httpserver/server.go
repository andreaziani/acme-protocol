package httpserver

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	ServerPort = ":5002"
	dir        = "/.well-known/acme-challenge/"
	reqPath    = "/builds/COURSE-NETSEC-ACME-AS-2019/aziani-acme-project-netsec-fall-19/src/"
)

func StartServer() {
	http.HandleFunc(dir, handler)
	log.Fatal(http.ListenAndServe(ServerPort, nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	ss := strings.Split(r.URL.Path, "/")
	fileName := ss[len(ss)-1][0:]

	dat, err := ioutil.ReadFile(reqPath + fileName)
	if err != nil {
		log.Fatal(err)
	}

	log.Info("Http server response on: " + string(dat))
	_, _ = fmt.Fprint(w, string(dat))
}
