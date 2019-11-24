package main

import (
	. "acme/client"
	. "acme/dns"
	. "acme/httpserver"
	. "acme/shutdownserver"
	"flag"
	"os"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

type Options struct {
	Challenge string
	Dir       string   `short:"w" long:"dir" description:"directory url of acme server"`
	Record    string   `short:"r" long:"record" description:"IPv4 address returned by DNS server for all A-record queries"`
	Revoke    bool     `short:"o" long:"revoke" description:"Revoke the certificate after obtaining it"`
	Domains   []string `short:"d" long:"domain" description:"the domain for which request the certificate"`
}

func main() {
	var opts Options

	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		log.Fatal(err)
	}
	flag.Parse()

	opts.Challenge = flag.Args()[0]
	opts.Challenge = opts.Challenge[:len(opts.Challenge)-2] + "-" + opts.Challenge[len(opts.Challenge)-2:]

	go StartServer()
	go StartDns(opts.Record)
	go StartClient(opts.Challenge, opts.Revoke, opts.Dir, opts.Domains)
	StartShutDownServer()
}
