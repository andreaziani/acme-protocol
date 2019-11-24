package dns

import (
	"io/ioutil"
	"net"
	"strconv"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	base = "/builds/COURSE-NETSEC-ACME-AS-2019/aziani-acme-project-netsec-fall-19/src/"
)

var domainsToAddresses string

type handler struct{}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	switch r.Question[0].Qtype {

	case dns.TypeA:
		log.Info("DNS server response to type A query")
		msg.Authoritative = true
		domain := msg.Question[0].Name

		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(domainsToAddresses),
		})

	case dns.TypeAAAA:
		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP(domainsToAddresses),
		})

	case dns.TypeTXT:
		log.Info("DNS server response to type TXT query")
		domain := msg.Question[0].Name

		var txt []string
		dat, err := ioutil.ReadFile(base + domain[:len(domain)-1])
		if err == nil {
			txt = append(txt, string(dat))
		}
		dat, err = ioutil.ReadFile(base + "w" + domain[:len(domain)-1])

		if err == nil {
			txt = append(txt, string(dat))
		}
		log.Info(txt)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: txt[:],
		})
	}
	_ = w.WriteMsg(&msg)
	//log.Info(msg)
}

func addDomainAddress(ip string) {
	domainsToAddresses = ip
}

func StartDns(ip string) {
	addDomainAddress(ip)
	srv := &dns.Server{Addr: "0.0.0.0:" + strconv.Itoa(10053), Net: "udp"}
	srv.Handler = &handler{}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set udp listener %s\n", err.Error())
	}
}
