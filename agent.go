package main

import (
	"flag"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/request"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net"
	"os"
)

var address string
var network string
var debugLevel bool

const certProp = "cert"
const ipProp = "ip"
const messageName = "check-client-tls-info"

func init() {
	flag.StringVar(&address, "a", "127.0.0.1:3000", "spoe agent listen address.")
	flag.StringVar(&network, "n", "tcp", "spoe agent listen network type.")
	flag.BoolVar(&debugLevel, "d", false, "enable debug logs")
	flag.Parse()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if debugLevel {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

}

func main() {

	log.Info().Str("net", network).Str("address", address).
		Msg("Start HAProxy SPOA.")

	listener, err := net.Listen(network, address)
	if err != nil {
		log.Printf("error create listener, %v", err)
		os.Exit(1)
	}
	defer listener.Close()

	a := agent.New(handler)

	if err := a.Serve(listener); err != nil {
		log.Printf("error agent serve: %+v\n", err)
	}
}

func handler(req *request.Request) {

	log.Info().Msgf("handle request EngineID: '%s', StreamID: '%d', FrameID: '%d' with %d messages\n", req.EngineID, req.StreamID, req.FrameID, req.Messages.Len())

	mes, err := req.Messages.GetByName(messageName)
	if err != nil {
		log.Printf("message %s not found: %v", messageName, err)
		return
	}

	ipValue, _ := mes.KV.Get(ipProp)
	cert, _ := mes.KV.Get(certProp)

	log.Debug().Msgf("var 'ip' not found in message: %s [%s]", ipValue, cert)
	req.Actions.SetVar(action.ScopeSession, "st", true)
}
