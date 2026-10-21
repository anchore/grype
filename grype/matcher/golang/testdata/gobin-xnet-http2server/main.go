// Command xnet-http2server is a test fixture: a Go program that runs a
// golang.org/x/net/http2 server. It references http2.(*Server).ServeConn, which
// GO-2022-0969 lists as vulnerable for golang.org/x/net, so the compiled binary
// carries that symbol and must MATCH the x/net advisory.
package main

import (
	"net"

	"golang.org/x/net/http2"
)

func main() {
	srv := &http2.Server{}
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return
	}
	c, err := l.Accept()
	if err != nil {
		return
	}
	// vulnerable server entrypoint: golang.org/x/net/http2.(*Server).ServeConn
	srv.ServeConn(c, &http2.ServeConnOpts{})
}
