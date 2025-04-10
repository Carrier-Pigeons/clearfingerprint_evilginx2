package goproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

// ProxyCtx is the Proxy context, contains useful information about every request. It is passed to
// every user function. Also used as a logger.
type ProxyCtx struct {
	// Will contain the client request from the proxy
	Req *http.Request
	// Will contain the remote server's response (if available. nil if the request wasn't send yet)
	Resp         *http.Response
	RoundTripper RoundTripper
	// will contain the recent error that occurred while trying to send receive or parse traffic
	Error error
	// A handle for the user to keep data in the context, from the call of ReqHandler to the
	// call of RespHandler
	UserData interface{}
	// Will connect a request to a response
	Session   int64
	certStore CertStorage
	Proxy     *ProxyHttpServer
}

type RoundTripper interface {
	RoundTrip(req *http.Request, ctx *ProxyCtx) (*http.Response, error)
}

type CertStorage interface {
	Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error)
}

type RoundTripperFunc func(req *http.Request, ctx *ProxyCtx) (*http.Response, error)

func (f RoundTripperFunc) RoundTrip(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {
	return f(req, ctx)
}

func (ctx *ProxyCtx) RoundTrip(req *http.Request) (*http.Response, error) {
	// if ctx.RoundTripper != nil {
	// 	return ctx.RoundTripper.RoundTrip(req, ctx)
	// }
	// return ctx.Proxy.Tr.RoundTrip(req)

	return sendRequestManually(req)
}

// This function sends the headers in unpredictable order each time, as the Request.Header map returns the keys in an unpredictable order each time, even when logging them. The function solves the problem of the Transport.RoundTime function alphabetizing the headers.
func sendRequestManually(req *http.Request) (*http.Response, error) {

	// Host header is not yet set.
	req.Header.Set("Host", req.URL.Hostname())
	// Ensure the host includes the port
	if !strings.Contains(req.URL.Host, ":") {
		if req.URL.Scheme == "https" {
			req.URL.Host += ":443"
		} else {
			req.URL.Host += ":80"
		}
	}

	log.Debug("Request URL: %s", req.URL.String())
	// log.Debug("Request Headers: %s", headersToString(req.Header))	// The headers cannot be logged in the same order they are sent. Use this log only to validate which headers exist.
	var conn net.Conn
	var err error

	// Check if the request is HTTPS
	if req.URL.Scheme == "https" {
		conn, err = tls.Dial("tcp", req.URL.Host, &tls.Config{})
	} else {
		conn, err = net.Dial("tcp", req.URL.Host)
	}

	if err != nil {
		return nil, err
	}

	// We do not close the connection, otherwise we cannot navigate the page after the first request.
	// defer conn.Close()

	// Write the request manually
	fmt.Fprintf(conn, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Fprintf(conn, "%s: %s\r\n", name, value)
		}
	}
	fmt.Fprint(conn, "\r\n")

	// Read the response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Debug("Error reading response: %v", err)
		return nil, err
	}

	log.Debug("Response Status: %s", resp.Status)
	return resp, nil
}

// Note that this function does not return headers in order. The http.Header map does not guarantee order when iterating through its keys.
func headersToString(headers http.Header) string {
	var sb strings.Builder
	for name, values := range headers {
		for _, value := range values {
			sb.WriteString(fmt.Sprintf("%s: %s\n", name, value))
		}
	}
	return sb.String()
}

func (ctx *ProxyCtx) printf(msg string, argv ...interface{}) {
	ctx.Proxy.Logger.Printf("[%03d] "+msg+"\n", append([]interface{}{ctx.Session & 0xFF}, argv...)...)
}

// Logf prints a message to the proxy's log. Should be used in a ProxyHttpServer's filter
// This message will be printed only if the Verbose field of the ProxyHttpServer is set to true
//
//	proxy.OnRequest().DoFunc(func(r *http.Request,ctx *goproxy.ProxyCtx) (*http.Request, *http.Response){
//		nr := atomic.AddInt32(&counter,1)
//		ctx.Printf("So far %d requests",nr)
//		return r, nil
//	})
func (ctx *ProxyCtx) Logf(msg string, argv ...interface{}) {
	if ctx.Proxy.Verbose {
		ctx.printf("INFO: "+msg, argv...)
	}
}

// Warnf prints a message to the proxy's log. Should be used in a ProxyHttpServer's filter
// This message will always be printed.
//
//	proxy.OnRequest().DoFunc(func(r *http.Request,ctx *goproxy.ProxyCtx) (*http.Request, *http.Response){
//		f,err := os.OpenFile(cachedContent)
//		if err != nil {
//			ctx.Warnf("error open file %v: %v",cachedContent,err)
//			return r, nil
//		}
//		return r, nil
//	})
func (ctx *ProxyCtx) Warnf(msg string, argv ...interface{}) {
	ctx.printf("WARN: "+msg, argv...)
}

var charsetFinder = regexp.MustCompile("charset=([^ ;]*)")

// Will try to infer the character set of the request from the headers.
// Returns the empty string if we don't know which character set it used.
// Currently it will look for charset=<charset> in the Content-Type header of the request.
func (ctx *ProxyCtx) Charset() string {
	charsets := charsetFinder.FindStringSubmatch(ctx.Resp.Header.Get("Content-Type"))
	if charsets == nil {
		return ""
	}
	return charsets[1]
}
