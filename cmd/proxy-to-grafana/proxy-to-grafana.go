// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// proxy-to-grafana uses a reverse proxy which identifies users based on their
// originating Tailscale node and creates / logs in users to grafana. Uses the
// auth proxy feature for Grafana:
// https://grafana.com/docs/grafana/latest/auth/auth-proxy/
//
// Provide the env var TS_AUTHKEY to have this server automatically join your
// tailnet, or look for the logged auth link on first start.
//
// Use this Grafana configuration to enable the auth proxy:
//
// ```
// [auth.proxy]
// enabled = true
// header_name = X-WEBAUTH-USER
// header_property = username
// auto_sign_up = true
// whitelist = 127.0.0.1
// headers = Name:X-WEBAUTH-NAME
// enable_login_token = true
// ```
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/client/tailscale"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

var (
	hostname     = flag.String("hostname", "", "Tailscale hostname to serve on")
	backendAddr  = flag.String("backend-addr", "", "Address of the Grafana server, in host:port format")
	tailscaleDir = flag.String("state-dir", "./", "Alternate directory to use for Tailscale state storage. If empty, a default is used.")
)

func main() {
	flag.Parse()
	if *hostname == "" || strings.Contains(*hostname, ".") {
		log.Fatal("missing or invalid --hostname")
	}
	if *backendAddr == "" {
		log.Fatal("missing --backend-addr")
	}
	ts := &tsnet.Server{
		Dir:      *tailscaleDir,
		Hostname: *hostname,
	}

	url, err := url.Parse(fmt.Sprintf("http://%s", *backendAddr))
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		modifyRequest(req)
	}

	ltsn, err := ts.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving access to %s on port 80", *backendAddr)
	log.Fatal(http.Serve(ltsn, ProxyRequestHandler(proxy)))
}

func ProxyRequestHandler(proxy *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
}

func modifyRequest(req *http.Request) {
	// with enable_login_token set to true, we get a cookie that handles
	// auth for paths that are not /login
	if req.URL.Path != "/login" {
		return
	}

	ipp, err := netaddr.ParseIPPort(req.RemoteAddr)
	if err != nil {
		log.Printf("bad remote address")
		return
	}
	if !tsaddr.IsTailscaleIP(ipp.IP()) {
		log.Printf("not a tailscale IP")
		return
	}
	user, err := getTailscaleUser(req.Context(), req.RemoteAddr)
	if err != nil {
		log.Printf("error getting Tailscale user: %v", err)
		return
	}
	// try to make these emails not collide with real users if any
	email := strings.Replace(user.LoginName, "@", "-auto@", 1)
	req.Header.Set("X-Webauth-User", email)
	req.Header.Set("X-Webauth-Name", user.DisplayName)
}

func getTailscaleUser(ctx context.Context, ip string) (*tailcfg.UserProfile, error) {
	whois, err := tailscale.WhoIs(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("failed to identify remote host: %w", err)
	}
	if len(whois.Node.Tags) != 0 {
		return nil, fmt.Errorf("tagged nodes are not users")
	}
	if whois.UserProfile == nil || whois.UserProfile.LoginName == "" {
		return nil, fmt.Errorf("failed to identify remote user")
	}

	return whois.UserProfile, nil
}
