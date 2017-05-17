/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"

	"golang.org/x/crypto/ssh"
)

// A Dialer is a means for a client to establish a SSH connection.
type Dialer interface {
	// Dial establishes a client connection to a SSH server.
	Dial(network string, addr string, config *ssh.ClientConfig) (*ssh.Client, error)
}

type directDial struct{}

// Dial calls ssh.Dial directly.
func (d directDial) Dial(network string, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial(network, addr, config)
}

type proxyDial struct {
	proxyHost string
}

// Dial first connects to a proxy, then uses the connection to establish a new
// SSH connection.
func (d proxyDial) Dial(network string, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	// build a proxy connection first
	pconn, err := dialProxy(d.proxyHost, addr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// do the same as ssh.Dial but pass in proxy connection
	c, chans, reqs, err := ssh.NewClientConn(pconn, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// DialerFromEnvironment returns a Dial function. If the https_proxy or http_proxy
// environment variable are set, it returns a function that will dial through
// said proxy server. If neither variable is set, it will connect to the SSH
// server directly.
func DialerFromEnvironment() Dialer {
	// try and get proxy addr from the environment
	proxyAddr := getProxyAddress()

	// if no proxy settings are in environment return regular ssh dialer,
	// otherwise return a proxy dialer
	if proxyAddr == "" {
		return directDial{}
	}
	return proxyDial{proxyHost: proxyAddr}
}

func dialProxy(proxyAddr string, addr string) (net.Conn, error) {
	ctx := context.Background()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	err = connectReq.Write(conn)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		return nil, trace.Wrap(err)
	}
	if resp.StatusCode != http.StatusOK {
		f := strings.SplitN(resp.Status, " ", 2)
		conn.Close()
		return nil, trace.BadParameter("Unable to proxy connection, StatusCode %v: %v", resp.StatusCode, f[1])
	}

	return conn, nil
}

func getProxyAddress() string {
	envs := []string{
		teleport.HTTPSProxy,
		strings.ToLower(teleport.HTTPSProxy),
		teleport.HTTPProxy,
		strings.ToLower(teleport.HTTPProxy),
	}

	for _, v := range envs {
		addr := os.Getenv(v)
		if addr != "" {
			return addr
		}
	}

	return ""
}
