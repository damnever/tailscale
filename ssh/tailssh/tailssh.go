// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

// Package tailssh is an SSH server integrated into Tailscale.
package tailssh

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/ssh"
	"inet.af/netaddr"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// TODO(bradfitz): this is all very temporary as code is temporarily
// being moved around; it will be restructured and documented in
// following commits.

// Handle handles an SSH connection from c.
func Handle(logf logger.Logf, lb *ipnlocal.LocalBackend, c net.Conn) error {
	tsd, err := os.Executable()
	if err != nil {
		return err
	}
	srv := &server{
		lb:             lb,
		logf:           logf,
		tailscaledPath: tsd,
	}
	ss, err := srv.newSSHServer()
	if err != nil {
		return err
	}
	ss.HandleConn(c)
	return nil
}

func (srv *server) newSSHServer() (*ssh.Server, error) {
	ss := &ssh.Server{
		Handler:           srv.handleSSH,
		RequestHandlers:   map[string]ssh.RequestHandler{},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{},
		// Note: the direct-tcpip channel handler and LocalPortForwardingCallback
		// only adds support for forwarding ports from the local machine.
		// TODO(maisem/bradfitz): add remote port forwarding support.
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
		Version:                     "SSH-2.0-Tailscale",
		LocalPortForwardingCallback: srv.mayForwardLocalPortTo,
	}
	for k, v := range ssh.DefaultRequestHandlers {
		ss.RequestHandlers[k] = v
	}
	for k, v := range ssh.DefaultChannelHandlers {
		ss.ChannelHandlers[k] = v
	}
	for k, v := range ssh.DefaultSubsystemHandlers {
		ss.SubsystemHandlers[k] = v
	}
	keys, err := srv.lb.GetSSH_HostKeys()
	if err != nil {
		return nil, err
	}
	for _, signer := range keys {
		ss.AddHostKey(signer)
	}
	return ss, nil
}

type server struct {
	lb             *ipnlocal.LocalBackend
	logf           logger.Logf
	tailscaledPath string

	// mu protects activeSessions.
	mu                      sync.Mutex
	activeSessionByH        map[string]*sshSession // ssh.SessionID (DH H) => that session
	activeSessionBySharedID map[string]*sshSession // yyymmddThhmmss-XXXXX => session
}

var debugPolicyFile = envknob.String("TS_DEBUG_SSH_POLICY_FILE")

// mayForwardLocalPortTo reports whether the ctx should be allowed to port forward
// to the specified host and port.
// TODO(bradfitz/maisem): should we have more checks on host/port?
func (srv *server) mayForwardLocalPortTo(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
	ss, ok := srv.getSessionForContext(ctx)
	if !ok {
		return false
	}
	return ss.action.AllowLocalPortForwarding
}

// sshPolicy returns the SSHPolicy for current node.
// If there is no SSHPolicy in the netmap, it returns a debugPolicy
// if one is defined.
func (srv *server) sshPolicy() (_ *tailcfg.SSHPolicy, ok bool) {
	lb := srv.lb
	nm := lb.NetMap()
	if nm == nil {
		return nil, false
	}
	if pol := nm.SSHPolicy; pol != nil {
		return pol, true
	}
	if debugPolicyFile != "" {
		f, err := os.ReadFile(debugPolicyFile)
		if err != nil {
			srv.logf("error reading debug SSH policy file: %v", err)
			return nil, false
		}
		p := new(tailcfg.SSHPolicy)
		if err := json.Unmarshal(f, p); err != nil {
			srv.logf("invalid JSON in %v: %v", debugPolicyFile, err)
			return nil, false
		}
		return p, true
	}
	return nil, false
}

func asTailscaleIPPort(a net.Addr) (netaddr.IPPort, error) {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netaddr.IPPort{}, fmt.Errorf("non-TCP addr %T %v", a, a)
	}
	tanetaddr, ok := netaddr.FromStdIP(ta.IP)
	if !ok {
		return netaddr.IPPort{}, fmt.Errorf("unparseable addr %v", ta.IP)
	}
	if !tsaddr.IsTailscaleIP(tanetaddr) {
		return netaddr.IPPort{}, fmt.Errorf("non-Tailscale addr %v", ta.IP)
	}
	return netaddr.IPPortFrom(tanetaddr, uint16(ta.Port)), nil
}

// evaluatePolicy returns the SSHAction, sshConnInfo and localUser
// after evaluating the sshUser and remoteAddr against the SSHPolicy.
// The remoteAddr and localAddr params must be Tailscale IPs.
func (srv *server) evaluatePolicy(sshUser string, localAddr, remoteAddr net.Addr) (_ *tailcfg.SSHAction, _ *sshConnInfo, localUser string, _ error) {
	logf := srv.logf
	lb := srv.lb
	logf("Handling SSH from %v for user %v", remoteAddr, sshUser)

	pol, ok := srv.sshPolicy()
	if !ok {
		return nil, nil, "", fmt.Errorf("tsshd: rejecting connection; no SSH policy")
	}

	srcIPP, err := asTailscaleIPPort(remoteAddr)
	if err != nil {
		return nil, nil, "", fmt.Errorf("tsshd: rejecting: %w", err)
	}
	dstIPP, err := asTailscaleIPPort(localAddr)
	if err != nil {
		return nil, nil, "", err
	}
	node, uprof, ok := lb.WhoIs(srcIPP)
	if !ok {
		return nil, nil, "", fmt.Errorf("Hello, %v. I don't know who you are.\n", srcIPP)
	}

	ci := &sshConnInfo{
		now:     time.Now(),
		sshUser: sshUser,
		src:     srcIPP,
		dst:     dstIPP,
		node:    node,
		uprof:   &uprof,
	}
	a, localUser, ok := evalSSHPolicy(pol, ci)
	if !ok {
		return nil, nil, "", fmt.Errorf("ssh: access denied for %q from %v", uprof.LoginName, ci.src.IP())
	}
	return a, ci, localUser, nil
}

// handleSSH is invoked when a new SSH connection attempt is made.
func (srv *server) handleSSH(s ssh.Session) {
	logf := srv.logf

	sshUser := s.User()
	action, ci, localUser, err := srv.evaluatePolicy(sshUser, s.LocalAddr(), s.RemoteAddr())
	if err != nil {
		logf(err.Error())
		s.Exit(1)
		return
	}

	// Loop processing/fetching Actions until one reaches a
	// terminal state (Accept, Reject, or invalid Action), or
	// until fetchSSHAction times out due to the context being
	// done (client disconnect) or its 30 minute timeout passes.
	// (Which is a long time for somebody to see login
	// instructions and go to a URL to do something.)
ProcessAction:
	for {
		if action.Message != "" {
			io.WriteString(s.Stderr(), strings.Replace(action.Message, "\n", "\r\n", -1))
		}
		if action.Reject {
			logf("ssh: access denied for %q from %v", ci.uprof.LoginName, ci.src.IP())
			s.Exit(1)
			return
		}
		if action.Accept {
			break ProcessAction
		}
		url := action.HoldAndDelegate
		if url == "" {
			logf("ssh: access denied; SSHAction has neither Reject, Accept, or next step URL")
			s.Exit(1)
			return
		}
		action, err = srv.fetchSSHAction(s.Context(), url)
		if err != nil {
			logf("ssh: fetching SSAction from %s: %v", url, err)
			s.Exit(1)
			return
		}
	}

	lu, err := user.Lookup(localUser)
	if err != nil {
		logf("ssh: user Lookup %q: %v", localUser, err)
		s.Exit(1)
		return
	}

	ss := srv.newSSHSession(s, ci, lu, action)
	ss.run()
}

// sshSession is an accepted Tailscale SSH session.
type sshSession struct {
	ssh.Session
	idH      string // the RFC4253 sec8 hash H; don't share outside process
	sharedID string // ID that's shared with control
	logf     logger.Logf

	ctx           *sshContext // implements context.Context
	srv           *server
	connInfo      *sshConnInfo
	action        *tailcfg.SSHAction
	localUser     *user.User
	agentListener net.Listener // non-nil if agent-forwarding requested+allowed

	// initialized by launchProcess:
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.Reader
	stderr io.Reader // nil for pty sessions
	ptyReq *ssh.Pty  // non-nil for pty sessions

	// We use this sync.Once to ensure that we only terminate the process once,
	// either it exits itself or is terminated
	exitOnce sync.Once
}

func (srv *server) newSSHSession(s ssh.Session, ci *sshConnInfo, lu *user.User, action *tailcfg.SSHAction) *sshSession {
	sharedID := fmt.Sprintf("%s-%02x", ci.now.UTC().Format("20060102T150405"), randBytes(5))
	return &sshSession{
		Session:   s,
		idH:       s.Context().(ssh.Context).SessionID(),
		sharedID:  sharedID,
		ctx:       newSSHContext(),
		srv:       srv,
		action:    action,
		localUser: lu,
		connInfo:  ci,
		logf:      logger.WithPrefix(srv.logf, "ssh-session("+sharedID+"): "),
	}
}

func (srv *server) fetchSSHAction(ctx context.Context, url string) (*tailcfg.SSHAction, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	bo := backoff.NewBackoff("fetch-ssh-action", srv.logf, 10*time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		res, err := srv.lb.DoNoiseRequest(req)
		if err != nil {
			bo.BackOff(ctx, err)
			continue
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			bo.BackOff(ctx, fmt.Errorf("unexpected status: %v", res.Status))
			continue
		}
		a := new(tailcfg.SSHAction)
		if err := json.NewDecoder(res.Body).Decode(a); err != nil {
			bo.BackOff(ctx, err)
			continue
		}
		return a, nil
	}
}

// killProcessOnContextDone waits for ss.ctx to be done and kills the process,
// unless the process has already exited.
func (ss *sshSession) killProcessOnContextDone() {
	<-ss.ctx.Done()
	// Either the process has already existed, in which case this does nothing.
	// Or, the process is still running in which case this will kill it.
	ss.exitOnce.Do(func() {
		err := ss.ctx.Err()
		if serr, ok := err.(SSHTerminationError); ok {
			msg := serr.SSHTerminationMessage()
			if msg != "" {
				io.WriteString(ss.Stderr(), "\r\n\r\n"+msg+"\r\n\r\n")
			}
		}
		ss.logf("terminating SSH session from %v: %v", ss.connInfo.src.IP(), err)
		ss.cmd.Process.Kill()
	})
}

// sessionAction returns the SSHAction associated with the session.
func (srv *server) getSessionForContext(sctx ssh.Context) (ss *sshSession, ok bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	ss, ok = srv.activeSessionByH[sctx.SessionID()]
	return
}

// startSession registers ss as an active session.
func (srv *server) startSession(ss *sshSession) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.activeSessionByH == nil {
		srv.activeSessionByH = make(map[string]*sshSession)
	}
	if srv.activeSessionBySharedID == nil {
		srv.activeSessionBySharedID = make(map[string]*sshSession)
	}
	if ss.idH == "" {
		panic("empty idH")
	}
	if _, dup := srv.activeSessionByH[ss.idH]; dup {
		panic("dup idH")
	}
	if ss.sharedID == "" {
		panic("empty sharedID")
	}
	if _, dup := srv.activeSessionBySharedID[ss.sharedID]; dup {
		panic("dup sharedID")
	}
	srv.activeSessionByH[ss.idH] = ss
	srv.activeSessionBySharedID[ss.sharedID] = ss
}

// endSession unregisters s from the list of active sessions.
func (srv *server) endSession(ss *sshSession) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.activeSessionByH, ss.idH)
	delete(srv.activeSessionBySharedID, ss.sharedID)
}

var errSessionDone = errors.New("session is done")

// handleSSHAgentForwarding starts a Unix socket listener and in the background
// forwards agent connections between the listenr and the ssh.Session.
// On success, it assigns ss.agentListener.
func (ss *sshSession) handleSSHAgentForwarding(s ssh.Session, lu *user.User) error {
	if !ssh.AgentRequested(ss) || !ss.action.AllowAgentForwarding {
		return nil
	}
	ss.logf("ssh: agent forwarding requested")
	ln, err := ssh.NewAgentListener()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && ln != nil {
			ln.Close()
		}
	}()

	uid, err := strconv.ParseUint(lu.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(lu.Gid, 10, 32)
	if err != nil {
		return err
	}
	socket := ln.Addr().String()
	dir := filepath.Dir(socket)
	// Make sure the socket is accessible by the user.
	if err := os.Chown(socket, int(uid), int(gid)); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return err
	}

	go ssh.ForwardAgentConnections(ln, s)
	ss.agentListener = ln
	return nil
}

// run is the entrypoint for a newly accepted SSH session.
//
// When ctx is done, the session is forcefully terminated. If its Err
// is an SSHTerminationError, its SSHTerminationMessage is sent to the
// user.
func (ss *sshSession) run() {
	srv := ss.srv
	srv.startSession(ss)
	defer srv.endSession(ss)

	defer ss.ctx.CloseWithError(errSessionDone)

	if ss.action.SesssionDuration != 0 {
		t := time.AfterFunc(ss.action.SesssionDuration, func() {
			ss.ctx.CloseWithError(userVisibleError{
				fmt.Sprintf("Session timeout of %v elapsed.", ss.action.SesssionDuration),
				context.DeadlineExceeded,
			})
		})
		defer t.Stop()
	}

	logf := srv.logf
	lu := ss.localUser
	localUser := lu.Username

	if euid := os.Geteuid(); euid != 0 {
		if lu.Uid != fmt.Sprint(euid) {
			logf("ssh: can't switch to user %q from process euid %v", localUser, euid)
			fmt.Fprintf(ss, "can't switch user\n")
			ss.Exit(1)
			return
		}
	}

	// Take control of the PTY so that we can configure it below.
	// See https://github.com/tailscale/tailscale/issues/4146
	ss.DisablePTYEmulation()

	if err := ss.handleSSHAgentForwarding(ss, lu); err != nil {
		logf("ssh: agent forwarding failed: %v", err)
	} else if ss.agentListener != nil {
		// TODO(maisem/bradfitz): add a way to close all session resources
		defer ss.agentListener.Close()
	}
	err := ss.launchProcess(ss.ctx)
	if err != nil {
		logf("start failed: %v", err.Error())
		ss.Exit(1)
		return
	}
	go ss.killProcessOnContextDone()

	go func() {
		_, err := io.Copy(ss.stdin, ss)
		if err != nil {
			// TODO: don't log in the success case.
			logf("ssh: stdin copy: %v", err)
		}
		ss.stdin.Close()
	}()
	go func() {
		_, err := io.Copy(ss, ss.stdout)
		if err != nil {
			// TODO: don't log in the success case.
			logf("ssh: stdout copy: %v", err)
		}
	}()
	// stderr is nil for ptys.
	if ss.stderr != nil {
		go func() {
			_, err := io.Copy(ss.Stderr(), ss.stderr)
			if err != nil {
				// TODO: don't log in the success case.
				logf("ssh: stderr copy: %v", err)
			}
		}()
	}
	err = ss.cmd.Wait()
	// This will either make the SSH Termination goroutine be a no-op,
	// or itself will be a no-op because the process was killed by the
	// aforementioned goroutine.
	ss.exitOnce.Do(func() {})

	if err == nil {
		logf("ssh: Wait: ok")
		ss.Exit(0)
		return
	}
	if ee, ok := err.(*exec.ExitError); ok {
		code := ee.ProcessState.ExitCode()
		logf("ssh: Wait: code=%v", code)
		ss.Exit(code)
		return
	}

	logf("ssh: Wait: %v", err)
	ss.Exit(1)
	return
}

type sshConnInfo struct {
	// now is the time to consider the present moment for the
	// purposes of rule evaluation.
	now time.Time

	// sshUser is the requested local SSH username ("root", "alice", etc).
	sshUser string

	// src is the Tailscale IP and port that the connection came from.
	src netaddr.IPPort

	// dst is the Tailscale IP and port that the connection came for.
	dst netaddr.IPPort

	// node is srcIP's node.
	node *tailcfg.Node

	// uprof is node's UserProfile.
	uprof *tailcfg.UserProfile
}

func evalSSHPolicy(pol *tailcfg.SSHPolicy, ci *sshConnInfo) (a *tailcfg.SSHAction, localUser string, ok bool) {
	for _, r := range pol.Rules {
		if a, localUser, err := matchRule(r, ci); err == nil {
			return a, localUser, true
		}
	}
	return nil, "", false
}

// internal errors for testing; they don't escape to callers or logs.
var (
	errNilRule        = errors.New("nil rule")
	errNilAction      = errors.New("nil action")
	errRuleExpired    = errors.New("rule expired")
	errPrincipalMatch = errors.New("principal didn't match")
	errUserMatch      = errors.New("user didn't match")
)

func matchRule(r *tailcfg.SSHRule, ci *sshConnInfo) (a *tailcfg.SSHAction, localUser string, err error) {
	if r == nil {
		return nil, "", errNilRule
	}
	if r.Action == nil {
		return nil, "", errNilAction
	}
	if r.RuleExpires != nil && ci.now.After(*r.RuleExpires) {
		return nil, "", errRuleExpired
	}
	if !matchesPrincipal(r.Principals, ci) {
		return nil, "", errPrincipalMatch
	}
	if !r.Action.Reject || r.SSHUsers != nil {
		localUser = mapLocalUser(r.SSHUsers, ci.sshUser)
		if localUser == "" {
			return nil, "", errUserMatch
		}
	}
	return r.Action, localUser, nil
}

func mapLocalUser(ruleSSHUsers map[string]string, reqSSHUser string) (localUser string) {
	if v, ok := ruleSSHUsers[reqSSHUser]; ok {
		return v
	}
	return ruleSSHUsers["*"]
}

func matchesPrincipal(ps []*tailcfg.SSHPrincipal, ci *sshConnInfo) bool {
	for _, p := range ps {
		if p == nil {
			continue
		}
		if p.Any {
			return true
		}
		if !p.Node.IsZero() && ci.node != nil && p.Node == ci.node.StableID {
			return true
		}
		if p.NodeIP != "" {
			if ip, _ := netaddr.ParseIP(p.NodeIP); ip == ci.src.IP() {
				return true
			}
		}
		if p.UserLogin != "" && ci.uprof != nil && ci.uprof.LoginName == p.UserLogin {
			return true
		}
	}
	return false
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
