// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package prober implements a simple blackbox prober. Each probe runs
// in its own goroutine, and run results are recorded as Prometheus
// metrics.
package prober

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"tailscale.com/metrics"
)

// Probe is a function that probes something and reports whether the
// probe succeeded. The provided context must be used to ensure timely
// cancellation and timeout behavior.
type Probe func(context.Context) error

// a Prober manages a set of probes and keeps track of their results.
type Prober struct {
	// Maps are keyed by probe name
	lastStart     metrics.LabelMap
	lastEnd       metrics.LabelMap
	lastResult    metrics.LabelMap
	lastLatency   metrics.LabelMap
	alertDuration metrics.LabelMap

	mu     sync.Mutex // protects all following fields
	probes map[string]chan struct{}
}

// New returns a new Prober.
func New() *Prober {
	return &Prober{
		lastStart:     metrics.LabelMap{Label: "probe"},
		lastEnd:       metrics.LabelMap{Label: "probe"},
		lastResult:    metrics.LabelMap{Label: "probe"},
		lastLatency:   metrics.LabelMap{Label: "probe"},
		alertDuration: metrics.LabelMap{Label: "probe"},
		probes:        map[string]chan struct{}{},
	}
}

// Expvar returns the metrics for running probes.
func (p *Prober) Expvar() *metrics.Set {
	ret := new(metrics.Set)
	ret.Set("start_secs", &p.lastStart)
	ret.Set("end_secs", &p.lastEnd)
	ret.Set("result", &p.lastResult)
	ret.Set("latency_millis", &p.lastLatency)
	ret.Set("suggested_alert_secs", &p.alertDuration)
	return ret
}

// Run executes fun every interval, and exports probe results under probeName.
//
// fun is given a context.Context that, if obeyed, ensures that fun
// ends within interval. If fun disregards the context, it will not be
// run again until it does finish, and metrics will reflect that the
// probe function is stuck.
//
// Run returns a context.CancelFunc that stops the probe when
// invoked. Probe shutdown and removal happens-before the CancelFunc
// returns.
//
// Registering a probe under an already-registered name panics.
func (p *Prober) Run(name string, interval time.Duration, fun Probe) context.CancelFunc {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.registerLocked(name, interval)

	ctx, cancel := context.WithCancel(context.Background())
	go p.probeLoop(ctx, name, interval, fun)

	return func() {
		p.mu.Lock()
		stopped := p.probes[name]
		p.mu.Unlock()
		cancel()
		<-stopped
	}
}

func (p *Prober) probeLoop(ctx context.Context, name string, interval time.Duration, fun Probe) {
	tick := time.NewTicker(interval)
	defer func() {
		p.unregister(name)
		tick.Stop()
	}()

	for {
		select {
		case <-tick.C:
			p.runProbe(ctx, name, interval, fun)
		case <-ctx.Done():
			return
		}
	}
}

func (p *Prober) runProbe(ctx context.Context, name string, interval time.Duration, fun Probe) {
	start := p.start(name)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("probe %s panicked: %v", name, r)
			p.end(name, start, errors.New("panic"))
		}
	}()
	timeout := time.Duration(float64(interval) * 0.8)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := fun(ctx)
	p.end(name, start, err)
	if err != nil {
		log.Printf("probe %s: %v", name, err)
	}
}

func (p *Prober) registerLocked(name string, interval time.Duration) {
	if _, ok := p.probes[name]; ok {
		panic(fmt.Sprintf("probe named %q already registered", name))
	}

	stoppedCh := make(chan struct{})
	p.probes[name] = stoppedCh
	p.alertDuration.Get(name).Set(int64(interval.Seconds() * 4))
}

func (p *Prober) unregister(name string) {
	// Unregister the probe, since this loop only exits when the
	// probe is deleted.
	p.mu.Lock()
	defer p.mu.Unlock()
	close(p.probes[name])
	delete(p.probes, name)
	p.lastStart.Delete(name)
	p.lastEnd.Delete(name)
	p.lastResult.Delete(name)
	p.lastLatency.Delete(name)
	p.alertDuration.Delete(name)
}

func (p *Prober) start(name string) time.Time {
	st := time.Now()
	p.lastStart.Get(name).Set(st.Unix())
	return st
}

func (p *Prober) end(name string, start time.Time, err error) {
	end := time.Now()
	p.lastEnd.Get(name).Set(end.Unix())
	p.lastLatency.Get(name).Set(end.Sub(start).Milliseconds())
	v := int64(1)
	if err != nil {
		v = 0
	}
	p.lastResult.Get(name).Set(v)
}
