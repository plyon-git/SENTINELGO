// Copyright (c) 2026 Parrish Lyon. All rights reserved.
// SENTINELGO | Parrish Lyon | PL-SENTINELGO-20260914
// Go adaptation of the supplied generator credited to Ledgewell Data Team.
package sentinelgo

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"math/rand"
	"strconv"
	"time"
)

type GenerateOptions struct {
	Rows   int
	Seed   int64
	End    time.Time
	Labels bool
}
type GenerationSummary struct {
	Rows             int           `json:"rows"`
	LabeledFraudRows int           `json:"labeled_fraud_rows"`
	InjectionTarget  float64       `json:"injection_target"`
	Seed             int64         `json:"seed"`
	Identity         BuildIdentity `json:"identity"`
}
type syntheticOrder struct {
	values [10]string
	fraud  bool
}
type profile struct {
	id, country, device, domain, prefix string
	average                             float64
	fraud                               bool
}
type choice struct {
	s string
	w float64
}

var countries = []choice{{"US", .35}, {"GB", .08}, {"DE", .07}, {"FR", .06}, {"JP", .05}, {"AU", .04}, {"CA", .04}, {"BR", .03}, {"IN", .03}, {"NL", .02}, {"SE", .02}, {"SG", .02}, {"IT", .02}, {"ES", .02}, {"MX", .02}, {"other", .13}}
var deviceChoices = []choice{{"iPhone; CPU iPhone OS 17_2", .25}, {"Android 14", .30}, {"Windows NT 10.0", .25}, {"Macintosh; Intel Mac OS X 10_15_7", .10}, {"iPad; CPU OS 17_2", .05}, {"Linux x86_64", .05}}
var domains = []choice{{"gmail.com", .45}, {"yahoo.com", .12}, {"outlook.com", .10}, {"icloud.com", .08}, {"protonmail.com", .03}, {"hotmail.com", .05}, {"aol.com", .02}, {"live.com", .03}, {"company.com", .07}, {"other", .05}}

type generator struct {
	r            *rand.Rand
	end          time.Time
	profiles     []profile
	legit, fraud []int
}

func (g *generator) pick(c []choice) string {
	total := 0.0
	for _, v := range c {
		total += v.w
	}
	x := g.r.Float64() * total
	for _, v := range c {
		x -= v.w
		if x < 0 {
			return v.s
		}
	}
	return c[len(c)-1].s
}
func (g *generator) between(a, b int) int { return a + g.r.Intn(b-a+1) }
func (g *generator) timestamp() time.Time {
	t := g.end.Add(-90 * 24 * time.Hour).Add(time.Duration(g.r.Int63n(90*24*3600+1)) * time.Second)
	if t.Hour() >= 2 && t.Hour() <= 7 && g.r.Float64() > .3 {
		t = t.Add(time.Duration(g.between(1, 6)) * time.Hour)
	}
	if t.After(g.end) {
		return g.end
	}
	return t
}
func (g *generator) card() string {
	b := make([]byte, 32)
	_, _ = g.r.Read(b)
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:6])
}
func (g *generator) ip(fraud bool) string {
	if fraud && g.r.Float64() < .4 {
		p := []string{"104.16.", "172.64.", "185.222.", "198.54.", "45.138.", "76.76."}
		return fmt.Sprintf("%s%d.%d", p[g.r.Intn(len(p))], g.between(1, 254), g.between(1, 254))
	}
	if g.r.Float64() < .7 {
		return fmt.Sprintf("192.168.%d.%d", g.between(1, 254), g.between(1, 254))
	}
	return fmt.Sprintf("203.0.113.%d", g.between(1, 254))
}
func (g *generator) order(p profile, fraud bool) syntheticOrder {
	value := math.Max(1, p.average+g.r.NormFloat64()*p.average*.3)
	if fraud {
		value = math.Max(50, p.average*(1.5+g.r.Float64()*3.5))
	}
	device := p.device
	if g.r.Float64() >= .85 {
		device = g.pick(deviceChoices)
	}
	ip := p.prefix + strconv.Itoa(g.between(1, 254))
	if fraud && g.r.Float64() < .5 {
		ip = g.ip(true)
	} else if g.r.Float64() >= .8 {
		ip = g.ip(false)
	}
	email := p.id[5:] + "@" + p.domain
	if fraud && g.r.Float64() < .15 {
		domain := g.pick(domains)
		if g.r.Float64() < .2 {
			domain = "mailinator.com"
		}
		if domain == "other" {
			domain = "example.com"
		}
		email = p.id + "@" + domain
	}
	cats := []string{"ELEC", "CLTH", "HOME", "SPRT", "BOOK", "TOYS"}
	return syntheticOrder{[10]string{"", g.timestamp().Format("2006-01-02 15:04:05"), p.id, fmt.Sprintf("%.2f", value), ip, g.card(), fmt.Sprintf("%s-%d", cats[g.r.Intn(len(cats))], g.between(1000, 9999)), p.country, device, email}, fraud}
}

// Generate preserves the source injection-and-sampling design. The 1.8% target
// is an injection-pool share, not a promise of a measured 1.8% fraud-label rate.
func Generate(ctx context.Context, w io.Writer, o GenerateOptions) (GenerationSummary, error) {
	summary := GenerationSummary{Rows: o.Rows, InjectionTarget: .018, Seed: o.Seed, Identity: Identity()}
	if o.Rows < 1 || o.Rows > 1000000 {
		return summary, fmt.Errorf("rows must be 1..1000000")
	}
	if o.End.IsZero() {
		return summary, fmt.Errorf("end timestamp is required")
	}
	g := generator{r: rand.New(rand.NewSource(o.Seed)), end: o.End.UTC()}
	for i := 1; i <= 2000; i++ {
		p := profile{id: fmt.Sprintf("user_%04d", i), country: g.pick(countries), device: g.pick(deviceChoices), domain: g.pick(domains), prefix: fmt.Sprintf("192.168.%d.", g.between(1, 254)), average: math.Exp(4 + g.r.NormFloat64()*1.2), fraud: g.r.Float64() < .01}
		if p.domain == "other" {
			p.domain = fmt.Sprintf("company%d.example", g.between(1, 50))
		}
		g.profiles = append(g.profiles, p)
		if p.fraud {
			g.fraud = append(g.fraud, i-1)
		} else {
			g.legit = append(g.legit, i-1)
		}
	}
	if len(g.fraud) == 0 {
		g.fraud = []int{0}
	}
	if len(g.legit) == 0 {
		g.legit = []int{1}
	}
	orders := make([]syntheticOrder, 0, o.Rows)
	legitCount := int(float64(o.Rows) * (1 - .018))
	fraudCount := o.Rows - legitCount
	for i := 0; i < legitCount; i++ {
		if i%1024 == 0 {
			if e := ctx.Err(); e != nil {
				return summary, e
			}
		}
		orders = append(orders, g.order(g.profiles[g.r.Intn(2000)], false))
	}
	injected := []syntheticOrder{}
	for k := 0; k < int(float64(fraudCount)*.25); k++ {
		card := g.card()
		base := g.timestamp().Add(-5 * time.Minute)
		count := g.between(5, 12)
		for j := 0; j < count; j++ {
			o := g.order(g.profiles[g.r.Intn(2000)], true)
			o.values[1] = base.Add(time.Duration(g.between(1, 5)) * time.Minute).Format("2006-01-02 15:04:05")
			o.values[3] = fmt.Sprintf("%.2f", 1+g.r.Float64()*14)
			o.values[5] = card
			o.values[4] = g.ip(true)
			injected = append(injected, o)
		}
	}
	for k := 0; k < int(float64(fraudCount)*.30); k++ {
		p := g.profiles[g.legit[g.r.Intn(len(g.legit))]]
		t := g.timestamp().Add(-30 * time.Minute)
		a, b := g.order(p, false), g.order(p, true)
		a.values[1] = t.Format("2006-01-02 15:04:05")
		b.values[1] = t.Add(time.Duration(g.between(5, 30)) * time.Minute).Format("2006-01-02 15:04:05")
		b.values[4] = g.ip(true)
		b.values[8] = g.pick(deviceChoices)
		b.values[3] = fmt.Sprintf("%.2f", p.average*(2+g.r.Float64()*2))
		injected = append(injected, a, b)
	}
	for k := 0; k < int(float64(fraudCount)*.20); k++ {
		p := g.profiles[g.fraud[g.r.Intn(len(g.fraud))]]
		o := g.order(p, true)
		o.values[3] = fmt.Sprintf("%.2f", 800+g.r.Float64()*2200)
		o.values[6] = fmt.Sprintf("ELEC-%d", g.between(5000, 9999))
		o.values[4] = g.ip(true)
		o.values[7] = []string{"US", "GB", "DE"}[g.r.Intn(3)]
		injected = append(injected, o)
	}
	for k := 0; k < int(float64(fraudCount)*.25); k++ {
		p := g.profiles[g.legit[g.r.Intn(len(g.legit))]]
		o := g.order(p, false)
		o.fraud = true
		o.values[6] = fmt.Sprintf("GIFT-%d", g.between(1000, 9999))
		o.values[3] = fmt.Sprintf("%.2f", 200+g.r.Float64()*600)
		injected = append(injected, o)
	}
	g.r.Shuffle(len(injected), func(i, j int) { injected[i], injected[j] = injected[j], injected[i] })
	if len(injected) > fraudCount {
		injected = injected[:fraudCount]
	}
	for len(injected) < fraudCount {
		injected = append(injected, g.order(g.profiles[g.fraud[g.r.Intn(len(g.fraud))]], true))
	}
	orders = append(orders, injected...)
	g.r.Shuffle(len(orders), func(i, j int) { orders[i], orders[j] = orders[j], orders[i] })
	cw := csv.NewWriter(w)
	headers := []string{"order_id", "timestamp", "user_id", "order_value", "ip_address", "card_fingerprint", "item_id", "country", "device_info", "email"}
	if o.Labels {
		headers = append(headers, "is_fraud")
	}
	if e := cw.Write(headers); e != nil {
		return summary, e
	}
	for i := range orders {
		if i%1024 == 0 {
			if e := ctx.Err(); e != nil {
				return summary, e
			}
		}
		o := &orders[i]
		o.values[0] = fmt.Sprintf("ORD-%06d", i+1)
		if o.fraud {
			summary.LabeledFraudRows++
		}
		record := o.values[:]
		if len(headers) > 10 {
			record = append(append([]string{}, record...), strconv.FormatBool(o.fraud))
		}
		if e := cw.Write(record); e != nil {
			return summary, e
		}
	}
	cw.Flush()
	return summary, cw.Error()
}
