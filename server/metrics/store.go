// Package metrics wraps an embedded Prometheus TSDB plus the PromQL engine.
//
// Every sample is stored with host_id and tenant_id labels. Metric names get
// an "sentrel_" prefix so the /metrics exposition and PromQL queries are
// unambiguous.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/util/compression"
)

// Prefix is prepended to every metric name.
const Prefix = "sentrel_"

// Store is the time-series store.
type Store struct {
	db     *tsdb.DB
	engine *promql.Engine
	dir    string
	log    *slog.Logger

	mu        sync.RWMutex
	retention time.Duration
}

// Sample is a single data point.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  float64
	TsMs   int64
}

// Open opens or creates the TSDB in dir.
func Open(dir string, retention time.Duration, log *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	opts := tsdb.DefaultOptions()
	opts.RetentionDuration = retention.Milliseconds()
	opts.WALCompression = compression.Snappy
	// Agents may deliver buffered samples after a reconnect.
	opts.OutOfOrderTimeWindow = (2 * time.Hour).Milliseconds()
	db, err := tsdb.Open(dir, log.With("component", "tsdb"), nil, opts, nil)
	if err != nil {
		return nil, err
	}
	eng := promql.NewEngine(promql.EngineOpts{
		Logger:               log.With("component", "promql"),
		MaxSamples:           20_000_000,
		Timeout:              time.Minute,
		LookbackDelta:        5 * time.Minute,
		EnableAtModifier:     true,
		EnableNegativeOffset: true,
	})
	return &Store{db: db, engine: eng, dir: dir, log: log, retention: retention}, nil
}

// Close flushes and closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SetRetention changes the global retention. Blocks older than this are
// removed at the next compaction.
func (s *Store) SetRetention(d time.Duration) error {
	s.mu.Lock()
	s.retention = d
	s.mu.Unlock()
	return s.db.ApplyConfig(&config.Config{StorageConfig: config.StorageConfig{TSDBConfig: &config.TSDBConfig{
		OutOfOrderTimeWindow: (2 * time.Hour).Milliseconds(),
		Retention:            &config.TSDBRetentionConfig{Time: model.Duration(d)},
	}}})
}

// Retention returns the configured global retention.
func (s *Store) Retention() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.retention
}

// Append writes samples for one host.
func (s *Store) Append(hostID, tenantID int64, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	app := s.db.Appender(context.Background())
	hid := strconv.FormatInt(hostID, 10)
	tid := strconv.FormatInt(tenantID, 10)
	var firstErr error
	for _, smp := range samples {
		if math.IsNaN(smp.Value) || math.IsInf(smp.Value, 0) {
			continue
		}
		b := labels.NewScratchBuilder(len(smp.Labels) + 3)
		b.Add(labels.MetricName, Prefix+sanitize(smp.Name))
		for k, v := range smp.Labels {
			if k == "" || k != sanitize(k) || k == "host_id" || k == "tenant_id" || k == labels.MetricName {
				continue
			}
			b.Add(k, v)
		}
		if hostID > 0 {
			b.Add("host_id", hid)
		}
		b.Add("tenant_id", tid)
		b.Sort()
		ts := smp.TsMs
		if ts == 0 {
			ts = time.Now().UnixMilli()
		}
		if _, err := app.Append(0, b.Labels(), ts, smp.Value); err != nil && firstErr == nil {
			if !errors.Is(err, storage.ErrDuplicateSampleForTimestamp) && !errors.Is(err, storage.ErrOutOfOrderSample) && !errors.Is(err, storage.ErrTooOldSample) {
				firstErr = err
			}
		}
	}
	if err := app.Commit(); err != nil {
		return err
	}
	return firstErr
}

func sanitize(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
			b.WriteRune(r)
		case r >= '0' && r <= '9' && i > 0:
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Point is [unix seconds, value].
type Point [2]float64

// Series is one result series.
type Series struct {
	Labels map[string]string `json:"labels"`
	Points []Point           `json:"points"`
}

// QueryRange runs a PromQL range query.
func (s *Store) QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]Series, error) {
	if step <= 0 {
		step = autoStep(start, end)
	}
	qry, err := s.engine.NewRangeQuery(ctx, s.db, nil, q, start, end, step)
	if err != nil {
		return nil, err
	}
	defer qry.Close()
	res := qry.Exec(ctx)
	if res.Err != nil {
		return nil, res.Err
	}
	return toSeries(res.Value)
}

// QueryInstant runs a PromQL instant query.
func (s *Store) QueryInstant(ctx context.Context, q string, ts time.Time) ([]Series, error) {
	qry, err := s.engine.NewInstantQuery(ctx, s.db, nil, q, ts)
	if err != nil {
		return nil, err
	}
	defer qry.Close()
	res := qry.Exec(ctx)
	if res.Err != nil {
		return nil, res.Err
	}
	return toSeries(res.Value)
}

// promParser parses PromQL with default options.
var promParser = parser.NewParser(parser.Options{})

// ParseExpr parses a PromQL expression.
func ParseExpr(q string) (parser.Expr, error) { return promParser.ParseExpr(q) }

// ValidateQuery parses q without executing it.
func ValidateQuery(q string) error {
	_, err := promParser.ParseExpr(q)
	return err
}

func toSeries(v parser.Value) ([]Series, error) {
	var out []Series
	switch m := v.(type) {
	case promql.Matrix:
		for _, ser := range m {
			sr := Series{Labels: ser.Metric.Map()}
			for _, p := range ser.Floats {
				sr.Points = append(sr.Points, Point{float64(p.T) / 1000, p.F})
			}
			out = append(out, sr)
		}
	case promql.Vector:
		for _, smp := range m {
			out = append(out, Series{Labels: smp.Metric.Map(), Points: []Point{{float64(smp.T) / 1000, smp.F}}})
		}
	case promql.Scalar:
		out = append(out, Series{Labels: map[string]string{}, Points: []Point{{float64(m.T) / 1000, m.V}}})
	default:
		return nil, fmt.Errorf("unsupported result type %T", v)
	}
	sort.Slice(out, func(i, j int) bool { return labelKey(out[i].Labels) < labelKey(out[j].Labels) })
	return out, nil
}

func labelKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + m[k] + ",")
	}
	return b.String()
}

// autoStep picks a step giving roughly 300-600 points.
func autoStep(start, end time.Time) time.Duration {
	d := end.Sub(start)
	step := d / 400
	for _, s := range []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour} {
		if step <= s {
			return s
		}
	}
	return 12 * time.Hour
}

// AutoStep is exported for API handlers.
func AutoStep(start, end time.Time) time.Duration { return autoStep(start, end) }

// DeleteHost removes all samples for a host.
func (s *Store) DeleteHost(ctx context.Context, hostID int64) error {
	m := labels.MustNewMatcher(labels.MatchEqual, "host_id", strconv.FormatInt(hostID, 10))
	return s.db.Delete(ctx, math.MinInt64, math.MaxInt64, m)
}

// EnforceRetention deletes data older than the global retention, and older
// than each host's override where that is shorter. hostRetention maps
// host_id to retention.
func (s *Store) EnforceRetention(ctx context.Context, hostRetention map[int64]time.Duration) error {
	now := time.Now()
	global := s.Retention()
	all := labels.MustNewMatcher(labels.MatchRegexp, labels.MetricName, ".+")
	if err := s.db.Delete(ctx, math.MinInt64, now.Add(-global).UnixMilli(), all); err != nil {
		return err
	}
	for id, r := range hostRetention {
		if r <= 0 || r >= global {
			continue
		}
		m := labels.MustNewMatcher(labels.MatchEqual, "host_id", strconv.FormatInt(id, 10))
		if err := s.db.Delete(ctx, math.MinInt64, now.Add(-r).UnixMilli(), m); err != nil {
			return err
		}
	}
	return s.db.CleanTombstones()
}

// Stats summarises storage usage.
type Stats struct {
	DiskBytes      int64   `json:"disk_bytes"`
	Blocks         int     `json:"blocks"`
	HeadSeries     uint64  `json:"head_series"`
	TotalSamples   uint64  `json:"total_samples"`
	BytesPerSample float64 `json:"bytes_per_sample"`
	MinTime        int64   `json:"min_time"`
	MaxTime        int64   `json:"max_time"`
}

// Stats returns storage statistics.
func (s *Store) Stats() Stats {
	st := Stats{HeadSeries: s.db.Head().NumSeries()}
	var blockBytes int64
	var blockSamples uint64
	for _, b := range s.db.Blocks() {
		st.Blocks++
		blockBytes += b.Size()
		blockSamples += b.Meta().Stats.NumSamples
	}
	st.TotalSamples = blockSamples
	st.DiskBytes = dirSize(s.dir)
	if blockSamples > 0 {
		st.BytesPerSample = float64(blockBytes) / float64(blockSamples)
	} else {
		st.BytesPerSample = 1.5 // typical Gorilla-compressed sample
	}
	st.MinTime = s.db.Head().MinTime()
	if bs := s.db.Blocks(); len(bs) > 0 {
		st.MinTime = bs[0].Meta().MinTime
	}
	st.MaxTime = s.db.Head().MaxTime()
	return st
}

func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// HostSampleCounts counts stored samples per host_id across all data,
// using chunk metadata only (cheap: no sample decoding).
func (s *Store) HostSampleCounts(ctx context.Context) (map[int64]uint64, error) {
	q, err := s.db.ChunkQuerier(math.MinInt64, math.MaxInt64)
	if err != nil {
		return nil, err
	}
	defer q.Close()
	m := labels.MustNewMatcher(labels.MatchRegexp, "host_id", ".+")
	set := q.Select(ctx, false, nil, m)
	out := map[int64]uint64{}
	for set.Next() {
		ser := set.At()
		id, _ := strconv.ParseInt(ser.Labels().Get("host_id"), 10, 64)
		it := ser.Iterator(nil)
		for it.Next() {
			c := it.At()
			if c.Chunk != nil {
				out[id] += uint64(c.Chunk.NumSamples())
			}
		}
	}
	return out, set.Err()
}

// LatestValues returns the most recent value per series matching name for a
// host within the lookback window.
func (s *Store) LatestValues(ctx context.Context, hostID int64, name string, lookback time.Duration) ([]Series, error) {
	q := fmt.Sprintf(`last_over_time(%s%s{host_id="%d"}[%ds])`, Prefix, sanitize(name), hostID, int(lookback.Seconds()))
	return s.QueryInstant(ctx, q, time.Now())
}

// Gather walks every series' most recent sample (within 10 minutes) and
// calls fn; used by the /metrics exposition endpoint.
func (s *Store) Gather(ctx context.Context, tenantID int64, fn func(name string, lbls labels.Labels, v float64, ts int64)) error {
	now := time.Now().UnixMilli()
	q, err := s.db.Querier(now-10*60*1000, now)
	if err != nil {
		return err
	}
	defer q.Close()
	ms := []*labels.Matcher{labels.MustNewMatcher(labels.MatchRegexp, labels.MetricName, Prefix+".+")}
	if tenantID > 0 {
		ms = append(ms, labels.MustNewMatcher(labels.MatchEqual, "tenant_id", strconv.FormatInt(tenantID, 10)))
	}
	set := q.Select(ctx, false, nil, ms...)
	var it chunkenc.Iterator
	for set.Next() {
		ser := set.At()
		it = ser.Iterator(it)
		var lt int64
		var lv float64
		found := false
		for vt := it.Next(); vt != chunkenc.ValNone; vt = it.Next() {
			if vt == chunkenc.ValFloat {
				lt, lv = it.At()
				found = true
			}
		}
		if found {
			fn(ser.Labels().Get(labels.MetricName), ser.Labels(), lv, lt)
		}
	}
	return set.Err()
}
