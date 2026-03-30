package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coregx/coregex"
	"github.com/peterbourgon/ff/v4"
	"github.com/sethvargo/go-retry"
)

const (
	authHeader  = "X-ND-AUTH"
	authMissing = `MAC id="0",nonce="0",mac="0"`

	httpTimeout = 30 * time.Second
	maxRetries  = 3
	backoffBase = 500 * time.Millisecond
	drainLimit  = 32 << 10
	nameLimit   = 240
)

var (
	pdfRewriter  = coregex.MustCompile(`^https?://(?:.+)\.ykt\.cbern\.com\.cn/(.+)/([\da-f-]{36})\.pkg/(.+)\.pdf$`)
	syncMatch    = coregex.MustCompile(`^https?://[^/]+/syncClassroom/basicWork/detail`)
	invalidChars = coregex.MustCompile(`[/:?"<>|]`)
	tokenPtr     atomic.Pointer[string]
	transport    = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		WriteBufferSize:       32 << 10,
		ReadBufferSize:        32 << 10,
	}
	apiClient      = &http.Client{Transport: transport, Timeout: httpTimeout}
	downloadClient = &http.Client{Transport: transport}
	bufPool        = sync.Pool{New: func() any { b := make([]byte, 128<<10); return &b }}
)

type Asset struct {
	URL   string
	CID   string
	Title string
}

type ResolvedAsset struct {
	Asset  Asset
	RawURL string
}

type tiItem struct {
	Format   string   `json:"lc_ti_format"`
	Storage  string   `json:"ti_storage"`
	Storages []string `json:"ti_storages"`
	Source   bool     `json:"ti_is_source_file"`
}

type details struct {
	Title string   `json:"title"`
	Items []tiItem `json:"ti_items"`
}

type listingEntry struct {
	Type  string   `json:"resource_type_code"`
	Items []tiItem `json:"ti_items"`
}

type httpError int

func (e httpError) Error() string { return fmt.Sprintf("HTTP %d", e) }

func token() string {
	if p := tokenPtr.Load(); p != nil {
		return `MAC id="` + *p + `",nonce="0",mac="0"`
	}
	return authMissing
}

func setToken(s string) {
	if s = strings.TrimSpace(s); s == "" {
		tokenPtr.Store(nil)
	} else {
		tokenPtr.Store(&s)
	}
}

func isRetryStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
}

func drain(rc io.ReadCloser) {
	if rc != nil {
		_, _ = io.CopyN(io.Discard, rc, drainLimit)
		_ = rc.Close()
	}
}

func req(ctx context.Context, client *http.Client, method, raw string, body []byte) (*http.Response, error) {
	var resp *http.Response
	var last error
	backoff := retry.WithCappedDuration(5*time.Second, retry.NewExponential(backoffBase))
	err := retry.Do(ctx, retry.WithMaxRetries(maxRetries, backoff), func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, raw, r)
		if err != nil {
			return err
		}
		req.Header.Set(authHeader, token())
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err = client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var nerr net.Error
			if errors.As(err, &nerr) {
				last = err
				return retry.RetryableError(err)
			}
			return err
		}
		if isRetryStatus(resp.StatusCode) {
			drain(resp.Body)
			last = httpError(resp.StatusCode)
			return retry.RetryableError(last)
		}
		return nil
	})
	if err != nil {
		if last != nil {
			return nil, last
		}
		return nil, err
	}
	return resp, nil
}

func resolveStorage(raw string, authed bool) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if after, ok :=strings.CutPrefix(raw, "cs_path:${ref-path}"); ok  {
		if authed {
			return "https://r1-ndr-private.ykt.cbern.com.cn" + after
		}
		return "https://c1.ykt.cbern.com.cn" + strings.TrimPrefix(raw, "cs_path:${ref-path}")
	}
	if authed {
		return raw
	}
	if pdfRewriter.MatchString(raw) {
		return pdfRewriter.ReplaceAllString(raw, "https://c1.ykt.cbern.com.cn/$1/$2.pkg/$3.pdf")
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.HasSuffix(u.Host, "ykt.cbern.com.cn") {
		return raw
	}
	u.Scheme, u.Host = "https", "c1.ykt.cbern.com.cn"
	return u.String()
}

func pickPDF(items []tiItem) string {
	authed := tokenPtr.Load() != nil
	for pass := range 2 {
		for _, it := range items {
			if it.Format != "pdf" || pass == 0 && !it.Source {
				continue
			}
			if s := resolveStorage(it.Storage, authed); s != "" {
				return s
			}
			for _, s := range it.Storages {
				if s = resolveStorage(s, authed); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func decode[T any](r io.Reader, out *T) bool { return json.NewDecoder(r).Decode(out) == nil }

func resolveFromListing(ctx context.Context, cid string) string {
	resp, err := req(ctx, apiClient, http.MethodGet, fmt.Sprintf("https://s-file-1.ykt.cbern.com.cn/zxx/ndrs/special_edu/thematic_course/%s/resources/list.json", cid), nil)
	if err != nil {
		return ""
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var list []listingEntry
	if !decode(resp.Body, &list) {
		return ""
	}
	for _, e := range list {
		if e.Type == "assets_document" {
			if u := pickPDF(e.Items); u != "" {
				return u
			}
		}
	}
	return ""
}

func resolveOne(ctx context.Context, raw string) *ResolvedAsset {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	cid := strings.TrimSpace(u.Query().Get("contentId"))
	if cid == "" {
		return nil
	}
	typ := strings.TrimSpace(u.Query().Get("contentType"))
	if typ == "" {
		typ = "assets_document"
	}
	base := "https://s-file-1.ykt.cbern.com.cn/zxx/ndrv2/resources/tch_material/details/%s.json"
	if typ == "thematic_course" || syncMatch.MatchString(raw) {
		base = "https://s-file-1.ykt.cbern.com.cn/zxx/ndrs/special_edu/resources/details/%s.json"
	}
	resp, err := req(ctx, apiClient, http.MethodGet, fmt.Sprintf(base, cid), nil)
	if err != nil {
		return nil
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var d details
	if !decode(resp.Body, &d) {
		return nil
	}
	pdf := pickPDF(d.Items)
	if pdf == "" && typ == "thematic_course" {
		pdf = resolveFromListing(ctx, cid)
	}
	if pdf == "" {
		return nil
	}
	return &ResolvedAsset{Asset: Asset{URL: pdf, CID: cid, Title: strings.TrimSpace(d.Title)}, RawURL: raw}
}

func cleanName(s string) string {
	s = strings.Trim(strings.Join(strings.FieldsFunc(invalidChars.ReplaceAllString(strings.TrimSpace(s), "_"), func(r rune) bool {
		return r == 0 || r == '_' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}), "_"), ". ")
	if s == "" {
		return "download"
	}
	if len(s) > nameLimit {
		s = strings.TrimRight(s[:nameLimit], ". ")
		if s == "" {
			return "download"
		}
	}
	return s
}

func makeName(a Asset) string {
	if a.Title != "" {
		return cleanName(a.Title) + ".pdf"
	}
	if a.CID != "" {
		return a.CID + ".pdf"
	}
	return "download.pdf"
}

func collectURLs(args []string, file string) ([]string, error) {
	urls := make([]string, 0, len(args)+16)
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			urls = append(urls, s)
		}
	}
	for _, s := range args {
		add(s)
	}
	if file != "" {
		var r io.Reader = os.Stdin
		if file != "-" {
			f, err := os.Open(file)
			if err != nil {
				return nil, fmt.Errorf("open file: %w", err)
			}
			defer f.Close()
			r = f
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}
	}
	seen := map[string]struct{}{}
	return slices.DeleteFunc(urls, func(s string) bool {
		_, ok := seen[s]
		seen[s] = struct{}{}
		return ok
	}), nil
}

func resolveAll(ctx context.Context, urls []string) ([]ResolvedAsset, []string) {
	if len(urls) == 0 {
		return nil, nil
	}
	n := len(urls)
	workers := min(n, max(4, runtime.NumCPU()*2))
	type result struct {
		i int
		a *ResolvedAsset
	}
	jobs := make(chan int, n)
	out := make(chan result, n)
	for i := range urls {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for i := range jobs {
				a := resolveOne(ctx, urls[i])
				select {
				case <-ctx.Done():
					return
				case out <- result{i, a}:
				}
			}
		}()
	}
	go func() { wg.Wait(); close(out) }()
	ordered := make([]*ResolvedAsset, n)
	failed := make([]string, 0, n/4)
	for r := range out {
		if r.a == nil {
			failed = append(failed, urls[r.i])
		} else {
			ordered[r.i] = r.a
		}
	}
	resolved := make([]ResolvedAsset, 0, n-len(failed))
	for _, a := range ordered {
		if a != nil {
			resolved = append(resolved, *a)
		}
	}
	return resolved, failed
}

func freeSpace(path string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	n := int64(st.Bavail) * int64(st.Bsize)
	return n, n >= 0
}

func formatBytes(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + "B"
	}
	u := [...]string{"KB", "MB", "GB", "TB", "PB"}
	f := float64(n) / 1024
	for i := range u {
		if f < 1024 || i == len(u)-1 {
			return strconv.FormatFloat(f, 'f', 1, 64) + u[i]
		}
		f /= 1024
	}
	return "0B"
}

func contentLength(ctx context.Context, raw string) int64 {
	resp, err := req(ctx, apiClient, http.MethodHead, raw, nil)
	if err != nil {
		return 0
	}
	defer drain(resp.Body)
	n, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	return max64(n, 0)
}

type progress struct {
	w     io.Writer
	label string
	total int64
	last  time.Time
	bytes atomic.Int64
}

func (p *progress) write(n int) {
	p.bytes.Add(int64(n))
	if now := time.Now(); now.Sub(p.last) >= 250*time.Millisecond {
		p.last = now
		p.print(false)
	}
}

func (p *progress) print(done bool) {
	n := p.bytes.Load()
	if p.total > 0 {
		fmt.Fprintf(p.w, "\r%s %s/%s (%.1f%%)", p.label, formatBytes(n), formatBytes(p.total), float64(n)*100/float64(p.total))
	} else {
		fmt.Fprintf(p.w, "\r%s %s", p.label, formatBytes(n))
	}
	if done {
		_, _ = fmt.Fprint(p.w, "\n")
	}
}

func download(ctx context.Context, raw, dest string, overwrite bool) error {
	dest = filepath.Clean(dest)
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if !overwrite {
		if _, err := os.Stat(dest); err == nil {
			return fmt.Errorf("destination exists: %s", dest)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat destination: %w", err)
		}
	}
	resp, err := req(ctx, downloadClient, http.MethodGet, raw, nil)
	if err != nil {
		return fmt.Errorf("download request: %w", err)
	}
	defer drain(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return httpError(resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, ".dl-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	p := &progress{w: os.Stderr, label: dest + ":", total: max64(resp.ContentLength, 0)}
	if p.total == 0 {
		p.total = contentLength(ctx, raw)
	}
	buf := *bufPool.Get().(*[]byte)
	defer bufPool.Put(&buf)
	if free, ok := freeSpace(dir); ok {
		_, _ = fmt.Fprintf(os.Stderr, "%s: free %s\n", dest, formatBytes(free))
	}
	_, err = io.CopyBuffer(tmp, io.TeeReader(resp.Body, writerFunc(p.write)), buf)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	p.print(true)
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	if overwrite {
		_ = os.Remove(dest)
	}
	if err := os.Rename(name, dest); err != nil {
		return fmt.Errorf("rename file: %w", err)
	}
	if err := os.Chmod(dest, 0o644); err != nil {
		return fmt.Errorf("chmod file: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	ok = true
	return nil
}

type writerFunc func(int)

func (f writerFunc) Write(p []byte) (int, error) { f(len(p)); return len(p), nil }

func runParse(ctx context.Context, token, fromFile string, args []string) error {
	setToken(token)
	urls, err := collectURLs(args, fromFile)
	if err != nil {
		return err
	}
	assets, _ := resolveAll(ctx, urls)
	for _, a := range assets {
		_, _ = fmt.Fprintln(os.Stdout, a.Asset.URL)
	}
	return nil
}

func runDownload(ctx context.Context, token, fromFile, output, outputDir string, overwrite bool, args []string) error {
	setToken(token)
	urls, err := collectURLs(args, fromFile)
	if err != nil {
		return err
	}
	assets, failed := resolveAll(ctx, urls)
	if len(assets) == 0 && len(failed) > 0 {
		return errors.New("failed to resolve any URLs")
	}
	for _, a := range assets {
		dest := makeName(a.Asset)
		if outputDir != "" {
			dest = filepath.Join(outputDir, dest)
		}
		if output != "" {
			dest = output
		}
		if err := download(ctx, a.Asset.URL, dest, overwrite); err != nil {
			return fmt.Errorf("download %s: %w", dest, err)
		}
	}
	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var token, fromFile, output, outputDir string
	var overwrite bool

	rootFlags := ff.NewFlagSet("tch-material")
	rootFlags.StringVar(&token, 0, "token", "", "")

	parseFlags := ff.NewFlagSet("parse")
	parseFlags.StringVar(&fromFile, 'f', "from-file", "", "")

	downloadFlags := ff.NewFlagSet("download")
	downloadFlags.StringVar(&fromFile, 'f', "from-file", "", "")
	downloadFlags.StringVar(&output, 'o', "output", "", "")
	downloadFlags.StringVar(&outputDir, 'd', "output-dir", "", "")
	downloadFlags.BoolVar(&overwrite, 'w', "overwrite", "")

	root := &ff.Command{
		Name:  "tch-material",
		Flags: rootFlags,
		Subcommands: []*ff.Command{
			{Name: "parse", Flags: parseFlags, Exec: func(ctx context.Context, args []string) error { return runParse(ctx, token, fromFile, args) }},
			{Name: "download", Flags: downloadFlags, Exec: func(ctx context.Context, args []string) error {
				return runDownload(ctx, token, fromFile, output, outputDir, overwrite, args)
			}},
		},
	}
	if err := root.ParseAndRun(ctx, os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
