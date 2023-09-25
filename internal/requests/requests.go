package requests

import (
	"compress/gzip"
	"crypto/tls"
	"github.com/tidwall/gjson"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RomiChan/syncx"
	"github.com/pkg/errors"
)

var client = newClient(time.Second * 15)
var clients syncx.Map[time.Duration, *http.Client]

var clienth2 = &http.Client{
	Transport: &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 999,
	},
	Timeout: time.Second * 15,
}

func newClient(t time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// Disable http2
			TLSNextProto:        map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
			MaxIdleConnsPerHost: 999,
		},
		Timeout: t,
	}
}

// ErrOverSize 响应主体过大时返回此错误
var ErrOverSize = errors.New("oversize")

// UserAgent HTTP请求时使用的UA
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 Edg/87.0.664.66"

// WithTimeout get a download instance with timeout t
func (r Request) WithTimeout(t time.Duration) *Request {
	if c, ok := clients.Load(t); ok {
		r.custcli = c
	} else {
		c := newClient(t)
		clients.Store(t, c)
		r.custcli = c
	}
	return &r
}

// Request is a file download request
type Request struct {
	Method  string
	URL     string
	Header  map[string]string
	Limit   int64
	Body    io.Reader
	custcli *http.Client
}

func (r Request) client() *http.Client {
	if r.custcli != nil {
		return r.custcli
	}
	if strings.Contains(r.URL, "go-cqhttp.org") {
		return clienth2
	}
	return client
}

func (r Request) do() (*http.Response, error) {
	if r.Method == "" {
		r.Method = http.MethodGet
	}
	req, err := http.NewRequest(r.Method, r.URL, r.Body)
	if err != nil {
		return nil, err
	}

	req.Header["User-Agent"] = []string{UserAgent}
	for k, v := range r.Header {
		req.Header.Set(k, v)
	}

	return r.client().Do(req)
}

func (r Request) body() (io.ReadCloser, error) {
	resp, err := r.do()
	if err != nil {
		return nil, err
	}

	limit := r.Limit // check file size limit
	if limit > 0 && resp.ContentLength > limit {
		_ = resp.Body.Close()
		return nil, ErrOverSize
	}

	if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
		return gzipReadCloser(resp.Body)
	}
	return resp.Body, err
}

// Bytes 对给定URL发送请求，返回响应主体
func (r Request) Bytes() ([]byte, error) {
	rd, err := r.body()
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	defer r.client().CloseIdleConnections()
	return io.ReadAll(rd)
}

// JSON 发送请求， 并转换响应为JSON
func (r Request) JSON() (gjson.Result, error) {
	rd, err := r.body()
	if err != nil {
		return gjson.Result{}, err
	}
	defer rd.Close()
	defer r.client().CloseIdleConnections()

	var sb strings.Builder
	_, err = io.Copy(&sb, rd)
	if err != nil {
		return gjson.Result{}, err
	}

	return gjson.Parse(sb.String()), nil
}

type gzipCloser struct {
	f io.Closer
	r *gzip.Reader
}

// gzipReadCloser 从 io.ReadCloser 创建 gunzip io.ReadCloser
func gzipReadCloser(reader io.ReadCloser) (io.ReadCloser, error) {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	return &gzipCloser{
		f: reader,
		r: gzipReader,
	}, nil
}

// Read impls io.Reader
func (g *gzipCloser) Read(p []byte) (n int, err error) {
	return g.r.Read(p)
}

// Close impls io.Closer
func (g *gzipCloser) Close() error {
	_ = g.f.Close()
	return g.r.Close()
}
