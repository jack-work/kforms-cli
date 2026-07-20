// Package api is a thin HTTP client for gluck-forms. Every call goes
// through a resolver that supplies the current bearer token; on a 401
// the client asks the resolver to invalidate the token (which triggers
// a hush refresh) and retries exactly once. Anything past that is a
// hard failure the caller must surface.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdmime "mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Resolver interface {
	Resolve() (string, error)
	Invalidate(token string) error
}

type Client struct {
	Base     string // https://forms.kelliher.info
	Resolver Resolver
	HTTP     *http.Client
}

func New(base string, resolver Resolver) *Client {
	return &Client{
		Base:     strings.TrimRight(base, "/"),
		Resolver: resolver,
		HTTP:     http.DefaultClient,
	}
}

// do runs a request, refreshing once on 401. Returns the decoded body
// on success; on non-2xx returns an error whose message contains the
// server's response body verbatim (JSON error responses live there).
func (c *Client) do(method, path string, body any, out any) error {
	var attempt func(retry bool) error
	attempt = func(retry bool) error {
		tok, err := c.Resolver.Resolve()
		if err != nil {
			return err
		}

		var reqBody io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				return fmt.Errorf("marshal request: %w", err)
			}
			reqBody = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, c.Base+path, reqBody)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized && !retry {
			// Give the resolver a chance to refresh, then retry once.
			if err := c.Resolver.Invalidate(tok); err != nil {
				return fmt.Errorf("token rejected and refresh failed: %w", err)
			}
			return attempt(true)
		}

		bs, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Preserve server body verbatim so jq can parse it.
			return errors.New(strings.TrimSpace(string(bs)))
		}
		if out != nil && len(bs) > 0 {
			// If out is *json.RawMessage, hand the bytes over untouched.
			if raw, ok := out.(*json.RawMessage); ok {
				*raw = append((*raw)[:0], bs...)
				return nil
			}
			if err := json.Unmarshal(bs, out); err != nil {
				return fmt.Errorf("decode response: %w (body: %s)", err, string(bs))
			}
		}
		return nil
	}
	return attempt(false)
}

// ── typed shapes ────────────────────────────────────────────────────────

// Field mirrors a single form field on the wire.
type Field struct {
	Name     string         `json:"name"`
	Label    string         `json:"label"`
	Kind     string         `json:"kind"`
	Required bool           `json:"required"`
	Config   map[string]any `json:"config,omitempty"`
}

// Form is the API's JSON shape for a form.
type Form struct {
	Slug        string  `json:"slug"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Version     int     `json:"version,omitempty"`
	Frozen      bool    `json:"frozen,omitempty"`
	CreatedAt   string  `json:"created_at,omitempty"`
	UpdatedAt   string  `json:"updated_at,omitempty"`
	Fields      []Field `json:"fields"`
}

// FormListItem is the summary shape returned by GET /forms.
type FormListItem struct {
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Version   int    `json:"version"`
	Frozen    bool   `json:"frozen"`
	CreatedAt string `json:"created_at"`
}

type MintReq struct {
	Hint    string `json:"hint,omitempty"`
	Days    int    `json:"days,omitempty"`
	MaxUses int    `json:"max_uses,omitempty"`
}

type MintResp struct {
	ID       int64  `json:"id"`
	Token    string `json:"token"`
	URL      string `json:"url,omitempty"`
	Hint     string `json:"hint,omitempty"`
	Expires  string `json:"expires_at,omitempty"`
	MaxUses  int    `json:"max_uses,omitempty"`
}

type TokenListItem struct {
	ID        int64  `json:"id"`
	Hint      string `json:"hint"`
	Uses      int    `json:"uses"`
	MaxUses   int    `json:"max_uses"`
	ExpiresAt string `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
	CreatedAt string `json:"created_at"`
}

// Material mirrors a form's reference document on the wire.
type Material struct {
	ID        int64  `json:"id"`
	Filename  string `json:"filename"`
	Label     string `json:"label,omitempty"`
	Mime      string `json:"mime"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Ord       int    `json:"ord"`
	CreatedAt string `json:"created_at,omitempty"`
}

type ResponseListItem struct {
	ID          int64          `json:"id"`
	SubmittedAt string         `json:"submitted_at"`
	TokenHint   string         `json:"token_hint"`
	Answers     map[string]any `json:"answers"`
}

// ── form endpoints ──────────────────────────────────────────────────────

func (c *Client) FormCreate(f *Form) (*Form, error) {
	var out Form
	err := c.do(http.MethodPost, "/forms", f, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) FormGet(slug string) (*Form, error) {
	var out Form
	err := c.do(http.MethodGet, "/forms/"+slug, nil, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) FormUpdate(slug string, f *Form) (*Form, error) {
	var out Form
	err := c.do(http.MethodPut, "/forms/"+slug, f, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) FormFreeze(slug string) error {
	return c.do(http.MethodPost, "/forms/"+slug+"/freeze", nil, nil)
}

func (c *Client) FormList() ([]FormListItem, error) {
	var out []FormListItem
	err := c.do(http.MethodGet, "/forms", nil, &out)
	return out, err
}

// ── token endpoints ─────────────────────────────────────────────────────

func (c *Client) TokenMint(slug string, req MintReq) (*MintResp, error) {
	var out MintResp
	err := c.do(http.MethodPost, "/forms/"+slug+"/tokens", req, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TokenList(slug string) ([]TokenListItem, error) {
	var out []TokenListItem
	err := c.do(http.MethodGet, "/forms/"+slug+"/tokens", nil, &out)
	return out, err
}

func (c *Client) TokenRevoke(id string) error {
	return c.do(http.MethodPost, "/tokens/"+id+"/revoke", nil, nil)
}

// ── response endpoints ──────────────────────────────────────────────────

func (c *Client) ResponseList(slug string) ([]ResponseListItem, error) {
	var out []ResponseListItem
	err := c.do(http.MethodGet, "/forms/"+slug+"/responses", nil, &out)
	return out, err
}

// ResponseListRaw returns the raw JSON body for --json output. Preserves
// server field order and any keys we don't know about.
func (c *Client) ResponseListRaw(slug string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.do(http.MethodGet, "/forms/"+slug+"/responses", nil, &raw)
	return raw, err
}

func (c *Client) ResponseGet(id string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.do(http.MethodGet, "/responses/"+id, nil, &raw)
	return raw, err
}

// ── material endpoints ──────────────────────────────────────────────────

func (c *Client) MaterialsList(slug string) ([]Material, error) {
	var out []Material
	err := c.do(http.MethodGet, "/forms/"+slug+"/materials", nil, &out)
	return out, err
}

// MaterialUpload streams a file as multipart/form-data. The server
// dedups by (form, sha256) — 200 with the existing row is treated as
// success by the caller. label is optional; when empty the server
// falls back to the basename of the uploaded file.
func (c *Client) MaterialUpload(slug, path, label string) (*Material, error) {
	var attempt func(retry bool) (*Material, error)
	attempt = func(retry bool) (*Material, error) {
		tok, err := c.Resolver.Resolve()
		if err != nil {
			return nil, err
		}

		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()

		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		filename := filepath.Base(path)

		// Determine per-part Content-Type from extension.
		ct := stdmime.TypeByExtension(filepath.Ext(filename))
		if ct == "" {
			ct = "application/octet-stream"
		}

		writeErr := make(chan error, 1)
		go func() {
			defer pw.Close()
			defer mw.Close()
			if label != "" {
				if err := mw.WriteField("label", label); err != nil {
					writeErr <- err
					return
				}
			}
			hdr := make(textproto.MIMEHeader)
			hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, filename))
			hdr.Set("Content-Type", ct)
			part, err := mw.CreatePart(hdr)
			if err != nil {
				writeErr <- err
				return
			}
			if _, err := io.Copy(part, f); err != nil {
				writeErr <- err
				return
			}
			writeErr <- nil
		}()

		req, err := http.NewRequest(http.MethodPost, c.Base+"/forms/"+slug+"/materials", pr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", mw.FormDataContentType())

		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("POST /forms/%s/materials: %w", slug, err)
		}
		defer resp.Body.Close()
		if werr := <-writeErr; werr != nil {
			return nil, fmt.Errorf("multipart write: %w", werr)
		}

		if resp.StatusCode == http.StatusUnauthorized && !retry {
			if err := c.Resolver.Invalidate(tok); err != nil {
				return nil, fmt.Errorf("token rejected and refresh failed: %w", err)
			}
			return attempt(true)
		}

		bs, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, errors.New(strings.TrimSpace(string(bs)))
		}
		var m Material
		if err := json.Unmarshal(bs, &m); err != nil {
			return nil, fmt.Errorf("decode material response: %w (body: %s)", err, string(bs))
		}
		return &m, nil
	}
	return attempt(false)
}

func (c *Client) MaterialDelete(slug string, id int64) error {
	return c.do(http.MethodDelete, "/forms/"+slug+"/materials/"+strconv.FormatInt(id, 10), nil, nil)
}

// MaterialFetch streams a material (admin download) to out. Returns the
// server-provided filename (from Content-Disposition, if present) and
// the response's Content-Type.
func (c *Client) MaterialFetch(id int64, out io.Writer) (string, string, error) {
	tok, err := c.Resolver.Resolve()
	if err != nil {
		return "", "", err
	}
	url := c.Base + "/materials/" + strconv.FormatInt(id, 10)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		_ = c.Resolver.Invalidate(tok)
		tok, err = c.Resolver.Resolve()
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err = c.HTTP.Do(req)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bs, _ := io.ReadAll(resp.Body)
		return "", "", errors.New(strings.TrimSpace(string(bs)))
	}

	filename := ""
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := stdmime.ParseMediaType(cd); err == nil {
			if name := params["filename"]; name != "" {
				filename = filepath.Base(name)
			}
		}
	}
	ctype := resp.Header.Get("Content-Type")
	if _, err := io.Copy(out, resp.Body); err != nil {
		return filename, ctype, err
	}
	return filename, ctype, nil
}

// ── blob fetch ──────────────────────────────────────────────────────────

// BlobFetch streams a blob to dst. If dst is empty, the server's
// Content-Disposition filename is used (falling back to the blob id).
// Returns the path the file was written to.
func (c *Client) BlobFetch(id, dst string) (string, error) {
	tok, err := c.Resolver.Resolve()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodGet, c.Base+"/blobs/"+id, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		_ = c.Resolver.Invalidate(tok)
		tok, err = c.Resolver.Resolve()
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err = c.HTTP.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bs, _ := io.ReadAll(resp.Body)
		return "", errors.New(strings.TrimSpace(string(bs)))
	}

	if dst == "" {
		dst = id
		if cd := resp.Header.Get("Content-Disposition"); cd != "" {
			if _, params, err := stdmime.ParseMediaType(cd); err == nil {
				if name := params["filename"]; name != "" {
					dst = filepath.Base(name)
				}
			}
		}
	}

	f, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", err
	}
	return dst, nil
}

// Health hits an unauthenticated endpoint so smoke tests can distinguish
// "network broken" from "auth broken". The server exposes GET /health.
func (c *Client) Health() error {
	req, err := http.NewRequest(http.MethodGet, c.Base+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bs, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check: %d %s", resp.StatusCode, strings.TrimSpace(string(bs)))
	}
	return nil
}
