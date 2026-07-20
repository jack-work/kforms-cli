// gforms CLI. Subcommands live in one file for the same reason
// gluck-todo-cli does — small surface, easy to grep.
//
// Auth model in one paragraph: `login` runs OAuth's RFC 8628 device
// grant against Authelia, hands the resulting tokens to the hush agent.
// Every other command constructs an Aggregate resolver (env-var override
// → hush) and passes it to the API client, which sets Authorization:
// Bearer on every request and retries once on 401 after asking the
// resolver to refresh. See README.md for the fuller picture.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	hush "github.com/jack-work/hush/client"

	"github.com/jack-work/gforms-cli/internal/api"
	"github.com/jack-work/gforms-cli/internal/auth"
	"github.com/jack-work/gforms-cli/internal/form"
)

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	apiBase   = envDefault("GFORMS_API", "https://forms.kelliher.info")
	issuer    = envDefault("GFORMS_ISSUER", "https://auth.kelliher.info")
	clientID  = envDefault("GFORMS_CLIENT_ID", "gforms-cli")
	hushName  = envDefault("GFORMS_HUSH_NAME", "gforms")
	envTokVar = "GFORMS_TOKEN"
	scopes    = "openid profile groups offline_access"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	var err error
	switch cmd {
	case "login":
		err = cmdLogin()
	case "logout":
		err = cmdLogout()
	case "whoami":
		err = cmdWhoami()
	case "create":
		err = cmdCreate()
	case "edit":
		err = cmdEdit()
	case "show":
		err = cmdShow()
	case "freeze":
		err = cmdFreeze()
	case "list", "ls":
		err = cmdList()
	case "mint":
		err = cmdMint()
	case "tokens":
		err = cmdTokens()
	case "revoke":
		err = cmdRevoke()
	case "responses":
		err = cmdResponses()
	case "response":
		err = cmdResponse()
	case "fetch":
		err = cmdFetch()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `gforms — CLI for the gluck-forms service (auth'd forms w/ per-form SAS URLs)

USAGE
  gforms <command> [args...]

BACKGROUND
  Two hosts back one service:
    forms.kelliher.info   admin API (Authelia 2FA; requires the
                          'gluck-forms-admin' lldap group)
    f.kelliher.info       public form filler; URL is f.kelliher.info/<token>

  Admin commands here use OIDC device-flow (RFC 8628) against
  auth.kelliher.info. On first use, run 'gforms login' — you'll get a
  code + URL, open the URL in a browser, complete 2FA, confirm the
  code. Tokens are stored age-encrypted in the hush agent; refresh is
  automatic on 401. Requires 'hush up -d' to be running.

AUTH
  login                          authenticate via device flow, store tokens in hush
  logout                         forget the stored refresh token
  whoami                         print the current user + groups

FORMS
  create   -f FILE.yaml          load form from YAML, POST /forms
                                 (yaml schema below; ord auto-assigned)
  edit     <slug>                GET form → $EDITOR (YAML) → PUT form
                                 (allowed only while frozen=false)
  show     <slug>                pretty-print a form as JSON
  freeze   <slug>                lock a form; no further edits
                                 (one-way; existing tokens keep working)
  list                           list all forms

TOKENS (SAS URLS)
  mint     <slug> [flags]        mint a new capability URL for one form
     --hint STRING               admin-visible label (e.g. "noah")
     --days INT                  lifetime in days (default 30)
     --uses INT                  max uses (default: unlimited-within-expiry)
                                 → prints raw token + full URL EXACTLY ONCE.
                                   only sha256(token) is stored server-side.
  tokens   <slug>                list tokens for a form (hint/uses/expiry)
  revoke   <token-id>            revoke a token (still counted, but 410 on use)

RESPONSES
  responses <slug> [--json]      list responses for a form (table or JSON)
  response  <id>                 show one response as JSON (answers + blob refs)
  fetch     <blob-id> [-o FILE]  save a blob to disk
                                 (default filename from server Content-Disposition)

YAML SCHEMA (for 'create -f FILE.yaml')
  slug: <slug-str>              url-safe; unique per instance
  title: <str>                  shown as page title on public form
  description: <markdown-str>   rendered above fields
  fields:
    - name: <machine_key>       [a-z_][a-z0-9_]*
      label: <human-visible>
      description: <help-text>  optional
      required: true|false      default true
      kind: <see below>
      config: { … kind-specific … }

FIELD KINDS + CONFIG
  short_text     config: { max_length: 200, pattern?: <regex> }
  long_text      config: { max_length: 5000, min_length?: N }
  email          config: { max_length: 200 }
  phone          config: { }
  date           config: { min?: "YYYY-MM-DD", max?: "YYYY-MM-DD" }
  radio          config: { options: [ {value, label}, … ] }
  multiselect    config: { options: [ {value, label}, … ] }
  checkbox       config: { must_check: true }   (rejects false when required)
  signature      config: { mode: "drawn"|"typed"|"both" }
                 → drawn stored as SVG blob; typed inline in answers JSON
  file           config: { accept: ["application/pdf","image/*"], max_size_mb: 25 }
  markdown       config: { content: <markdown-str> }   (display only; no answer)

ENVIRONMENT OVERRIDES (all optional)
  GFORMS_API         default: https://forms.kelliher.info
  GFORMS_ISSUER      default: https://auth.kelliher.info
  GFORMS_CLIENT_ID   default: gforms-cli
  GFORMS_HUSH_NAME   default: gforms
  GFORMS_TOKEN       raw bearer JWT (escape hatch; bypasses hush)
  EDITOR             used by 'edit' (default: vi)

ERRORS
  Non-2xx responses exit non-zero and print the server's JSON error to stderr.
  A 401 triggers an automatic hush refresh and one retry; if that still 401s,
  run 'gforms login' again.

EXAMPLES
  hush up -d                              # prerequisite once per session
  gforms login                            # first-run auth
  gforms create -f wfh-rol.yaml           # define a form from YAML
  gforms freeze wfh-rol-2026              # lock it
  gforms mint wfh-rol-2026 --hint noah --days 30
    → prints https://f.kelliher.info/<token> — text this to Noah
  gforms tokens wfh-rol-2026              # audit who has open links
  gforms responses wfh-rol-2026 --json | jq '.[] | .answers.legal_name'
  gforms fetch 42 -o noah-signature.svg   # download a signature blob`)
}

// hushClient returns a live hush client or a helpful error.
func hushClient() (*hush.Client, error) {
	c, err := hush.New()
	if err != nil {
		return nil, fmt.Errorf("hush client: %w", err)
	}
	if err := c.Ping(); err != nil {
		return nil, fmt.Errorf("hush agent is not running (start it: hush up -d): %w", err)
	}
	return c, nil
}

func newResolver(h *hush.Client) *auth.Aggregate {
	return &auth.Aggregate{Strategies: []auth.CredentialStrategy{
		&auth.EnvVar{Name: envTokVar},
		&auth.OAuth{Hush: h, Name: hushName},
	}}
}

func newAPIClient() (*api.Client, error) {
	h, err := hushClient()
	if err != nil {
		return nil, err
	}
	return api.New(apiBase, newResolver(h)), nil
}

func prettyJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// prettyRaw indents a json.RawMessage. Used for pass-through responses
// where we don't want to lose fields we don't model.
func prettyRaw(raw json.RawMessage) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Fall back to raw bytes if it isn't valid JSON.
		_, err := os.Stdout.Write(raw)
		return err
	}
	return prettyJSON(v)
}

// ── auth commands ───────────────────────────────────────────────────────

func cmdLogin() error {
	h, err := hushClient()
	if err != nil {
		return err
	}
	return auth.LoginDevice(h, auth.DeviceConfig{
		ProviderName:           hushName,
		DeviceAuthorizationURL: issuer + "/api/oidc/device-authorization",
		TokenURL:               issuer + "/api/oidc/token",
		AuthorizeURL:           issuer + "/api/oidc/authorization",
		ClientID:               clientID,
		Scopes:                 scopes,
	})
}

func cmdLogout() error {
	h, err := hushClient()
	if err != nil {
		return err
	}
	if err := h.OAuthDelete(hushName); err != nil {
		if errors.Is(err, hush.ErrOAuthNotFound) {
			fmt.Fprintln(os.Stderr, "already logged out")
			return nil
		}
		return fmt.Errorf("hush OAuthDelete: %w", err)
	}
	fmt.Fprintln(os.Stderr, "logged out (hush credential deleted)")
	return nil
}

func cmdWhoami() error {
	h, err := hushClient()
	if err != nil {
		return err
	}
	tok, err := newResolver(h).Resolve()
	if err != nil {
		return err
	}
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return fmt.Errorf("token is not a JWT (opaque?): got %d segments", len(parts))
	}
	claims, err := decodeJWTClaims(parts[1])
	if err != nil {
		return err
	}
	interesting := []string{"preferred_username", "sub", "groups", "email", "aud", "iss", "exp", "iat"}
	for _, k := range interesting {
		if v, ok := claims[k]; ok {
			fmt.Printf("%-22s %v\n", k+":", v)
			delete(claims, k)
		}
	}
	if len(claims) > 0 {
		fmt.Println("---")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(claims)
	}
	return nil
}

// ── form commands ───────────────────────────────────────────────────────

func cmdCreate() error {
	var path string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f" || a == "--file":
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", a)
			}
			path = args[i+1]
			i++
		case strings.HasPrefix(a, "--file="):
			path = strings.TrimPrefix(a, "--file=")
		default:
			return fmt.Errorf("unknown arg: %s (usage: gforms create -f FILE.yaml)", a)
		}
	}
	if path == "" {
		return fmt.Errorf("usage: gforms create -f FILE.yaml")
	}
	f, err := form.LoadYAML(path)
	if err != nil {
		return err
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	created, err := c.FormCreate(f)
	if err != nil {
		return err
	}
	return prettyJSON(created)
}

func cmdEdit() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: gforms edit <slug>")
	}
	slug := os.Args[1]
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	current, err := c.FormGet(slug)
	if err != nil {
		return err
	}
	body, err := form.DumpYAML(current)
	if err != nil {
		return err
	}
	// Round-trip through a temp file so the user can back out with :q!.
	tmp, err := os.CreateTemp("", "gforms-*.yaml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	// Editors may be "vim -u NONE" etc.; split into fields.
	parts := strings.Fields(editor)
	parts = append(parts, tmpPath)
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor exited non-zero: %w", err)
	}

	edited, err := form.LoadYAML(tmpPath)
	if err != nil {
		return fmt.Errorf("re-parse edited yaml: %w", err)
	}
	updated, err := c.FormUpdate(slug, edited)
	if err != nil {
		return err
	}
	return prettyJSON(updated)
}

func cmdShow() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: gforms show <slug>")
	}
	slug := os.Args[1]
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	f, err := c.FormGet(slug)
	if err != nil {
		return err
	}
	return prettyJSON(f)
}

func cmdFreeze() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: gforms freeze <slug>")
	}
	slug := os.Args[1]
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	if err := c.FormFreeze(slug); err != nil {
		return err
	}
	fmt.Printf("froze %s\n", slug)
	return nil
}

func cmdList() error {
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	forms, err := c.FormList()
	if err != nil {
		return err
	}
	if len(forms) == 0 {
		fmt.Println("(no forms)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SLUG\tTITLE\tVERSION\tFROZEN\tCREATED_AT")
	for _, f := range forms {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%t\t%s\n", f.Slug, f.Title, f.Version, f.Frozen, f.CreatedAt)
	}
	return tw.Flush()
}

// ── token commands ──────────────────────────────────────────────────────

func cmdMint() error {
	args := os.Args[1:]
	if len(args) < 1 {
		return fmt.Errorf("usage: gforms mint <slug> [--hint NAME] [--days N] [--uses N]")
	}
	slug := args[0]
	req := api.MintReq{}
	i := 1
	for i < len(args) {
		a := args[i]
		val := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", a)
			}
			v := args[i+1]
			i += 2
			return v, nil
		}
		switch {
		case a == "--hint":
			v, err := val()
			if err != nil {
				return err
			}
			req.Hint = v
		case a == "--days":
			v, err := val()
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("--days: %w", err)
			}
			req.Days = n
		case a == "--uses":
			v, err := val()
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("--uses: %w", err)
			}
			req.MaxUses = n
		default:
			return fmt.Errorf("unknown arg: %s", a)
		}
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	resp, err := c.TokenMint(slug, req)
	if err != nil {
		return err
	}
	url := resp.URL
	if url == "" {
		url = "https://f.kelliher.info/" + resp.Token
	}
	fmt.Printf("Token: %s\n", resp.Token)
	fmt.Printf("URL:   %s\n", url)
	return nil
}

func cmdTokens() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: gforms tokens <slug>")
	}
	slug := os.Args[1]
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	toks, err := c.TokenList(slug)
	if err != nil {
		return err
	}
	if len(toks) == 0 {
		fmt.Println("(no tokens)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tHINT\tUSES/MAX\tEXPIRES\tREVOKED")
	for _, t := range toks {
		usage := fmt.Sprintf("%d/%d", t.Uses, t.MaxUses)
		if t.MaxUses == 0 {
			usage = fmt.Sprintf("%d/∞", t.Uses)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\n", t.ID, t.Hint, usage, t.ExpiresAt, t.Revoked)
	}
	return tw.Flush()
}

func cmdRevoke() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: gforms revoke <token-id>")
	}
	id := os.Args[1]
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	if err := c.TokenRevoke(id); err != nil {
		return err
	}
	fmt.Printf("revoked %s\n", id)
	return nil
}

// ── response commands ──────────────────────────────────────────────────

func cmdResponses() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: gforms responses <slug> [--json]")
	}
	slug := os.Args[1]
	jsonOut := false
	for _, a := range os.Args[2:] {
		if a == "--json" {
			jsonOut = true
		} else {
			return fmt.Errorf("unknown arg: %s", a)
		}
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	if jsonOut {
		raw, err := c.ResponseListRaw(slug)
		if err != nil {
			return err
		}
		return prettyRaw(raw)
	}
	items, err := c.ResponseList(slug)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("(no responses)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSUBMITTED_AT\tTOKEN_HINT\tFIELDS_SUMMARY")
	for _, r := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.SubmittedAt, r.TokenHint, summarizeAnswers(r.Answers))
	}
	return tw.Flush()
}

// summarizeAnswers joins the first three non-blob answers, comma-separated
// and truncated. Blob answers (typically map[string]any with a "blob_id"
// key) are skipped so signatures/file uploads don't dominate the row.
func summarizeAnswers(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	// Sort keys for deterministic output.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple lexical sort; the API doesn't guarantee order anyway.
	sortStrings(keys)
	parts := []string{}
	for _, k := range keys {
		if len(parts) >= 3 {
			break
		}
		v := m[k]
		if isBlobAnswer(v) {
			continue
		}
		s := fmt.Sprintf("%s=%s", k, truncate(fmt.Sprintf("%v", v), 24))
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func isBlobAnswer(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, hasBlob := m["blob_id"]
	return hasBlob
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func sortStrings(ss []string) {
	// Tiny insertion sort — the field lists are short.
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j-1] > ss[j]; j-- {
			ss[j-1], ss[j] = ss[j], ss[j-1]
		}
	}
}

func cmdResponse() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: gforms response <id>")
	}
	id := os.Args[1]
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	raw, err := c.ResponseGet(id)
	if err != nil {
		return err
	}
	return prettyRaw(raw)
}

func cmdFetch() error {
	args := os.Args[1:]
	if len(args) < 1 {
		return fmt.Errorf("usage: gforms fetch <blob-id> [-o FILE]")
	}
	id := args[0]
	dst := ""
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" || a == "--output":
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", a)
			}
			dst = args[i+1]
			i++
		case strings.HasPrefix(a, "--output="):
			dst = strings.TrimPrefix(a, "--output=")
		default:
			return fmt.Errorf("unknown arg: %s", a)
		}
	}
	c, err := newAPIClient()
	if err != nil {
		return err
	}
	path, err := c.BlobFetch(id, dst)
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(path)
	fmt.Printf("wrote %s\n", abs)
	return nil
}
