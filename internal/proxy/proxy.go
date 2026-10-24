package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/yourorg/agent-auth-proxy/internal/auth"
)

// TargetFor mirrors targetUrlFor() + sandboxPortFor(): builds the in-cluster
// service DNS name for the sandbox. /files always uses port 80 for the browser
// flow; every other path uses the target port carried in the authenticated
// token claims. API bearer tokens always use their port claim so they can
// never be routed to the /files port.
func TargetFor(claims *auth.AgentClaims, path string) *url.URL {
	port := strconv.Itoa(claims.Port)
	if claims.Type != auth.TokenTypeAPI && strings.HasPrefix(path, "/files") {
		port = "80"
	}
	host := fmt.Sprintf("%s.%s.svc.cluster.local", claims.ClaimID, claims.Namespace)
	return &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%s", host, port),
	}
}

// stripHeaders removes the headers that must not be forwarded to the sandbox,
// mirroring requestHeadersForSandbox(). Auth-proxy's own session cookie is
// stripped so the sandbox never sees it; any app cookies are preserved.
// Authorization, Origin, and Referer belong to the target and are preserved.
func stripHeaders(h http.Header) {
	h.Del("X-Forwarded-Uri")
	h.Del("Proxy-Authorization")
}

func stripAuthProxyCookie(h http.Header) {
	raw := h.Get("Cookie")
	if raw == "" {
		return
	}
	parts := strings.Split(raw, ";")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if strings.HasPrefix(trimmed, auth.CookieName+"=") {
			continue
		}
		kept = append(kept, trimmed)
	}
	if len(kept) == 0 {
		h.Del("Cookie")
		return
	}
	h.Set("Cookie", strings.Join(kept, "; "))
}

// stripTokenParam removes the one-time ?token= param before forwarding to
// the sandbox, mirroring forwardedUrl.searchParams.delete("token").
func stripTokenParam(rawQuery string) string {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	q.Del("token")
	return q.Encode()
}

// New builds a *httputil.ReverseProxy whose target is resolved per-request
// from the AgentClaims stored in the request context by the auth middleware.
// WebSocket upgrades (Connection: Upgrade) are handled transparently by
// ReverseProxy since Go 1.12 - no separate WS relay code needed.
func New() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			ctx := pr.In.Context()
			claims := ClaimsFromContext(ctx)
			forwarded := ForwardedURLFromContext(ctx) // path+query as seen by the client
			isAPI := claims.Type == auth.TokenTypeAPI

			target := TargetFor(claims, forwarded.Path)
			pr.SetURL(target)
			pr.Out.Host = target.Host // ensure Host header matches target, not original

			pr.Out.URL.Path = forwarded.Path
			if isAPI {
				pr.Out.URL.RawQuery = forwarded.RawQuery
			} else {
				pr.Out.URL.RawQuery = stripTokenParam(forwarded.RawQuery)
			}

			stripHeaders(pr.Out.Header)
			stripAuthProxyCookie(pr.Out.Header)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
		// The proxy URL is used as the iframe source and can remain stable while
		// the sandbox content changes. Override any upstream cache policy so
		// browsers and intermediary CDNs always fetch the current response.
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("Cache-Control", "no-store, max-age=0")
			return nil
		},
	}
}
