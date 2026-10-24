package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yourorg/agent-auth-proxy/internal/auth"
	"github.com/yourorg/agent-auth-proxy/internal/proxy"
)

type debugResponse struct {
	Error string `json:"error"`
	Debug struct {
		Stage           string `json:"stage"`
		RequestWasHTTPS bool   `json:"requestWasHttps"`
	} `json:"debug"`
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func signedAccessToken(t *testing.T, secret, id string, expiresAt time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.AgentClaims{
		AgentID: "agent-1", ClaimID: "claim-1", Namespace: "project-1", Port: 8080,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: auth.Issuer, ID: id, IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	})
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tokenString
}

func signedAPIToken(t *testing.T, secret, id string, expiresAt time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.AgentClaims{
		AgentID: "agent-1", ClaimID: "claim-1", Namespace: "project-1", Port: 8080, Type: auth.TokenTypeAPI,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: auth.Issuer, ID: id, IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	})
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tokenString
}

func TestBearerAPITokenIsProxiedDirectly(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAPIToken(t, "test-secret", "api-direct", time.Now().Add(time.Hour))

	proxyCalled := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalled = true
		if got := r.URL.Path; got != "/api/items" {
			t.Errorf("upstream path = %q, want /api/items", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := handleRequest(backend)

	req := httptest.NewRequest(http.MethodGet, "/api/items?view=1", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if !proxyCalled {
		t.Fatal("bearer API request was not proxied directly")
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("cookies = %d, want 0 (no session exchange)", len(cookies))
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("bearer API request unexpectedly redirected")
	}
}

func TestBearerAPITokenCanBeReused(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAPIToken(t, "test-secret", "api-reuse", time.Now().Add(time.Hour))

	calls := 0
	handler := handleRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
		req.Header.Set("Proxy-Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d status = %d, want %d", i, rec.Code, http.StatusNoContent)
		}
	}
	if calls != 3 {
		t.Fatalf("upstream calls = %d, want 3", calls)
	}
}

func TestBearerAPITokenUsesPortClaimForFiles(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAPIToken(t, "test-secret", "api-files", time.Now().Add(time.Hour))

	var targets []string
	rp := proxy.New()
	rp.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		targets = append(targets, r.URL.Host)
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	handler := handleRequest(rp)

	for _, path := range []string{"/api/items", "/files/download"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Proxy-Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d, want %d", path, rec.Code, http.StatusNoContent)
		}
	}
	want := []string{"claim-1.project-1.svc.cluster.local:8080", "claim-1.project-1.svc.cluster.local:8080"}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", targets, want)
	}
}

func TestBearerAPITokenPreservesTargetHeadersAndStripsProxyAuthorization(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAPIToken(t, "test-secret", "api-headers", time.Now().Add(time.Hour))

	var gotOrigin, gotAuth, gotTargetAuth, gotProxyAuth string
	rp := proxy.New()
	rp.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		gotOrigin = r.Header.Get("Origin")
		gotAuth = r.Header.Get("Authorization")
		gotTargetAuth = r.Header.Get("TargetAuthorization")
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	handler := handleRequest(rp)

	req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+token)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	req.Header.Set("TargetAuthorization", "Basic dXNlcjpwYXNz")
	req.Header.Set("Origin", "https://app.example.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if gotOrigin != "https://app.example.test" {
		t.Fatalf("upstream Origin = %q, want preserved", gotOrigin)
	}
	if gotAuth != "Basic dXNlcjpwYXNz" {
		t.Fatalf("upstream Authorization = %q, want preserved", gotAuth)
	}
	if gotTargetAuth != "Basic dXNlcjpwYXNz" {
		t.Fatalf("upstream TargetAuthorization = %q, want preserved", gotTargetAuth)
	}
	if gotProxyAuth != "" {
		t.Fatalf("upstream Proxy-Authorization = %q, want stripped", gotProxyAuth)
	}
}

func TestAuthorizationBearerAPITokenIsNotProxyAuthentication(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAPIToken(t, "test-secret", "api-no-target-auth", time.Now().Add(time.Hour))

	handler := handleRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Authorization must not authenticate the proxy")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestProxyAuthorizationMalformedIsRejected(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAPIToken(t, "test-secret", "api-target-auth-crlf", time.Now().Add(time.Hour))

	handler := handleRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("malformed Proxy-Authorization must not be proxied")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusProxyAuthRequired)
	}
	if got := rec.Header().Get("Proxy-Authenticate"); got != "Bearer" {
		t.Fatalf("Proxy-Authenticate = %q, want Bearer", got)
	}
}

func TestBearerAPITokenWrongTypeIsRejected(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.AgentClaims{
		AgentID: "agent-1", ClaimID: "claim-1", Namespace: "project-1", Port: 8080,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: auth.Issuer, ID: "not-api", IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	handler := handleRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request without api type should not be proxied")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusProxyAuthRequired)
	}
}

func TestBearerAPITokenDebugReportsBadTypeStage(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	t.Setenv("AUTH_PROXY_DEBUG_ENABLED", "true")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.AgentClaims{
		AgentID: "agent-1", ClaimID: "claim-1", Namespace: "project-1", Port: 8080,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: auth.Issuer, ID: "not-api-debug", IssuedAt: jwt.NewNumericDate(time.Now()), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	handleRequest(http.NotFoundHandler()).ServeHTTP(rec, req)

	var response debugResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode debug response: %v", err)
	}
	if response.Debug.Stage != "api_token_bad_type" {
		t.Fatalf("stage = %q, want api_token_bad_type", response.Debug.Stage)
	}
	if rec.Code != http.StatusProxyAuthRequired || rec.Header().Get("Proxy-Authenticate") != "Bearer" {
		t.Fatalf("proxy authentication response = (%d, %q), want (407, Bearer)", rec.Code, rec.Header().Get("Proxy-Authenticate"))
	}
}

func TestProxyAuthorizationTakesPrecedenceOverCookieAndQueryToken(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	accessToken := signedAccessToken(t, "test-secret", "priority-query", time.Now().Add(time.Hour))
	session, err := auth.CreateSessionToken(&auth.AgentClaims{AgentID: "agent-1", ClaimID: "claim-1", Namespace: "project-1", Port: 8080})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/items?token="+accessToken, nil)
	req.Header.Set("Proxy-Authorization", "Bearer invalid")
	req.AddCookie(auth.SessionCookie(session, req))
	rec := httptest.NewRecorder()
	handleRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("invalid Proxy-Authorization must not fall back to cookie or query token")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusProxyAuthRequired || rec.Header().Get("Proxy-Authenticate") != "Bearer" {
		t.Fatalf("proxy authentication response = (%d, %q), want (407, Bearer)", rec.Code, rec.Header().Get("Proxy-Authenticate"))
	}
}

func TestSessionFlowPreservesTargetHeaders(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAccessToken(t, "test-secret", "session-origin", time.Now().Add(time.Hour))

	var gotOrigin, gotReferer, gotAuth, gotTargetAuth string
	rp := proxy.New()
	rp.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		gotOrigin = r.Header.Get("Origin")
		gotReferer = r.Header.Get("Referer")
		gotAuth = r.Header.Get("Authorization")
		gotTargetAuth = r.Header.Get("TargetAuthorization")
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	handler := handleRequest(rp)

	exchange := httptest.NewRequest(http.MethodGet, "/dashboard?token="+token, nil)
	exchangeRec := httptest.NewRecorder()
	handler.ServeHTTP(exchangeRec, exchange)
	cookie := exchangeRec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", "https://app.example.test")
	req.Header.Set("Authorization", "Bearer application-token")
	req.Header.Set("Referer", "https://app.example.test/page")
	req.Header.Set("TargetAuthorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if gotOrigin != "https://app.example.test" {
		t.Fatalf("upstream Origin = %q, want preserved for session flow", gotOrigin)
	}
	if gotReferer != "https://app.example.test/page" {
		t.Fatalf("upstream Referer = %q, want preserved for session flow", gotReferer)
	}
	if gotAuth != "Bearer application-token" {
		t.Fatalf("upstream Authorization = %q, want preserved for session flow", gotAuth)
	}
	if gotTargetAuth != "Basic dXNlcjpwYXNz" {
		t.Fatalf("upstream TargetAuthorization = %q, want preserved", gotTargetAuth)
	}
}

func TestUnauthorizedWithoutTokenHasNoDebugResponse(t *testing.T) {
	t.Setenv("AUTH_PROXY_DEBUG_ENABLED", "true")
	rec := httptest.NewRecorder()
	handleRequest(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if rec.Header().Get("Content-Type") == "application/json" {
		t.Fatal("response unexpectedly contains debug JSON")
	}
}

func TestInvalidTokenWithoutDebugFlagHasNoDebugResponse(t *testing.T) {
	t.Setenv("AUTH_PROXY_DEBUG_ENABLED", "false")
	rec := httptest.NewRecorder()
	handleRequest(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?token=invalid", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if rec.Header().Get("Content-Type") == "application/json" {
		t.Fatal("response unexpectedly contains debug JSON")
	}
}

func TestDebugResponseForInvalidToken(t *testing.T) {
	t.Setenv("AUTH_PROXY_DEBUG_ENABLED", "true")
	rec := httptest.NewRecorder()
	handleRequest(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?token=invalid", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	var response debugResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode debug response: %v", err)
	}
	if response.Debug.Stage != "access_token_parse_error" {
		t.Fatalf("stage = %q, want access_token_parse_error", response.Debug.Stage)
	}
}

func TestDebugResponseForExpiredTokenIncludesHTTPHint(t *testing.T) {
	t.Setenv("AUTH_PROXY_DEBUG_ENABLED", "true")
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAccessToken(t, "test-secret", "expired-debug-token", time.Now().Add(-time.Minute))
	req := httptest.NewRequest(http.MethodGet, "/?token="+token, nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()
	handleRequest(http.NotFoundHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	var response debugResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode debug response: %v", err)
	}
	if response.Error != "unauthorized" || response.Debug.Stage != "access_token_expired" {
		t.Fatalf("response = %+v, want expired debug response", response)
	}
	if response.Debug.RequestWasHTTPS {
		t.Fatal("requestWasHttps = true, want false")
	}
}

func TestDebugResponseForReplayedToken(t *testing.T) {
	t.Setenv("AUTH_PROXY_DEBUG_ENABLED", "true")
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAccessToken(t, "test-secret", "replayed-debug-token", time.Now().Add(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/?token="+token, nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	handleRequest(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), req)
	rec := httptest.NewRecorder()
	handleRequest(http.NotFoundHandler()).ServeHTTP(rec, req)
	var response debugResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode debug response: %v", err)
	}
	if response.Debug.Stage != "access_token_replayed" {
		t.Fatalf("stage = %q, want access_token_replayed", response.Debug.Stage)
	}
}

func TestTokenRedirectSetsOriginalSessionCookie(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.AgentClaims{
		AgentID:   "agent-base-agent-c5bbc",
		ClaimID:   "ac-agent-base-agent-c5bbc-82393158",
		Namespace: "proj-agent-test-1-2cd39535",
		Port:      8080,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "jan.meier@ost.ch",
			Issuer:    auth.Issuer,
			ID:        "access-token-main-test",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?token="+tokenString+"&view=1", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "base-agent.90027620.quickstack.me")
	rec := httptest.NewRecorder()

	shouldNotProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should redirect before proxying")
	})
	handleRequest(shouldNotProxy).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "https://base-agent.90027620.quickstack.me/?view=1" {
		t.Fatalf("Location = %q", got)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != auth.CookieName {
		t.Fatalf("cookie name = %q", cookie.Name)
	}
	if !cookie.Secure {
		t.Fatal("cookie should be secure for https forwarded proto")
	}

	replayRecorder := httptest.NewRecorder()
	handleRequest(shouldNotProxy).ServeHTTP(replayRecorder, req)
	if replayRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want %d", replayRecorder.Code, http.StatusUnauthorized)
	}
}

func TestTokenExchangeSessionRequestIsProxied(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.AgentClaims{
		AgentID: "agent-1", ClaimID: "claim-1", Namespace: "project-1", Port: 8080,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: auth.Issuer, ID: "access-token-session-proxy-test",
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	proxyCalled := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := handleRequest(backend)

	exchangeReq := httptest.NewRequest(http.MethodGet, "/app?token="+tokenString, nil)
	exchangeReq.Header.Set("X-Forwarded-Proto", "https")
	exchangeReq.Header.Set("X-Forwarded-Host", "sandbox.example.test")
	exchangeRec := httptest.NewRecorder()
	handler.ServeHTTP(exchangeRec, exchangeReq)

	if exchangeRec.Code != http.StatusFound {
		t.Fatalf("exchange status = %d, want %d", exchangeRec.Code, http.StatusFound)
	}
	cookies := exchangeRec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("exchange cookies = %d, want 1", len(cookies))
	}

	sessionReq := httptest.NewRequest(http.MethodGet, "/app", nil)
	sessionReq.AddCookie(cookies[0])
	sessionRec := httptest.NewRecorder()
	handler.ServeHTTP(sessionRec, sessionReq)

	if sessionRec.Code != http.StatusNoContent {
		t.Fatalf("session status = %d, want %d", sessionRec.Code, http.StatusNoContent)
	}
	if !proxyCalled {
		t.Fatal("authenticated session request was not passed to the proxy")
	}
}

func TestSessionRequestUsesClaimPortAndFilesUses80(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAccessToken(t, "test-secret", "target-port-flow", time.Now().Add(time.Hour))
	var targets []string
	rp := proxy.New()
	rp.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		targets = append(targets, r.URL.Host)
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	handler := handleRequest(rp)

	exchange := httptest.NewRequest(http.MethodGet, "/dashboard?token="+token, nil)
	exchange.Header.Set("X-Forwarded-Proto", "https")
	exchangeRec := httptest.NewRecorder()
	handler.ServeHTTP(exchangeRec, exchange)
	cookie := exchangeRec.Result().Cookies()[0]
	for _, path := range []string{"/dashboard", "/files/download"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d, want %d", path, rec.Code, http.StatusNoContent)
		}
	}
	want := []string{"claim-1.project-1.svc.cluster.local:8080", "claim-1.project-1.svc.cluster.local:80"}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Fatalf("targets = %v, want %v", targets, want)
	}
}

func TestProxiedResponsesDisableCaching(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	token := signedAccessToken(t, "test-secret", "no-store-response", time.Now().Add(time.Hour))
	rp := proxy.New()
	rp.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Cache-Control": []string{"public, max-age=3600"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	})
	handler := handleRequest(rp)

	exchange := httptest.NewRequest(http.MethodGet, "/dashboard?token="+token, nil)
	exchangeRec := httptest.NewRecorder()
	handler.ServeHTTP(exchangeRec, exchange)
	cookie := exchangeRec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Fatalf("Cache-Control = %q, want no-store, max-age=0", got)
	}
}

func TestDebugRedirectLogsInternalTargetOnlyInDebugMode(t *testing.T) {
	t.Setenv("AGENT_JWT_SECRET", "test-secret")
	oldOutput := log.Writer()
	defer log.SetOutput(oldOutput)
	var logs bytes.Buffer
	log.SetOutput(&logs)

	for _, tc := range []struct {
		name, debug, path, want string
	}{
		{"regular", "true", "/dashboard", "internal_target=claim-1.project-1.svc.cluster.local:8080"},
		{"files", "true", "/files/download", "internal_target=claim-1.project-1.svc.cluster.local:80"},
		{"disabled", "false", "/dashboard", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AUTH_PROXY_DEBUG_ENABLED", tc.debug)
			logs.Reset()
			token := signedAccessToken(t, "test-secret", "debug-redirect-"+tc.name, time.Now().Add(time.Hour))
			req := httptest.NewRequest(http.MethodGet, tc.path+"?token="+token, nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			rec := httptest.NewRecorder()
			handleRequest(http.NotFoundHandler()).ServeHTTP(rec, req)
			if tc.want == "" {
				if logs.Len() != 0 {
					t.Fatalf("debug-disabled redirect logged %q", logs.String())
				}
				return
			}
			if !strings.Contains(logs.String(), tc.want) || strings.Contains(logs.String(), token) {
				t.Fatalf("log = %q, want %q without token", logs.String(), tc.want)
			}
		})
	}
}
