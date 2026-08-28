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
