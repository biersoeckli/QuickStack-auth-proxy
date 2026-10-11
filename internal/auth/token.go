package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	Issuer     = "quickstack-auth-proxy"
	CookieName = "qs-auth-proxy-session"

	// TokenTypeAPI marks an access token that is used directly (reusable) as a
	// bearer credential for API/WebSocket traffic instead of being exchanged
	// for a session cookie.
	TokenTypeAPI = "api"
)

// AgentClaims mirrors AgentAccessTokenPayload from the Bun implementation.
// Type is optional for the browser/session flow and must be "api" for tokens
// that are sent as a bearer credential and routed directly to the target.
type AgentClaims struct {
	AgentID   string `json:"agentId"`
	ClaimID   string `json:"claimId"`
	Namespace string `json:"namespace"`
	Port      int    `json:"port"`
	Type      string `json:"type,omitempty"`
	jwt.RegisteredClaims
}

// validPort accepts TCP ports that can be used as a sandbox target.
func validPort(p int) bool {
	return p >= 1 && p <= 65535
}

// sessionSecret is generated once per process, exactly like the Bun version's
// crypto.getRandomValues(new Uint8Array(32)). This means sessions don't survive
// a pod restart - if you run >1 replica or want restarts to preserve sessions,
// move this to a Kubernetes Secret shared across replicas instead.
var sessionSecret = randomSecret()

var consumedAccessTokens = struct {
	sync.Mutex
	jtiExpiry map[string]time.Time
}{jtiExpiry: make(map[string]time.Time)}

func randomSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("failed to generate session secret: %w", err))
	}
	return b
}

func sessionTTL() time.Duration {
	v := os.Getenv("AGENT_SESSION_JWT_TTL_SECONDS")
	if v == "" {
		v = "3600"
	}
	secs, err := strconv.Atoi(v)
	if err != nil {
		secs = 3600
	}
	return time.Duration(secs) * time.Second
}

// accessTokenTTL is deliberately short because a URL token is only used once
// to establish the longer-lived session cookie.
func accessTokenTTL() time.Duration {
	v := os.Getenv("AGENT_ACCESS_TOKEN_TTL_SECONDS")
	if v == "" {
		v = "60"
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		secs = 60
	}
	return time.Duration(secs) * time.Second
}

// VerifyAccessToken validates the single-use token passed as ?token=... using
// the shared long-lived secret (AGENT_JWT_SECRET), equivalent to jose's
// jwtVerify with HS256 in the original implementation.
func VerifyAccessToken(tokenStr string) (*AgentClaims, error) {
	secret := os.Getenv("AGENT_JWT_SECRET")
	if secret == "" {
		return nil, errors.New("AGENT_JWT_SECRET is required")
	}
	claims, err := parseAndValidate(tokenStr, []byte(secret))
	if err != nil {
		return nil, err
	}
	if claims.ID == "" || claims.ExpiresAt == nil {
		return nil, errors.New("invalid access token payload. Missing jti or exp")
	}
	if claims.Type == TokenTypeAPI {
		return nil, errors.New("invalid access token payload. api tokens must be supplied as a bearer token")
	}
	if isAccessTokenConsumed(claims.ID) {
		return nil, errors.New("access token has already been consumed")
	}
	return claims, nil
}

// VerifyAPIToken validates a reusable API token supplied as an
// "Authorization: Bearer <jwt>" credential. Unlike the one-time exchange token
// it is intentionally allowed to be reused and is never added to the replay
// store; it is only bounded by its exp claim.
func VerifyAPIToken(tokenStr string) (*AgentClaims, error) {
	secret := os.Getenv("AGENT_JWT_SECRET")
	if secret == "" {
		return nil, errors.New("AGENT_JWT_SECRET is required")
	}
	claims, err := parseAndValidate(tokenStr, []byte(secret))
	if err != nil {
		return nil, err
	}
	if claims.ExpiresAt == nil {
		return nil, errors.New("invalid api token payload. Missing exp")
	}
	if claims.Type != TokenTypeAPI {
		return nil, fmt.Errorf("invalid api token payload. type must be %q", TokenTypeAPI)
	}
	return claims, nil
}

// BearerToken extracts the credential from an Authorization header. It returns
// false when the header is absent or does not use the Bearer scheme.
func BearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// VerifySessionToken validates the HttpOnly cookie session token, signed with
// the process-local sessionSecret (equivalent to verifySessionToken in Bun).
func VerifySessionToken(tokenStr string) (*AgentClaims, error) {
	return parseAndValidate(tokenStr, sessionSecret)
}

func parseAndValidate(tokenStr string, secret []byte) (*AgentClaims, error) {
	claims := &AgentClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	}, jwt.WithIssuer(Issuer), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if claims.AgentID == "" || claims.ClaimID == "" || claims.Namespace == "" {
		return nil, errors.New("invalid token payload")
	}
	if !validPort(claims.Port) {
		return nil, errors.New("invalid token payload. Missing or invalid port")
	}
	return claims, nil
}

// ConsumeAccessToken records a successfully exchanged access-token jti until its
// expiry. The proxy is single-replica, so this in-memory store enforces one use.
func ConsumeAccessToken(c *AgentClaims) error {
	if c.ID == "" || c.ExpiresAt == nil {
		return errors.New("invalid access token jti")
	}

	consumedAccessTokens.Lock()
	defer consumedAccessTokens.Unlock()
	pruneConsumedAccessTokens(time.Now())
	if _, exists := consumedAccessTokens.jtiExpiry[c.ID]; exists {
		return errors.New("access token has already been consumed")
	}
	consumedAccessTokens.jtiExpiry[c.ID] = c.ExpiresAt.Time
	return nil
}

func isAccessTokenConsumed(jti string) bool {
	consumedAccessTokens.Lock()
	defer consumedAccessTokens.Unlock()
	pruneConsumedAccessTokens(time.Now())
	_, exists := consumedAccessTokens.jtiExpiry[jti]
	return exists
}

func pruneConsumedAccessTokens(now time.Time) {
	for jti, expiry := range consumedAccessTokens.jtiExpiry {
		if !expiry.After(now) {
			delete(consumedAccessTokens.jtiExpiry, jti)
		}
	}
}

// CreateSessionToken mints the short-lived session JWT stored in the cookie,
// equivalent to createSessionToken in the Bun implementation.
func CreateSessionToken(c *AgentClaims) (string, error) {
	now := time.Now()
	newClaims := AgentClaims{
		AgentID:   c.AgentID,
		ClaimID:   c.ClaimID,
		Namespace: c.Namespace,
		Port:      c.Port,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   c.Subject,
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTTL())),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	return token.SignedString(sessionSecret)
}

// SessionCookie builds the Set-Cookie header value, mirroring sessionCookie().
func SessionCookie(token string, r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
}

// ForwardedURI reconstructs the original request URL the way an ingress
// forward-auth setup provides it (equivalent to getForwardedUri()).
func ForwardedURI(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Uri"); v != "" {
		return v
	}
	return r.URL.RequestURI()
}

// ParseForwardedURL turns the forwarded URI string into a *url.URL, mirroring
// getUrlFromForwardedUri (base is irrelevant, only used to satisfy url.Parse).
func ParseForwardedURL(forwardedURI string) (*url.URL, error) {
	return url.Parse(forwardedURI)
}

// ExternalOrigin mirrors getExternalOrigin() for building the redirect Location.
func ExternalOrigin(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = r.URL.Scheme
	}
	if proto == "" {
		proto = "http"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Header.Get("Host")
	}
	if host == "" {
		host = r.Host
	}
	return fmt.Sprintf("%s://%s", proto, host)
}
