package auth

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DebugReport is safe to return or log when AUTH_PROXY_DEBUG_ENABLED is set.
// It deliberately excludes token and cookie values.
type DebugReport struct {
	Stage              string           `json:"stage"`
	Error              string           `json:"error,omitempty"`
	ForwardedProto     string           `json:"forwardedProto"`
	ForwardedHost      string           `json:"forwardedHost"`
	Host               string           `json:"host"`
	ExternalOrigin     string           `json:"externalOrigin"`
	ForwardedPath      string           `json:"forwardedPath"`
	RequestWasHTTPS    bool             `json:"requestWasHttps"`
	ServerTimeUTC      string           `json:"serverTimeUtc"`
	AccessToken        AccessTokenDebug `json:"accessToken"`
	CookiesPresent     []string         `json:"cookiesPresent"`
	SessionCookieFound bool             `json:"sessionCookieFound"`
	Config             DebugConfig      `json:"config"`
	Hint               string           `json:"hint"`
}

type AccessTokenDebug struct {
	Present            bool   `json:"present"`
	Iat                *int64 `json:"iat,omitempty"`
	Exp                *int64 `json:"exp,omitempty"`
	SecondsUntilExpiry *int64 `json:"secondsUntilExpiry,omitempty"`
	SecondsSinceExpiry *int64 `json:"secondsSinceExpiry,omitempty"`
}

type DebugConfig struct {
	AgentJWTSecretSet      bool  `json:"agentJwtSecretSet"`
	AccessTokenTTLSeconds  int64 `json:"accessTokenTtlSeconds"`
	SessionTokenTTLSeconds int64 `json:"sessionTokenTtlSeconds"`
}

// BuildDebugReport creates a diagnostic report without exposing secrets.
// tokenValue is the raw access or API token (if any) used to extract non-secret
// timing metadata; it is never included in the report.
func BuildDebugReport(r *http.Request, forwardedURL *url.URL, stage string, tokenErr error, tokenValue string) DebugReport {
	now := time.Now().UTC()
	report := DebugReport{
		Stage:           stage,
		ForwardedProto:  r.Header.Get("X-Forwarded-Proto"),
		ForwardedHost:   r.Header.Get("X-Forwarded-Host"),
		Host:            r.Host,
		ExternalOrigin:  ExternalOrigin(r),
		RequestWasHTTPS: strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || (r.Header.Get("X-Forwarded-Proto") == "" && r.TLS != nil),
		ServerTimeUTC:   now.Format(time.RFC3339),
		CookiesPresent:  cookieNames(r),
		Config: DebugConfig{
			AgentJWTSecretSet:      os.Getenv("AGENT_JWT_SECRET") != "",
			AccessTokenTTLSeconds:  int64(accessTokenTTL() / time.Second),
			SessionTokenTTLSeconds: int64(sessionTTL() / time.Second),
		},
	}
	report.SessionCookieFound = containsCookie(report.CookiesPresent, CookieName)
	if tokenErr != nil {
		report.Error = tokenErr.Error()
	}
	if forwardedURL != nil {
		report.ForwardedPath = redactedForwardedPath(forwardedURL)
	}
	report.AccessToken = decodeAccessTokenDebug(tokenValue, now)
	report.Hint = debugHint(stage, report.RequestWasHTTPS)
	return report
}

func StageForAccessTokenError(err error) string {
	if errors.Is(err, jwt.ErrTokenExpired) {
		return "access_token_expired"
	}
	if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		return "access_token_bad_issuer"
	}
	if strings.Contains(err.Error(), "already been consumed") {
		return "access_token_replayed"
	}
	if strings.Contains(err.Error(), "invalid token payload") {
		return "access_token_invalid_payload"
	}
	return "access_token_parse_error"
}

// StageForAPITokenError maps a VerifyAPIToken error to a stable debug stage.
func StageForAPITokenError(err error) string {
	if errors.Is(err, jwt.ErrTokenExpired) {
		return "api_token_expired"
	}
	if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		return "api_token_bad_issuer"
	}
	if strings.Contains(err.Error(), `type must be`) {
		return "api_token_bad_type"
	}
	if strings.Contains(err.Error(), "invalid token payload") || strings.Contains(err.Error(), "invalid api token payload") {
		return "api_token_invalid_payload"
	}
	return "api_token_parse_error"
}

// LogDebugRedirect records redirect metadata only. It deliberately excludes
// credentials such as the access token and session-cookie value.
func LogDebugRedirect(claims *AgentClaims, forwardedURL, target *url.URL, location string) {
	log.Printf("auth proxy debug redirect: external=%s internal_target=%s path=%s claimId=%s namespace=%s port=%d",
		location, target.Host, forwardedURL.Path, claims.ClaimID, claims.Namespace, claims.Port)
}

// LogDebugAPIRequest records the resolved internal target for a directly
// proxied API/WebSocket request. It deliberately excludes token values.
func LogDebugAPIRequest(claims *AgentClaims, forwardedURL, target *url.URL) {
	log.Printf("auth proxy debug api request: internal_target=%s path=%s claimId=%s namespace=%s port=%d",
		target.Host, forwardedURL.Path, claims.ClaimID, claims.Namespace, claims.Port)
}

func cookieNames(r *http.Request) []string {
	cookies := r.Cookies()
	names := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		names = append(names, cookie.Name)
	}
	return names
}

func containsCookie(names []string, target string) bool {
	for _, name := range names {
		if name == target {
			return true
		}
	}
	return false
}

func redactedForwardedPath(forwardedURL *url.URL) string {
	copy := *forwardedURL
	query := copy.Query()
	for key := range query {
		query.Set(key, "[REDACTED]")
	}
	copy.RawQuery = query.Encode()
	return copy.EscapedPath() + func() string {
		if copy.RawQuery == "" {
			return ""
		}
		return "?" + copy.RawQuery
	}()
}

func decodeAccessTokenDebug(tokenStr string, now time.Time) AccessTokenDebug {
	debug := AccessTokenDebug{Present: tokenStr != ""}
	if tokenStr == "" {
		return debug
	}
	claims := &AgentClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(tokenStr, claims)
	if err != nil {
		return debug
	}
	if claims.IssuedAt != nil {
		value := claims.IssuedAt.Unix()
		debug.Iat = &value
	}
	if claims.ExpiresAt != nil {
		value := claims.ExpiresAt.Unix()
		debug.Exp = &value
		seconds := claims.ExpiresAt.Time.Sub(now).Seconds()
		if seconds >= 0 {
			value := int64(seconds)
			debug.SecondsUntilExpiry = &value
		} else {
			value := int64(-seconds)
			debug.SecondsSinceExpiry = &value
		}
	}
	return debug
}

func debugHint(stage string, requestWasHTTPS bool) string {
	if !requestWasHTTPS {
		return "Request was not forwarded as HTTPS. Secure session cookies are not sent over HTTP."
	}
	switch stage {
	case "access_token_expired":
		return "Access token was expired when it was verified."
	case "access_token_replayed":
		return "Access token was already consumed and can only be used once."
	case "access_token_bad_issuer":
		return "Access token issuer does not match the auth proxy issuer."
	case "session_cookie_missing":
		return "Session cookie was not sent with this request."
	case "session_cookie_invalid":
		return "Session cookie could not be verified."
	case "session_creation_failed":
		return "Session token creation failed. Check auth proxy configuration and logs."
	case "forwarded_url_parse_error":
		return "Forwarded URL could not be parsed."
	case "api_token_expired":
		return "Proxy-Authorization bearer token was expired when it was verified."
	case "api_token_bad_issuer":
		return "Proxy-Authorization bearer token issuer does not match the auth proxy issuer."
	case "api_token_bad_type":
		return `Proxy-Authorization bearer token must carry the "type":"api" claim.`
	case "api_token_invalid_payload":
		return "Proxy-Authorization bearer token is missing a required claim or has an invalid port."
	case "api_token_parse_error":
		return "Proxy-Authorization bearer token could not be parsed or the signature is invalid."
	case "proxy_authorization_malformed":
		return "Proxy-Authorization must use the Bearer scheme with a non-empty token."
	default:
		return fmt.Sprintf("Authentication failed at stage %s.", stage)
	}
}
