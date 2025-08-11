package handlers

import (
    "crypto/ecdsa"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "time"

    "github.com/go-jose/go-jose/v3"
    "github.com/go-jose/go-jose/v3/jwt"
    "github.com/twocanoes/psso-server/pkg/constants"
    "github.com/twocanoes/psso-server/pkg/file"
)

type OIDCDiscoveryResponse struct {
    Issuer                string   `json:"issuer"`
    AuthorizationEndpoint string   `json:"authorization_endpoint"`
    TokenEndpoint         string   `json:"token_endpoint"`
    JWKSUri              string   `json:"jwks_uri"`
    ResponseTypesSupported []string `json:"response_types_supported"`
    SubjectTypesSupported  []string `json:"subject_types_supported"`
    IdTokenSigningAlgValues []string `json:"id_token_signing_alg_values_supported"`
}

func OIDCDiscovery() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        baseURL := "https://" + r.Host
        
        discovery := OIDCDiscoveryResponse{
            Issuer:                baseURL,
            AuthorizationEndpoint: baseURL + constants.EndpointOIDCAuth,
            TokenEndpoint:         baseURL + constants.EndpointOIDCToken,
            JWKSUri:              baseURL + constants.EndpointJWKS,
            ResponseTypesSupported: []string{"code"},
            SubjectTypesSupported:  []string{"public"},
            IdTokenSigningAlgValues: []string{"ES256"},
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(discovery)
    }
}

func OIDCAuth() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Extract query parameters
        clientID := r.URL.Query().Get("client_id")
        redirectURI := r.URL.Query().Get("redirect_uri")
        responseType := r.URL.Query().Get("response_type")
        state := r.URL.Query().Get("state")
        
        // Validate request
        if clientID != constants.OIDCClientID || responseType != "code" {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }
        
        // Check if user has existing PSSO session (from cookie/header)
        sessionID := r.Header.Get("X-Session-ID") // Or from cookie
        var session *file.UserSession
        
        if sessionID != "" {
            var err error
            session, err = file.GetSession(sessionID)
            if err != nil {
                session = nil // Session invalid/expired
            }
        }
        
        if session != nil {
            // User already authenticated via PSSO, create auth code
            authCode, err := generateAndSaveAuthCode(session.SessionID, clientID)
            if err != nil {
                http.Error(w, "Server error", http.StatusInternalServerError)
                return
            }
            
            redirectURL, _ := url.Parse(redirectURI)
            query := redirectURL.Query()
            query.Set("code", authCode)
            query.Set("state", state)
            redirectURL.RawQuery = query.Encode()
            
            http.Redirect(w, r, redirectURL.String(), http.StatusFound)
        } else {
            // No PSSO session, show login form or redirect to PSSO login
            // For now, just return error - in production you'd show login form
            http.Error(w, "Authentication required", http.StatusUnauthorized)
        }
    }
}

func OIDCToken() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }
        
        r.ParseForm()
        grantType := r.FormValue("grant_type")
        code := r.FormValue("code")
        clientID := r.FormValue("client_id")
        
        if grantType != "authorization_code" || clientID != constants.OIDCClientID {
            http.Error(w, "Invalid request", http.StatusBadRequest)
            return
        }
        
        // Get and validate auth code
        authCodeObj, err := file.GetAuthCode(code)
        if err != nil {
            http.Error(w, "Invalid code", http.StatusBadRequest)
            return
        }
        
        // Get user session
        session, err := file.GetSession(authCodeObj.SessionID)
        if err != nil {
            http.Error(w, "Invalid session", http.StatusUnauthorized)
            return
        }
        
        // Delete used auth code
        file.DeleteAuthCode(code)
        
        // Get signing key
        servicePrivateKey, err := jwksPrivateKey()
        if err != nil {
            http.Error(w, "Server error", http.StatusInternalServerError)
            return
        }
        
        jwks, _ := file.GetJWKS()
        
        // Create ID token with real user data from PSSO session
        idToken, err := createOIDCIDToken(servicePrivateKey, jwks.KID, session)
        if err != nil {
            http.Error(w, "Server error", http.StatusInternalServerError)
            return
        }
        
        tokenResponse := map[string]interface{}{
            "access_token": generateAccessToken(),
            "token_type":   "Bearer",
            "expires_in":   3600,
            "id_token":     idToken,
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(tokenResponse)
    }
}

// Helper functions
func generateAccessToken() string {
    return fmt.Sprintf("access_%d", time.Now().Unix())
}

func createOIDCIDToken(privateKey *ecdsa.PrivateKey, keyID string, session *file.UserSession) (string, error) {
    now := time.Now()
    
    claims := jwt.Claims{
        Issuer:   "https://" + constants.Issuer,
        Subject:  session.Username,
        Audience: jwt.Audience{constants.OIDCClientID},
        IssuedAt: jwt.NewNumericDate(now),
        Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
    }
    
    // Include rich user data from PSSO authentication
    privateClaims := map[string]interface{}{
        "auth_time":    session.CreatedAt.Unix(),
        "email":        session.Email,
        "name":         session.DisplayName,
        "groups":       session.Groups,
        "session_id":   session.SessionID,
        "auth_method":  session.AuthMethod,
    }
    
    // Create signer with the private key
    signer, err := jose.NewSigner(
        jose.SigningKey{
            Algorithm: jose.ES256,
            Key:       privateKey,
        },
        &jose.SignerOptions{
            ExtraHeaders: map[jose.HeaderKey]interface{}{
                jose.HeaderKey("kid"): keyID,
            },
        },
    )
    if err != nil {
        return "", fmt.Errorf("failed to create signer: %w", err)
    }
    
    // Build and sign the JWT
    builder := jwt.Signed(signer).Claims(claims).Claims(privateClaims)
    token, err := builder.CompactSerialize()
    if err != nil {
        return "", fmt.Errorf("failed to serialize token: %w", err)
    }
    
    return token, nil
}