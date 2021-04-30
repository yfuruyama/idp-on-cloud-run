package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yfuruyama/crzerolog"
)

type IDTokenRequest struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
}

type TokenInfoSuccessResponse struct {
	Active bool   `json:"active"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
	Sub    string `json:"sub"`
	Aud    string `json:"aud"`
	Iss    string `json:"iss"`
}

type TokenInfoErrorResponse struct {
	Active bool `json:"active"`
}

type OIDCConfigurationResponse struct {
	Issuer                           string   `json:"issuer"`
	JWKsURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func main() {
	router := chi.NewRouter()
	rootLogger := zerolog.New(os.Stdout)
	middleware := crzerolog.InjectLogger(&rootLogger)

	keyResourceID := os.Getenv("KEY_RESOURCE_ID")
	if keyResourceID == "" {
		log.Fatal().Msg("env var KEY_RESOURCE_ID must be specified")
	}

	router.Post("/id_token", func(w http.ResponseWriter, r *http.Request) {
		var req IDTokenRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			handleError(r.Context(), w, err)
			return
		}
		issuer := fmt.Sprintf("https://%s", r.Host)

		idToken, err := GenerateIDToken(r.Context(), keyResourceID, req.Sub, req.Aud, issuer)
		if err != nil {
			handleError(r.Context(), w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(idToken); err != nil {
			handleError(r.Context(), w, err)
			return
		}
	})

	router.Get("/certs", func(w http.ResponseWriter, r *http.Request) {
		publicKey, err := GetPublicKey(r.Context(), keyResourceID)
		if err != nil {
			handleError(r.Context(), w, err)
			return
		}

		jwk, err := PublicKeyToJwk(publicKey, keyResourceID)
		if err != nil {
			handleError(r.Context(), w, err)
			return
		}

		jwkSet := &JWKSet{
			Keys: []*JWK{jwk},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwkSet); err != nil {
			handleError(r.Context(), w, err)
			return
		}
	})

	router.Get("/tokeninfo", func(w http.ResponseWriter, r *http.Request) {
		logger := log.Ctx(r.Context())
		publicKey, err := GetPublicKey(r.Context(), keyResourceID)
		if err != nil {
			handleError(r.Context(), w, err)
			return
		}

		jwk, err := PublicKeyToJwk(publicKey, keyResourceID)
		if err != nil {
			handleError(r.Context(), w, err)
			return
		}

		jwkSet := JWKSet{
			Keys: []*JWK{jwk},
		}

		idToken := r.URL.Query().Get("id_token")
		result, err := VerifyToken(idToken, jwkSet)
		if err != nil {
			handleError(r.Context(), w, err)
			return
		}

		if result.Valid {
			resp := &TokenInfoSuccessResponse{
				Active: true,
				Iat:    result.Body.Iat,
				Exp:    result.Body.Exp,
				Sub:    result.Body.Sub,
				Aud:    result.Body.Aud,
				Iss:    result.Body.Iss,
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				handleError(r.Context(), w, err)
				return
			}
		} else {
			logger.Info().Msgf("invalid id token: %s", result.ErrorDetail)
			resp := &TokenInfoErrorResponse{
				Active: false,
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				handleError(r.Context(), w, err)
				return
			}
		}
	})

	router.Get("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := fmt.Sprintf("https://%s", r.Host)
		jwkSetURL := fmt.Sprintf("https://%s/certs", r.Host)
		resp := &OIDCConfigurationResponse{
			Issuer:                           issuer,
			JWKsURI:                          jwkSetURL,
			IDTokenSigningAlgValuesSupported: []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			handleError(r.Context(), w, err)
			return
		}
	})

	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}
	log.Printf("Server listening on port %q", port)
	log.Fatal().Msg(http.ListenAndServe(":"+port, middleware(router)).Error())
}

func handleError(ctx context.Context, w http.ResponseWriter, err error) {
	logger := log.Ctx(ctx)
	logger.Err(err).Msg("")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "%s\n", http.StatusText(http.StatusInternalServerError))
}
