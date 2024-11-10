package token

import (
	"auth/authorization"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Token struct {
	ClientId     string
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
}

func NewToken(
	clientId string,
	isRefresh bool,
) (*Token, error, error) {
	accessClaims := jwt.RegisteredClaims{
		Issuer:    "issuer",                                             // トークン発行者の識別子: URI形式（"https://example.us.auth0.com"）
		Subject:   clientId,                                             // 認証の対象となるユーザのID（クライアントIDではなくユーザー: "auth0|...." auth0でのユーザーIDとか）
		Audience:  []string{clientId},                                   // トークンを利用する対象（APIなど: "http://localhost:8080"とか）
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 + time.Minute)), // トークンの有効期限
		NotBefore: jwt.NewNumericDate(time.Now()),                       // トークンが有効となる日時
		IssuedAt:  jwt.NewNumericDate(time.Now()),                       // トークンの発行日時
		ID:        "id",                                                 // JWT の一意の ID
	}
	access := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	accessTokenString, accessTokenErr := access.SignedString(priv)
	if accessTokenErr != nil {
		log.Println("access token create error")
		return nil, accessTokenErr, nil
	}

	refreshTokenString := ""
	var refreshTokenErr error
	if isRefresh {
		RefreshTokenClaims := jwt.RegisteredClaims{
			Issuer:    "issuer",
			Subject:   "subject",
			Audience:  []string{"audienct"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "id",
		}
		refresh := jwt.NewWithClaims(jwt.SigningMethodES256, RefreshTokenClaims)
		refreshTokenString, refreshTokenErr = refresh.SignedString(priv)
		if refreshTokenErr != nil {
			log.Println("refresh token create error")
			return nil, nil, refreshTokenErr
		}
	}
	return &Token{
		ClientId:     clientId,
		AccessToken:  accessTokenString,
		TokenType:    "Bearer",
		RefreshToken: refreshTokenString,
	}, nil, nil
}

type TokenRequest struct {
	Method              string
	GrantType           string
	RedirectUri         string
	AuthorizationHeader string
	CodeVerifier        string
}

func NewTokenRequest(r *http.Request) *TokenRequest {
	return &TokenRequest{
		Method:              r.Method,
		GrantType:           r.FormValue("grant_type"),
		RedirectUri:         r.FormValue("redirect_uri"),
		AuthorizationHeader: r.Header.Get("Authorization"),
		CodeVerifier:        r.FormValue("code_verifier"),
	}
}

func (tr *TokenRequest) validateTokenRequest() bool {
	if tr.Method != "POST" {
		log.Println("request method must be POST")
		return false
	}

	if tr.GrantType != "authorization_code" {
		log.Println("grant_type must be authorization_code")
		return false
	}

	if tr.RedirectUri != os.Getenv("REDIRECT_URI") {
		log.Println("redirect_uri is wrong")
		return false
	}

	return true
}

func (tr *TokenRequest) parseAuthorizationHeader() (string, error) {
	// 例）Authorization: Basic <BASE64エンコードしたユーザ名:パスワード>
	if !strings.HasPrefix(tr.AuthorizationHeader, "Basic") {
		return "", fmt.Errorf("authorization header is not basic")
	}
	basic := strings.Split(tr.AuthorizationHeader, "Basic ")[1]
	decoded, err := base64.StdEncoding.DecodeString(basic)
	if err != nil {
		return "", err
	}
	clientId := strings.Split(string(decoded), ":")[0]
	clientSecret := strings.Split(string(decoded), ":")[1]

	if clientSecret != os.Getenv("CLIENT_SECRET") {
		return "", fmt.Errorf("client secret is wrong")
	}

	return clientId, nil
}

func (tr *TokenRequest) validatePKCERequest(authorizationCode *authorization.AuthorizationCode) bool {
	if authorizationCode.CodeChallenge == nil && authorizationCode.CodeChallengeMethod == nil {
		return true
	}

	if tr.CodeVerifier == "" {
		log.Println("code_verifier is empty")
		return false
	}

	// code_challengeでcode_verifierを変換して、保存されているcode_challengeと比較
	codeChallenge := tr.getCodeChallenge(tr.CodeVerifier, *authorizationCode.CodeChallengeMethod)
	if codeChallenge != *authorizationCode.CodeChallenge {
		log.Println("code_verifier is wrong")
		return false
	}
	return true
}

func (tr *TokenRequest) getCodeChallenge(codeVerifier string, codeChallengeMethod string) string {
	if codeChallengeMethod == "plain" {
		return codeVerifier
	}

	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashed := h.Sum(nil)

	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)
	return codeChallenge
}
