package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	accessToken string,
	tokenType string,
	refreshToken string,
) *Token {
	return &Token{
		ClientId:     clientId,
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
	}
}

type TokenHandler struct {
	AuthRepo  *AuthorizationRepository
	TokenRepo *TokenRepository
}

func NewTokenHandler(
	authRepo *AuthorizationRepository,
	tokenRepo *TokenRepository,
) *TokenHandler {
	return &TokenHandler{
		AuthRepo:  authRepo,
		TokenRepo: tokenRepo,
	}
}

func (th *TokenHandler) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	// トークンリクエストを検証
	if !th.validateTokenRequest(r) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 認証ヘッダーを検証
	// client secretを確認
	// client idを取得して、データベースの値を取得
	clientId, clientSecret, err := th.parseAuthorizationHeader(r)
	if err != nil {
		log.Printf("Error: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !th.validateClientSecret(clientSecret) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	authorizationCode, err := th.AuthRepo.FindOne(clientId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// PKCEリクエストを検証
	// client idから取得した値とcode challengeの値を作成して、検証
	if !th.validatePKCERequest(authorizationCode, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// アクセス、リフレッシュトークンを作成
	// リフレッシュトークンはアクセストークンを発行するために必要
	// 期限はアクセストークンが短い、リフレッシュトークンが長い
	// アクセストークンの発行にはリフレッシュトークンと合わせてClientId,ClientSecretも必要
	access, refresh, accessErr, refreshErr := th.createJwtToken(clientId, false)
	if accessErr != nil {
		log.Println(accessErr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if refreshErr != nil {
		log.Println(refreshErr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	tokenType := "Bearer"

	// トークンを保存
	token := NewToken(clientId, access, tokenType, refresh)
	saveErr := th.TokenRepo.Save(token)
	if saveErr != nil {
		log.Println("保存エラー")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// レスポンスを作成
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"token_type":    tokenType,
		"refresh_token": refresh,
	})
}

func (th *TokenHandler) validateTokenRequest(r *http.Request) bool {
	if r.Method != "POST" {
		log.Println("request method must be POST")
		return false
	}

	if r.FormValue("grant_type") != "authorization_code" {
		log.Println("grant_type must be authorization_code")
		return false
	}

	if r.FormValue("redirect_uri") != os.Getenv("REDIRECT_URI") {
		log.Println("redirect_uri is wrong")
		return false
	}

	return true
}

func (th *TokenHandler) parseAuthorizationHeader(r *http.Request) (string, string, error) {
	// 例）Authorization: Basic <BASE64エンコードしたユーザ名:パスワード>
	authorizationHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorizationHeader, "Basic") {
		return "", "", fmt.Errorf("authorization header is not basic")
	}
	basic := strings.Split(authorizationHeader, "Basic ")[1]
	decoded, err := base64.StdEncoding.DecodeString(basic)
	if err != nil {
		return "", "", err
	}
	clientId := strings.Split(string(decoded), ":")[0]
	clientSecret := strings.Split(string(decoded), ":")[1]
	return clientId, clientSecret, nil
}

func (th *TokenHandler) validateClientSecret(clientSecret string) bool {
	if clientSecret != os.Getenv("CLIENT_SECRET") {
		log.Println("client secret is wrong")
		return false
	}
	return true
}

func (th *TokenHandler) validatePKCERequest(authorizationCode *AuthorizationCode, r *http.Request) bool {
	if authorizationCode.CodeChallenge == nil && authorizationCode.CodeChallengeMethod == nil {
		return true
	}

	codeVerifier := r.FormValue("code_verifier")
	if codeVerifier == "" {
		log.Println("code_verifier is empty")
		return false
	}

	// code_challengeでcode_verifierを変換して、保存されているcode_challengeと比較
	codeChallenge := getCodeChallenge(codeVerifier, *authorizationCode.CodeChallengeMethod)
	if codeChallenge != *authorizationCode.CodeChallenge {
		log.Println("code_verifier is wrong")
		return false
	}
	return true
}

func getCodeChallenge(codeVerifier string, codeChallengeMethod string) string {
	if codeChallengeMethod == "plain" {
		return codeVerifier
	}

	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashed := h.Sum(nil)

	codeChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hashed)
	return codeChallenge
}

func (th *TokenHandler) createJwtToken(clientId string, isRefresh bool) (string, string, error, error) {
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
		return "", "", accessTokenErr, nil
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
			return "", "", nil, refreshTokenErr
		}
	}
	return accessTokenString, refreshTokenString, nil, nil
}
