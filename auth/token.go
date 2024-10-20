package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type TokenHandler struct{}

func NewTokenHandler() *TokenHandler {
	return &TokenHandler{}
}

func (th *TokenHandler) HandleTokenHandler(w http.ResponseWriter, r *http.Request) {
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

	authorizationCode := getAuthorizationCode(clientId)

	// PKCEリクエストを検証
	// client idから取得した値とcode challengeの値を作成して、検証
	if !th.validatePKCERequest(*authorizationCode, r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// アクセス、リフレッシュトークンを作成
	// リフレッシュトークンはアクセストークンを発行するために必要
	// 期限はアクセストークンが短い、リフレッシュトークンが長い
	// アクセストークンの発行にはリフレッシュトークンと合わせてClientId,ClientSecretも必要
	access, refresh, _ := th.createToken(clientId, false)
	tokenType := "Bearer"
	expiresIn := 3600

	// トークンを保存
	fmt.Println(access)
	fmt.Println(refresh)
	fmt.Println(tokenType)
	fmt.Println(expiresIn)

	// レスポンスを作成
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"token_type":    tokenType,
		"expires_in":    expiresIn,
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

func getAuthorizationCode(clientId string) *AuthorizationCode {
	return &AuthorizationCode{
		ClientId:                clientId,
		RedirectUri:             "redirectUri",
		State:                   "state",
		Code:                    "code",
		CodeChallenge:           nil,
		CodeChallengeMethod:     nil,
		AuthResponseRedirectURL: "authResponseRedirectURL",
	}
}

func (th *TokenHandler) validatePKCERequest(authorizationCode AuthorizationCode, r *http.Request) bool {
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

func (th *TokenHandler) createToken(clientId string, isRefresh bool) (string, string, error) {
	buf := bytes.NewBufferString(clientId)
	now := time.Now()
	buf.WriteString(strconv.FormatInt(now.UnixNano(), 10))

	// jwtではなくmd5
	access := base64.URLEncoding.EncodeToString([]byte(uuid.NewMD5(uuid.Must(uuid.NewRandom()), buf.Bytes()).String()))
	access = strings.ToUpper(strings.TrimRight(access, "="))
	refresh := ""
	if isRefresh {
		refresh = base64.URLEncoding.EncodeToString([]byte(uuid.NewSHA1(uuid.Must(uuid.NewRandom()), buf.Bytes()).String()))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}
	return access, refresh, nil
}
