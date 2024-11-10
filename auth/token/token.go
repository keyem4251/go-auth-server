package token

import (
	"encoding/json"
	"log"
	"net/http"

	"auth/authorization"
)

type TokenHandler struct {
	AuthRepo  *authorization.AuthorizationRepository
	TokenRepo *TokenRepository
}

func NewTokenHandler(
	authRepo *authorization.AuthorizationRepository,
	tokenRepo *TokenRepository,
) *TokenHandler {
	return &TokenHandler{
		AuthRepo:  authRepo,
		TokenRepo: tokenRepo,
	}
}

func (th *TokenHandler) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	tr := NewTokenRequest(r)
	// トークンリクエストを検証
	if !tr.validateTokenRequest() {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 認証ヘッダーを検証
	// client secretを確認
	// client idを取得して、データベースの値を取得
	clientId, err := tr.parseAuthorizationHeader()
	if err != nil {
		log.Printf("Error: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	authorizationCode, err := th.AuthRepo.FindOne(clientId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// PKCEリクエストを検証
	// client idから取得した値とcode challengeの値を作成して、検証
	if !tr.validatePKCERequest(authorizationCode) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// アクセス、リフレッシュトークンを作成
	// リフレッシュトークンはアクセストークンを発行するために必要
	// 期限はアクセストークンが短い、リフレッシュトークンが長い
	// アクセストークンの発行にはリフレッシュトークンと合わせてClientId,ClientSecretも必要
	tk, accessErr, refreshErr := NewToken(clientId, false)
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

	// トークンを保存
	saveErr := th.TokenRepo.Save(tk)
	if saveErr != nil {
		log.Println("保存エラー")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// レスポンスを作成
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  tk.AccessToken,
		"token_type":    tk.TokenType,
		"refresh_token": tk.RefreshToken,
	})
}
