package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHandlTokenRequest(t *testing.T) {
	db := NewAuthDB()
	authRepo := NewAuthorizationRepository(db)
	tokenRepo := NewTokenRepository(db)
	th := NewTokenHandler(authRepo, tokenRepo)

	endpoint := "/token"
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// フォームフィールドを追加
	err := writer.WriteField("grant_type", "authorization_code")
	if err != nil {
		t.Fatalf("WriteField() error: %v", err)
	}
	err = writer.WriteField("redirect_uri", os.Getenv("REDIRECT_URI"))
	if err != nil {
		t.Fatalf("WriteField() error: %v", err)
	}
	err = writer.WriteField("code_verifier", "12343317382973291991938819928910374757839873781994008277893")
	if err != nil {
		t.Fatalf("WriteField() error: %v", err)
	}

	// Writerを閉じてContent-Typeを設定
	writer.Close()

	// httptest.NewRequest で POST リクエストを作成
	req := httptest.NewRequest(http.MethodPost, endpoint, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	clientId := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	basic := clientId + ":" + clientSecret
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basic)))

	w := httptest.NewRecorder()
	th.HandleTokenRequest(w, req)
	if w.Result().StatusCode != 200 {
		t.Errorf("status code is not 200: %v\n", w.Result().StatusCode)
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	if tokenType, ok := response["token_type"]; !ok || tokenType != "Bearer" {
		t.Errorf("unexpected token type: %v\n", tokenType)
	}
	if accessToken, ok := response["access_token"].(string); !ok || len([]rune(accessToken)) == 0 {
		t.Errorf("unexpected access token: %v\n", accessToken)
	}
}
