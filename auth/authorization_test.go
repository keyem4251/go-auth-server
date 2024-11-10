package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"auth/authorization"
	"auth/db"
)

func TestHandleAuthorizeRequest(t *testing.T) {
	db := db.NewAuthDB()
	authRepo := authorization.NewAuthorizationRepository(db)
	ah := authorization.NewAuthorizeHandler(authRepo)

	endpoint := "/authorize"
	responseType := "response_type=code"
	clientId := "client_id=" + os.Getenv("CLIENT_ID")
	redirectUri := "redirect_uri=" + os.Getenv("REDIRECT_URI")
	state := "state=xyz"
	codeChallenge := "code_challenge=123111111111111111111111111111111111111111111111111111111111"
	codeChallengeMethod := "code_challenge_method=plain"
	getParameter := "?" + responseType + "&" + clientId + "&" + redirectUri + "&" + state + "&" + codeChallenge + "&" + codeChallengeMethod
	req := httptest.NewRequest(http.MethodGet, endpoint+getParameter, nil)
	w := httptest.NewRecorder()
	ah.HandleAuthorizeRequest(w, req)
	if w.Result().StatusCode != 302 {
		t.Errorf("status code is not 302: %v\n", w.Result().StatusCode)
	}
}
