package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		log.Println("ping")
	})

	host := "0.0.0.0"
	port := "8080"
	log.Printf("listen start: %s:%s\n", host, port)
	http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), nil)
}

type AuthorizeHandler struct{}

func (ah *AuthorizeHandler) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	// リクエストの検証
	if !ah.validateRequest(r) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !ah.validatePKCERequest(r) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// それぞれの情報を取得
	cliendId := r.URL.Query().Get("client_id")
	redirect_uri := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	code_challenge := r.URL.Query().Get("code_challenge")
	code_challenge_method := r.URL.Query().Get("code_challenge_method")

	// データベースに情報を保存
	// TODO

	// リダイレクト
	redirectURL := os.Getenv("REDIRECT_URI") + "?code=" + code + "&state" + state
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (ah *AuthorizeHandler) validateRequest(r *http.Request) bool {
	switch {
	case r.Method != "GET":
		log.Println("request method must be GET")
		return false
	case r.URL.Query().Get("response_type") != "code":
		log.Println("response_type must be code")
		return false
	case r.URL.Query().Get("client_id") != os.Getenv("CLIENT_ID"):
		log.Println("client_id is wrong")
		return false
	case r.URL.Query().Get("redirect_uri") != os.Getenv("REDIRECT_URI"):
		log.Println("redirect_uri is wrong")
		return false
	case r.URL.Query().Get("state") == "":
		log.Println("state is empty")
		return false
	default:
		return true
	}
}

func (ah *AuthorizeHandler) validatePKCERequest(r *http.Request) bool {
	codeChallenge := r.URL.Query().Get("code_challenge")
	if codeChallenge == "" {
		log.Println("code_challenge is empty")
		return false
	} else if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
		log.Println("code_challenge is wrong")
		return false
	}

	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	if codeChallengeMethod == "" {
		log.Println("code_challenge_method is empty")
		return false
	} else if codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
		log.Println("code_challenge_method is wrong")
		return false
	}
	return true
}
