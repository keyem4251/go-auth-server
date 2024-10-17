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

	ah := NewAuthorizeHandler()
	http.HandleFunc("/authorize", ah.HandleAuthorizeRequest)
	host := "0.0.0.0"
	port := "8080"
	log.Printf("listen start: %s:%s\n", host, port)
	http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), nil)
}

type TokenHandler struct{}

func (th *TokenHandler) HandleTokenHandler(w http.ResponseWriter, r *http.Request) {
	// トークンリクエストを検証
	if !th.validateTokenRequest(r) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// 認証ヘッダーを検証
	// client secretを確認
	// client idを取得して、データベースの値を取得

	// PKCEリクエストを検証
	// client idから取得した値とcode challengeの値を作成して、検証

	// アクセス、リフレッシュトークンを作成

	// トークンを保存

	// レスポンスを作成

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
