package main

import (
	"fmt"
	"log"
	"net/http"
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

	// アクセス、リフレッシュトークンを作成

	// トークンを保存

	// レスポンスを作成

}
