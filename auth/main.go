package main

import (
	"fmt"
	"log"
	"net/http"

	"auth/authorization"
	"auth/db"
	"auth/token"
)

func main() {

	db := db.NewAuthDB()

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	authRepo := authorization.NewAuthorizationRepository(db)
	ah := authorization.NewAuthorizeHandler(authRepo)
	http.HandleFunc("/authorize", ah.HandleAuthorizeRequest)

	tokenRepo := token.NewTokenRepository(db)
	th := token.NewTokenHandler(authRepo, tokenRepo)
	http.HandleFunc("/token", th.HandleTokenRequest)

	host := "0.0.0.0"
	port := "8080"
	log.Printf("listen start: %s:%s\n", host, port)
	http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), nil)
}
