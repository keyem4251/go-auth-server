package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {

	db := NewDB()

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	ah := NewAuthorizeHandler(db)
	http.HandleFunc("/authorize", ah.HandleAuthorizeRequest)

	th := NewTokenHandler(db)
	http.HandleFunc("/token", th.HandleTokenRequest)

	host := "0.0.0.0"
	port := "8080"
	log.Printf("listen start: %s:%s\n", host, port)
	http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), nil)
}
