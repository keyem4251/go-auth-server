package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ping")
	})

	ah := NewAuthorizeHandler()
	http.HandleFunc("/authorize", ah.HandleAuthorizeRequest)

	th := NewTokenHandler()
	http.HandleFunc("/token", th.HandleTokenHandler)

	host := "0.0.0.0"
	port := "8080"
	log.Printf("listen start: %s:%s\n", host, port)
	http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), nil)
}
