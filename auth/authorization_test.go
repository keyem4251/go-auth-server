package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleAuthorizeRequest(t *testing.T) {
	db := NewDB()
	ah := NewAuthorizeHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	w := httptest.NewRecorder()
	ah.HandleAuthorizeRequest(w, req)
	if w.Result().StatusCode != 200 {
		t.Errorf("status code is not 200: %v\n", w.Result().StatusCode)
	}
}
