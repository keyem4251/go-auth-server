package authorization

import (
	"net/http"
)

func NewAuthorizeHandler(authRepo *AuthorizationRepository) *AuthorizeHandler {
	return &AuthorizeHandler{
		AuthRepo: authRepo,
	}
}

type AuthorizeHandler struct {
	AuthRepo *AuthorizationRepository
}

func (ah *AuthorizeHandler) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	ar := NewAuthorizationRequest(r)

	// リクエストの検証
	if !ar.ValidateRequest(r) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// PKCEの検証
	if !ar.ValidatePKCERequest(r) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// データベースに情報を保存
	authorizationCode := NewAuthorizationCode(ar)
	err := ah.AuthRepo.Save(authorizationCode)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// 認可レスポンスパラメータを処理するURLに認可コード、stateを渡す
	http.Redirect(w, r, authorizationCode.AuthResponseRedirectURL, http.StatusFound)
}
