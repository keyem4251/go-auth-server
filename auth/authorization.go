package main

import (
	"bytes"
	"encoding/base64"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
)

type AuthorizationCode struct {
	ClientId                string
	RedirectUri             string
	State                   string
	Code                    string
	CodeChallenge           *string
	CodeChallengeMethod     *string
	AuthResponseRedirectURL string
}

func NewAuthorizationCode(ar *AuthorizationRequest) *AuthorizationCode {
	// code作成
	// クライアントが認可コードをトークンエンドポイントに渡すことでアクセストークンと交換できる
	// 認可コードはどのユーザーがどのクライアントになんの権限を与えるかを氷顕現する
	buff := bytes.NewBufferString(ar.ClientId)
	token := uuid.NewMD5(uuid.Must(uuid.NewRandom()), buff.Bytes())
	code := base64.URLEncoding.EncodeToString([]byte(token.String()))

	authResponseRedirectURL := ar.RedirectUri + "?code=" + code + "&state" + ar.State
	return &AuthorizationCode{
		ClientId:                ar.ClientId,
		RedirectUri:             ar.RedirectUri,
		State:                   ar.State,
		Code:                    code,
		CodeChallenge:           &ar.CodeChallenge,
		CodeChallengeMethod:     &ar.CodeChallengeMethod,
		AuthResponseRedirectURL: authResponseRedirectURL,
	}
}

type AuthorizationRequest struct {
	Method              string
	ResponstType        string
	ClientId            string // クライアントのID
	RedirectUri         string // 認可レスポンスパラメータを受け取るURL
	State               string // CSRF対策のための値
	CodeChallenge       string // PKCEのために必要（データベースに保存）
	CodeChallengeMethod string // PKCEのために必要（データベースに保存）
}

func NewAuthorizationRequest(r *http.Request) *AuthorizationRequest {
	return &AuthorizationRequest{
		Method:              r.Method,
		ResponstType:        r.URL.Query().Get("response_type"),
		ClientId:            r.URL.Query().Get("client_id"),
		RedirectUri:         r.URL.Query().Get("redirect_uri"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	}
}

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

func (ar *AuthorizationRequest) ValidateRequest(r *http.Request) bool {
	switch {
	case ar.Method != "GET":
		log.Println("request method must be GET")
		return false
	case ar.ResponstType != "code":
		log.Println("response_type must be code")
		return false
	case ar.ClientId != os.Getenv("CLIENT_ID"):
		// 本来は登録されたクライアントの情報をDBに保存しておいて、DBの値と一致するか確認する
		log.Println("client_id is wrong")
		return false
	case ar.RedirectUri != os.Getenv("REDIRECT_URI"):
		// 本来は登録されたクライアントの情報をDBに保存しておいて、DBの値と一致するか確認する
		log.Println("redirect_uri is wrong")
		return false
	case ar.State == "":
		log.Println("state is empty")
		return false
	default:
		return true
	}
}

func (ar *AuthorizationRequest) ValidatePKCERequest(r *http.Request) bool {
	if ar.CodeChallenge == "" {
		log.Println("code_challenge is empty")
		return false
	} else if len(ar.CodeChallenge) < 43 || len(ar.CodeChallenge) > 128 {
		log.Println("code_challenge is wrong")
		return false
	}

	if ar.CodeChallengeMethod == "" {
		log.Println("code_challenge_method is empty")
		return false
	} else if ar.CodeChallengeMethod != "plain" && ar.CodeChallengeMethod != "S256" {
		log.Println("code_challenge_method is wrong")
		return false
	}
	return true
}
