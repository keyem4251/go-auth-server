package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"time"

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

func NewAuthorizationCode(
	clientId string,
	redirectUri string,
	state string,
	codeChallenge string,
	codeChallengeMethod string,
) *AuthorizationCode {
	// code作成
	// クライアントが認可コードをトークンエンドポイントに渡すことでアクセストークンと交換できる
	// 認可コードはどのユーザーがどのクライアントになんの権限を与えるかを氷顕現する
	buff := bytes.NewBufferString(clientId)
	token := uuid.NewMD5(uuid.Must(uuid.NewRandom()), buff.Bytes())
	code := base64.URLEncoding.EncodeToString([]byte(token.String()))

	authResponseRedirectURL := redirectUri + "?code=" + code + "&state" + state
	return &AuthorizationCode{
		ClientId:                clientId,
		RedirectUri:             redirectUri,
		State:                   state,
		Code:                    code,
		CodeChallenge:           &codeChallenge,
		CodeChallengeMethod:     &codeChallengeMethod,
		AuthResponseRedirectURL: authResponseRedirectURL,
	}
}

func NewAuthorizeHandler(db *MongoDB) *AuthorizeHandler {
	return &AuthorizeHandler{
		db,
	}
}

type AuthorizeHandler struct {
	db *MongoDB
}

func (ah *AuthorizeHandler) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	// リクエストの検証
	if !ah.validateRequest(r) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// PKCEの検証
	if !ah.validatePKCERequest(r) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// それぞれの情報を取得
	clientId := r.URL.Query().Get("client_id")       // クライアントのID
	redirectUri := r.URL.Query().Get("redirect_uri") // 認可レスポンスパラメータを受け取るURL
	state := r.URL.Query().Get("state")              // CSRF対策のための値

	// PKCEのために必要（データベースに保存）
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// データベースに情報を保存
	authorizationCode := NewAuthorizationCode(
		clientId,
		redirectUri,
		state,
		codeChallenge,
		codeChallengeMethod,
	)
	collection := ah.db.Database.Collection("authorization")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := collection.InsertOne(ctx, authorizationCode)
	if err != nil {
		log.Println("データベース保存エラー")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// 認可レスポンスパラメータを処理するURLに認可コード、stateを渡す
	http.Redirect(w, r, authorizationCode.AuthResponseRedirectURL, http.StatusFound)
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
		// 本来は登録されたクライアントの情報をDBに保存しておいて、DBの値と一致するか確認する
		log.Println("client_id is wrong")
		return false
	case r.URL.Query().Get("redirect_uri") != os.Getenv("REDIRECT_URI"):
		// 本来は登録されたクライアントの情報をDBに保存しておいて、DBの値と一致するか確認する
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
