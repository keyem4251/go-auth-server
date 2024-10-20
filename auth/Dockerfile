FROM golang:1.23.2-alpine

RUN apk update && apk add docker

RUN go install github.com/air-verse/air@latest

# 作業ディレクトリを設定
WORKDIR /workspace/auth

# Goモジュールファイルをコピーして依存関係をダウンロード
COPY go.mod ./
RUN go mod download

# ソースコードをコンテナにコピー
COPY . .

# アプリケーションを実行
CMD ["air"]