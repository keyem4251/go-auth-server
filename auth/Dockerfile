FROM golang:1.23.2-alpine

# 必要なパッケージをインストール
RUN apk add --no-cache \
    bash \
    docker \
    openrc \
    curl \
    git

# openrc の設定
RUN rc-update add docker boot && \
    rc-status && \
    touch /run/openrc/softlevel

# Docker デーモンをインストールするためのスクリプトの取得
RUN curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh

RUN go install github.com/air-verse/air@latest

# 作業ディレクトリを設定
WORKDIR /workspace/auth

# Goモジュールファイルをコピーして依存関係をダウンロード
COPY go.mod ./
RUN go mod download

# ソースコードをコンテナにコピー
COPY . .

# アプリケーションを実行
CMD ["sh", "-c", "dockerd-entrypoint.sh & air"]