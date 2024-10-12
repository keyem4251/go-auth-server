FROM golang:1.23.2-alpine

# 作業ディレクトリを設定
WORKDIR /app

# Goモジュールファイルをコピーして依存関係をダウンロード
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# ソースコードをコンテナにコピー
COPY . .

# アプリケーションをビルド
RUN go build -o main .

# アプリケーションを実行
CMD ["/main"]