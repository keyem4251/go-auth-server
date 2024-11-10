Go OAuth2 Authorization Server with PKCE and JWT

Overview

This project is an OAuth2 Authorization Server built in Go that supports PKCE (Proof Key for Code Exchange) and JWT (JSON Web Token) . 

Features

* OAuth2 Authorization Code Flow with PKCE: Enhanced security for authorization code flow.
* JWT Support: Issues signed JWTs as access tokens for secure access control.
* MongoDB Integration: Stores users and authorization data.
* Hot-Reloading with Air: Reflects code changes immediately during development.
* Devcontainer Support: Simplifies setup in a containerized development environment.

Requirements

* Docker and Docker Compose
* VS Code with Devcontainer extension
* MongoDB (default mongodb://mongo:27017)

Set Environment Variables: Create a .env file in the root with the following values:
```
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
REDIRECT_URI=https://yourapp.com/callback
SECRET_KEY=your_secret_key
DB_HOST=mongodb://mongo
DB_PORT=27017
```

Usage
* Authorization Reques
```
GET /authorize?client_id=your_client_id&response_type=code&redirect_uri=https://yourapp.com/callback&code_challenge=your_code_challenge&code_challenge_method=S256
```
* Token Exchange:
```
POST /token
Content-Type: application/x-www-form-urlencoded
client_id=your_client_id&client_secret=your_client_secret&grant_type=authorization_code&code=your_authorization_code&redirect_uri=https://yourapp.com/callback&code_verifier=your_code_verifier
```

Testing
```
go test
```
