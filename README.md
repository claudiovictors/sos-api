# API de autenticação

API em Go/Fiber com PostgreSQL e tokens JWT.

## Requisitos

- Go 1.27 ou superior
- PostgreSQL

## Configuração do PostgreSQL

Crie o banco e a tabela de usuários:

```sql
CREATE DATABASE schools;

\c schools

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE auth_refresh_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Configure as variáveis de ambiente antes de iniciar a API. Copie `.env.example`
para `.env` e substitua os valores localmente; a API carrega `.env` ao iniciar.
Variáveis já definidas no ambiente têm precedência.

```sh
cp .env.example .env
# Edite .env com os dados do seu banco e um segredo aleatório para AUTH_SECRET.
go run .
```

`DATABASE_URL` deve apontar para um banco que já tenha as tabelas `users` e
`auth_refresh_tokens`.
Use `sslmode=require` em ambientes que exigem TLS. Não versione credenciais ou
segredos; mantenha-os em variáveis de ambiente ou em um gerenciador de segredos.

## Endpoints

- `POST /auth/register` — recebe `{"name":"...","email":"...","password":"..."}`.
  Senhas devem ter de 8 a 72 bytes; são armazenadas com bcrypt.
- `POST /auth/login` — recebe `{"email":"...","password":"..."}` e retorna um
  token de acesso Bearer válido por 24 horas, um refresh token e os dados
  públicos do usuário.
- `POST /auth/refresh` — recebe `{"refresh_token":"..."}`. Cada uso rotaciona
  o refresh token; o anterior deixa de ser válido.
- `GET /auth/me` — exige `Authorization: Bearer <access_token>`.
- `POST /auth/logout` — exige o Bearer token e recebe
  `{"refresh_token":"..."}` para revogar a sessão; responde `204`. O cliente
  também deve descartar o token de acesso, que permanece válido até expirar.