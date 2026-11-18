# Schools API

REST API do projeto Schools, escrita em Go com Fiber v3 e PostgreSQL. O projeto
começa com autenticação (registro, login, JWT, refresh tokens e logout) e
expõe endpoints de usuários com autorização simples por papel (`user` / `admin`).

O código foi organizado para permanecer didático: `main.go` apenas monta a
aplicação, e cada responsabilidade está em um pacote pequeno.

## Tecnologias

- Go 1.27+
- Fiber v3
- PostgreSQL com `database/sql` + driver pgx (sem ORM)
- JWT (golang-jwt/v5), bcrypt, godotenv

## Requisitos

- Go 1.27 ou superior
- PostgreSQL 14+ (ou compatível)
- `psql` ou outra forma de executar os arquivos de migração (as migrações também
  podem ser aplicadas pelo comando Go descrito abaixo)

## Instalação

```sh
git clone <url-do-repositorio>
cd api
go mod download
```

## Configuração

Copie o arquivo de exemplo e preencha os valores locais:

```sh
cp .env.example .env
```

| Variável | Obrigatória | Padrão | Descrição |
| --- | --- | --- | --- |
| `DATABASE_URL` | sim | — | DSN do PostgreSQL, ex.: `postgres://user:pass@localhost:5432/schools?sslmode=disable` |
| `AUTH_SECRET` | sim | — | Segredo HMAC do JWT, com pelo menos 32 caracteres |
| `ADDR` | não | `:8080` | Endereço de escuta do Fiber |
| `DB_QUERY_TIMEOUT` | não | `5s` | Timeout para cada consulta ao banco |
| `DB_MAX_OPEN_CONNS` | não | `10` | Máximo de conexões abertas |
| `DB_MAX_IDLE_CONNS` | não | `5` | Máximo de conexões ociosas |
| `DB_CONN_MAX_LIFETIME` | não | `30m` | Tempo máximo de vida de uma conexão |
| `RATE_LIMIT_MAX` | não | `10` | Requisições por janela nos endpoints públicos de autenticação |
| `RATE_LIMIT_WINDOW` | não | `1m` | Janela do rate limit |
| `MIGRATIONS_DIR` | não | `migrations` | Diretório dos arquivos SQL de migração |

Nunca version `.env` nem segredos reais. Variáveis já exportadas no ambiente
têm precedência sobre o arquivo `.env`.

## Banco de dados e migrações

Crie o banco antes de rodar as migrações:

```sh
createdb schools
```

A API não cria tabelas automaticamente. Aplique as migrações versionadas:

```sh
go run ./cmd/migrate
```

O runner cria a tabela de controle `schema_migrations`, lê `migrations/*.sql` em
ordem e aplica apenas as versões pendentes, cada uma dentro de uma transação.

- `0001_init.sql`: cria `users`, `auth_refresh_tokens` e índices.
- `0002_existing_schema_columns.sql`: adiciona `role`, `is_active`,
  `updated_at` e `revoked_at` em bancos que já tinham o esquema antigo.

O esquema final é:

```sql
users(id, name, email, password_hash, role, is_active, created_at, updated_at)
auth_refresh_tokens(token_hash, user_id, expires_at, revoked_at, created_at)
```

`email` é único, `role` é `user` ou `admin`, e tokens de refresh são excluídos
em cascata quando o usuário é removido.

## Executando a API

```sh
go run .
```

Para promover um usuário a administrador (a API não permite auto-registro como
admin):

```sql
UPDATE users SET role = 'admin', updated_at = NOW() WHERE email = 'ana@example.com';
```

O papel é lido do banco a cada requisição autenticada; faça login novamente
após alterar o papel para atualizar o token.

## Formato das respostas

Sucesso:

```json
{ "success": true, "data": { }, "meta": { } }
```

Erro:

```json
{ "success": false, "error": "mensagem amigável" }
```

Códigos usados: `200` (leitura/atualização), `201` (criação), `204` (sem
conteúdo), `400` (validação), `401` (não autenticado), `403` (sem permissão),
`404` (não encontrado), `409` (conflito), `429` (rate limit) e `500` (erro
interno, sem detalhes vazados).

## Endpoints

Base URL: `http://localhost:8080/api/v1`.

### Saúde

- `GET /health` — responde `{"success":true,"data":{"status":"ok"}}`.
- `GET /health/ready` — verifica a conexão com o PostgreSQL.

### Autenticação

`POST /auth/register`

```json
{ "name": "Ana", "email": "ana@example.com", "password": "password123" }
```

Senha: 8 a 72 bytes. O email é normalizado para minúsculas e a senha é
armazenada apenas como hash bcrypt.

Resposta `201`:

```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "Ana",
    "email": "ana@example.com",
    "role": "user",
    "created_at": "2026-11-18T16:03:19Z"
  }
}
```

`POST /auth/login`

```json
{ "email": "ana@example.com", "password": "password123" }
```

Resposta `200`:

```json
{
  "success": true,
  "data": {
    "access_token": "<jwt>",
    "token_type": "Bearer",
    "expires_at": "2026-11-19T16:03:19Z",
    "refresh_token": "<token-opaco>",
    "user": { "id": 1, "name": "Ana", "email": "ana@example.com", "role": "user" }
  }
}
```

Erros de credencial sempre retornam a mesma mensagem, independentemente de o
email existir ou não.

`POST /auth/refresh`

```json
{ "refresh_token": "<token-opaco>" }
```

Cada chamada gira o refresh token: o anterior é revogado. Se um token já
usado/revogado for apresentado novamente, todos os tokens daquele usuário são
revogados.

`POST /auth/logout` — exige Bearer token.

```json
{ "refresh_token": "<token-opaco>" }
```

Responde `204`. O access token continua válido até expirar, portanto o cliente
deve descartá-lo localmente.

`GET /auth/me` — exige Bearer token; retorna os dados públicos do usuário.

### Usuários

Todas as rotas exigem Bearer token.

- `GET /users` — apenas administradores. Aceita `?limit=20&offset=0` (`limit`
  entre 1 e 100). Retorna `data` com a lista e `meta` com `limit`, `offset` e
  `total`.
- `GET /users/:id` — o próprio usuário ou administrador.
- `PATCH /users/:id` — o próprio usuário ou administrador. Corpo com qualquer
  combinação de `name`, `email` e `password`.
- `DELETE /users/:id` — o próprio usuário ou administrador. Desativa a conta
  (`is_active = false`) e revoga os refresh tokens; responde `204`.

Exemplo de atualização:

```sh
curl -X PATCH http://localhost:8080/api/v1/users/1 \
  -H 'Authorization: Bearer <access_token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Ana Silva"}'
```

Usuários comuns recebem `404` ao tentar ver outro usuário e `403` ao tentar
alterá-lo ou desativá-lo. Nenhuma resposta inclui `password_hash`.

## Usando os tokens

1. Registre-se e faça login.
2. Envie o access token em todas as rotas protegidas:
   `Authorization: Bearer <access_token>`.
3. Quando o access token expirar (24h), envie o refresh token (válido por 30
   dias) para `POST /auth/refresh` e armazene o novo par retornado.
4. Ao sair, chame `POST /auth/logout` com o refresh token atual e descarte
   ambos os tokens no cliente.

O JWT é assinado com HS256; a API aceita apenas esse algoritmo e valida
`exp`, `iss` (`schools-api`) e `aud` (`schools-api-clients`). Tokens de usuários
inativos são rejeitados mesmo antes do vencimento.

Middleware global: request ID, logs de acesso, recuperação de panic, headers de
segurança e rate limit (por IP + rota) nos endpoints públicos de autenticação.

## Estrutura do projeto

```text
main.go                    composição da aplicação
config/                    configuração de ambiente e conexão PostgreSQL
models/                    estruturas de domínio
controllers/               handlers de autenticação e usuários
middleware/                autenticação, autorização, erros e headers
routes/                    grupos de rotas /api/v1
utils/                     validação, JWT, respostas HTTP
migrations/                SQL versionado
cmd/migrate/               runner das migrações
```

## Testes e validação

```sh
gofmt -w .
go vet ./...
go test ./...
```

Os testes de handlers usam `go-sqlmock` e não exigem um PostgreSQL em
execução. Para um teste manual ponta a ponta, aplique as migrações, inicie a
API e use os exemplos acima.
