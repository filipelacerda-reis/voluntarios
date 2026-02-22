# Voluntário Hub (Monolito Docker)

Plataforma para gestão de voluntários, escalas, cultos e repertório de igrejas.

## Stack

- Backend: Node.js 20 + Express + PostgreSQL (`pg`)
- Frontend: Vanilla JS (SPA)
- Infra local: Docker Compose

## Arquitetura (Fase 1)

O backend foi modularizado para facilitar manutenção e evolução:

- `backend/src/routes/`: rotas por domínio
- `backend/src/controllers/`: camada HTTP (req/res)
- `backend/src/services/`: regras de negócio
- `backend/src/middlewares/errorHandler.js`: tratamento global de erros
- `backend/src/utils/`: helpers (async handler, parsers)
- `backend/src/constants/`: constantes de domínio

### Migração de banco desacoplada do runtime

- O `initDb()` foi removido do fluxo de boot.
- Migração/seed em script dedicado:
  - `backend/scripts/migrate.js`
- Comando:
  - `npm --prefix backend run migrate`

## Automação de lembretes (Fase 2)

Job diário com `node-cron`:

- Arquivo: `backend/src/jobs/reminders.job.js`
- Agenda: `0 9 * * *`
- Timezone: `America/Sao_Paulo`
- Ação: busca escalas `PENDENTE` de cultos futuros e grava logs em `notification_logs`
- Inicialização no boot da API (`backend/src/server.js`)

## Integração real de e-mail (Fase 3)

O canal `EMAIL` usa `nodemailer` com SMTP real:

- Serviço: `backend/src/services/notification.service.js`
- Variáveis obrigatórias para envio real:
  - `SMTP_HOST`
  - `SMTP_PORT`
  - `SMTP_USER`
  - `SMTP_PASS`
- Variável opcional:
  - `SMTP_FROM`

Comportamento:

- Mantém gravação em `notification_logs`
- Em sucesso: `status = ENVIADO`
- Em falha SMTP/exceção: `status = FALHA` e erro no payload

## Frontend refatorado + paginação (Fase 4)

### Módulo de API

- Novo arquivo: `frontend/api.js`
  - `api(path, options)`
  - `setAuthToken(token)`
  - `clearAuthToken()`
  - `jsonAuthHeaders()`
- `frontend/app.js` passou a importar esse módulo
- `frontend/index.html` usa script ES Module:
  - `<script type="module" src="/app/app.js"></script>`

### Registros (Audit Logs) paginados

Backend:

- Endpoint: `GET /api/audit-logs?page=1&limit=50`
- Retorno:
  - `items`
  - `page`
  - `limit`
  - `total`
  - `hasMore`

Frontend:

- Busca inicial com `page=1&limit=50`
- Botão **Carregar mais** para anexar próxima página

## Perfis e escopo

- `ADMIN`: acesso total
- `LIDER_MINISTERIO`: acesso por escopo de ministérios liderados
- `VOLUNTARIO`: fluxo operacional próprio

Regras aplicadas no projeto:

- Ministério `LOUVOR` é garantido na migração
- Repertório é visível para:
  - `ADMIN`
  - usuários vinculados ao ministério `LOUVOR`

## Funcionalidades principais

- Gestão de usuários e ministérios
- Bloqueios de agenda (indisponibilidade)
- Criação/edição/exclusão de cultos
- Planejamento avançado (repetição e criação em massa)
- Escalas com validação de indisponibilidade
- Aprovação/rejeição de escala
- Troca de escala
- Repertório por culto (adicionar/editar/remover)
- Notificações (PUSH/WHATSAPP/EMAIL)
- Logs de auditoria

## Execução local

```bash
cd /Users/sre/Desktop/voluntario
cp .env.example .env
npm --prefix backend run migrate
docker compose up --build -d
```

Acessos:

- App: [http://localhost:8090](http://localhost:8090)
- Health: [http://localhost:8090/api/health](http://localhost:8090/api/health)

Credenciais seed:

- `admin@igreja.local` / `admin123`
- `lider@igreja.local` / `lider123`
- `voluntario@igreja.local` / `voluntario123`

## Endpoints úteis

- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/change-password`
- `POST /api/notifications/reminders/pending-confirmations`
- `GET /api/notifications`
- `GET /api/audit-logs?page=1&limit=50`

## Produção (resumo)

- Reverse proxy TLS: `docker-compose.prod.yml` + `infra/nginx`
- Backup: `scripts/backup.sh`
- Segurança: `helmet`, rate limit, CORS, trust proxy, logs HTTP

## Commit inicial (sugestão)

```bash
git add .
git commit -m "feat: modulariza backend, adiciona cron de lembretes, SMTP real e paginação de auditoria"
git remote add origin git@github.com:filipelacerda-reis/voluntarios.git # se ainda não existir
git push -u origin main
```
