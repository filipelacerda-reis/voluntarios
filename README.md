# Voluntário Hub (Monolito Docker)

Plataforma de gestão para igrejas com foco em voluntários, escalas e repertório, em monolito Docker (backend + frontend).

## Visão geral

- Backend: Node.js + Express + PostgreSQL
- Frontend: SPA estática servida pelo backend
- Execução local: Docker Compose
- Perfis: `ADMIN`, `LIDER_MINISTERIO`, `VOLUNTARIO`

## Regras de acesso

- `ADMIN`:
  - acesso total
  - único perfil que cria usuários
  - único perfil que define líderes e altera ministérios de usuários
  - não pode auto-desativar a própria conta
  - contas `ADMIN` não podem ser desativadas
- `LIDER_MINISTERIO`:
  - acesso restrito ao(s) ministério(s) que lidera
  - não cria usuários
  - não desativa usuários
- `VOLUNTARIO`:
  - acesso operacional próprio (inscrição, confirmação, agenda, perfil)

## Ministérios e escopo

- Suporte a multi-ministério por usuário (`user_ministries`)
- Ministério `LOUVOR` é garantido no bootstrap
- Repertório é visível/gerenciável apenas para:
  - `ADMIN`
  - usuários vinculados ao ministério `LOUVOR`

## Funcionalidades implementadas

### Escalas e cultos

- Criação de culto
- Edição e exclusão de culto (`ADMIN` e `LIDER_MINISTERIO` no próprio escopo)
- Planejamento avançado:
  - repetição de culto + escala por período
  - criação em massa por dia da semana e turnos
- Autoinscrição do voluntário em culto
- Validação de conflito por pessoa na mesma data
- Validação de indisponibilidade por agenda

### Aprovação e confirmação

- Fila de aprovações para líder/admin
- Aprovar/rejeitar com observação
- Confirmação/recusa da escala pelo voluntário
- Lembretes em lote para confirmações pendentes

### Troca de escala

- Voluntário solicita troca com motivo
- Líder/admin aprova ou rejeita
- Notificação e auditoria da decisão

### Usuários e agenda

- Cadastro de usuário por admin
- Alteração de ministérios de usuário por admin
- Bloqueio de agenda por período

### Repertório

- Cadastro de músicas com tom, BPM, link web e tags
- Busca por nome/tom/tag
- Gestão de repertório por culto (adicionar, editar, remover)

### Notificações e auditoria

- Trilha local (mock) em `WHATSAPP`, `EMAIL`, `PUSH`
- Histórico de notificações
- Logs de auditoria

### UI

- Layout responsivo
- Tema claro/escuro
- Dashboard com cards de indicadores
- Painel de conta via engrenagem no cabeçalho:
  - trocar senha
  - trocar foto de perfil
  - ver ministérios do usuário

## Rodando localmente

```bash
cd /Users/sre/Desktop/voluntario
cp .env.example .env
docker compose up --build -d
```

Acesso:

- App: [http://localhost:8090](http://localhost:8090)
- Health: [http://localhost:8090/api/health](http://localhost:8090/api/health)

Credenciais seed:

- Admin: `admin@igreja.local` / `admin123`
- Líder: `lider@igreja.local` / `lider123`
- Voluntário: `voluntario@igreja.local` / `voluntario123`

## Endpoints principais

### Autenticação

- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/change-password`

### Usuários e ministérios

- `GET /api/ministries`
- `POST /api/ministries` (`ADMIN`)
- `GET /api/users` (`ADMIN`, `LIDER_MINISTERIO` com escopo)
- `POST /api/users` (`ADMIN`)
- `PATCH /api/users/:id/ministries` (`ADMIN`)
- `PATCH /api/users/:id/active` (`ADMIN`)

### Agenda e escalas

- `GET/POST/DELETE /api/availability-blocks`
- `GET /api/services`
- `POST /api/services`
- `PATCH /api/services/:id`
- `DELETE /api/services/:id`
- `GET /api/services/:id`
- `POST /api/services/:id/assignments`
- `POST /api/services/:id/self-assign`
- `PATCH /api/assignments/:id/status`

### Planejamento

- `POST /api/planning/repeat-service`
- `POST /api/services/bulk`

### Aprovações e trocas

- `GET /api/approvals/pending`
- `PATCH /api/approvals/:assignmentId`
- `POST /api/assignments/:id/swap-request`
- `GET /api/swap-requests?status=PENDENTE`
- `PATCH /api/swap-requests/:id`

### Repertório

- `GET /api/songs?q=texto`
- `POST /api/songs`
- `DELETE /api/songs/:id`
- `POST /api/services/:id/setlist`
- `PATCH /api/services/:serviceId/setlist/:itemId`
- `DELETE /api/services/:serviceId/setlist/:itemId`

### Notificações, auditoria e métricas

- `GET /api/notifications`
- `POST /api/notifications/test`
- `POST /api/notifications/reminders/pending-confirmations`
- `GET /api/audit-logs`
- `GET /api/metrics`

## Produção

### TLS + Proxy

1. Criar certificados em:
   - `/Users/sre/Desktop/voluntario/infra/nginx/certs/fullchain.pem`
   - `/Users/sre/Desktop/voluntario/infra/nginx/certs/privkey.pem`
2. Subir stack:

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

### Backup

```bash
/Users/sre/Desktop/voluntario/scripts/backup.sh
```

Backups em:

- `/Users/sre/Desktop/voluntario/backups`

## Segurança aplicada

- `helmet`
- `express-rate-limit`
- CORS configurável (`CORS_ORIGIN`)
- suporte a proxy (`TRUST_PROXY`)
- logs HTTP com `morgan`
