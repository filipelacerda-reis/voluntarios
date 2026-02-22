require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const { query } = require('./db');
const { authRequired, roleRequired, signToken } = require('./auth');

const app = express();
const PORT = Number(process.env.PORT || 8080);
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const TRUST_PROXY = Number(process.env.TRUST_PROXY || 0);

app.set('trust proxy', TRUST_PROXY);
app.use(helmet());
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map((x) => x.trim()) }));
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined'));
app.use(
  '/api',
  rateLimit({
    windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
    max: Number(process.env.RATE_LIMIT_MAX || 600),
    standardHeaders: true,
    legacyHeaders: false,
  }),
);

const ROLE_ADMIN = 'ADMIN';
const ROLE_LEADER = 'LIDER_MINISTERIO';
const ROLE_VOL = 'VOLUNTARIO';

function asDateOnly(value) {
  return new Date(`${value}T00:00:00`);
}

function dateToISO(d) {
  return d.toISOString().slice(0, 10);
}

function hasRole(user, roles) {
  return user && roles.includes(user.role);
}

function parseTags(input) {
  if (!input) return [];
  if (Array.isArray(input)) {
    return input.map((item) => String(item).trim()).filter(Boolean);
  }
  return String(input)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function isUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function canManageMinistry(req, resourceMinistryId) {
  if (req.user.role === ROLE_ADMIN) return true;
  const ministryIds = Array.isArray(req.user.ministryIds) ? req.user.ministryIds : [];
  if (req.user.role === ROLE_LEADER && ministryIds.includes(resourceMinistryId)) return true;
  return false;
}

function getScopedMinistryIds(req) {
  if (req.user.role === ROLE_ADMIN) return [];
  const leaderIds =
    req.user.role === ROLE_LEADER && Array.isArray(req.user.leaderMinistryIds) ? req.user.leaderMinistryIds.filter(Boolean) : [];
  if (leaderIds.length) return leaderIds;
  const ids = Array.isArray(req.user.ministryIds) ? req.user.ministryIds.filter(Boolean) : [];
  if (ids.length) return ids;
  return req.user.ministryId ? [req.user.ministryId] : [];
}

function hasMinistryAccess(req, ministryId) {
  if (req.user.role === ROLE_ADMIN) return true;
  if (!ministryId) return false;
  return getScopedMinistryIds(req).includes(ministryId);
}

async function getLouvorMinistryId() {
  const { rows } = await query(
    `SELECT id
     FROM ministries
     WHERE upper(name) = 'LOUVOR'
     ORDER BY name
     LIMIT 1`,
  );
  return rows[0]?.id || null;
}

async function writeAudit(actorUserId, action, entity, entityId, ministryId, payload = {}) {
  await query(
    `INSERT INTO audit_logs (actor_user_id, action, entity, entity_id, ministry_id, payload)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
    [actorUserId, action, entity, entityId, ministryId, JSON.stringify(payload)],
  );
}

async function createNotification({ userId, ministryId, channel, template, event, payload }) {
  const { rows } = await query(
    `INSERT INTO notification_logs (user_id, ministry_id, channel, template, event, payload, status, sent_at)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'ENVIADO', now())
     RETURNING id`,
    [userId, ministryId, channel, template, event, JSON.stringify(payload || {})],
  );
  return rows[0]?.id;
}

async function notifyUserMultiChannel({ userId, ministryId, template, event, payload, channels = ['WHATSAPP', 'EMAIL', 'PUSH'] }) {
  for (const channel of channels) {
    // Mock local delivery log; integration adapters can replace this call in production.
    await createNotification({ userId, ministryId, channel, template, event, payload });
  }
}

async function getServiceWithMinistry(serviceId) {
  const { rows } = await query(
    'SELECT id, service_date, service_time, title, notes, tags, ministry_id FROM services WHERE id = $1 LIMIT 1',
    [serviceId],
  );
  return rows[0] || null;
}

async function checkAvailabilityBlock(userId, serviceDate) {
  const { rows } = await query(
    `SELECT id, start_date, end_date, reason
     FROM availability_blocks
     WHERE user_id = $1
       AND $2::date BETWEEN start_date AND end_date
     LIMIT 1`,
    [userId, serviceDate],
  );
  return rows[0] || null;
}

async function checkPersonConflict(userId, serviceDate) {
  const { rows } = await query(
    `SELECT sa.id AS assignment_id, s.id AS service_id, s.title, s.service_date
     FROM service_assignments sa
     JOIN services s ON s.id = sa.service_id
     WHERE sa.user_id = $1
       AND s.service_date = $2::date
       AND sa.status <> 'RECUSADO'
     LIMIT 1`,
    [userId, serviceDate],
  );
  return rows[0] || null;
}

async function createApprovalRequest({ assignmentId, ministryId, requestedBy }) {
  let leaderRows = [];
  if (ministryId) {
    const result = await query(
      `SELECT id
       FROM users
       WHERE role = 'LIDER_MINISTERIO'
         AND active = true
         AND ministry_id = $1
       ORDER BY created_at ASC
       LIMIT 1`,
      [ministryId],
    );
    leaderRows = result.rows;
  } else {
    const result = await query(
      `SELECT id
       FROM users
       WHERE role = 'LIDER_MINISTERIO'
         AND active = true
       ORDER BY created_at ASC
       LIMIT 1`,
    );
    leaderRows = result.rows;
  }

  const approverId = leaderRows[0]?.id || null;
  const status = approverId ? 'PENDENTE' : 'APROVADO';

  const { rows } = await query(
    `INSERT INTO approval_requests (assignment_id, requested_by, approver_user_id, status)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (assignment_id) DO UPDATE SET requested_by = EXCLUDED.requested_by
     RETURNING id, status, approver_user_id`,
    [assignmentId, requestedBy, approverId, status],
  );

  if (!approverId) {
    await query('UPDATE service_assignments SET status = $1 WHERE id = $2', ['PENDENTE', assignmentId]);
  }

  return rows[0];
}

async function createAssignmentWithRules({ serviceId, userId, teamRole, actorUserId }) {
  const service = await getServiceWithMinistry(serviceId);
  if (!service) {
    return { error: { code: 404, message: 'Culto não encontrado' } };
  }

  const block = await checkAvailabilityBlock(userId, service.service_date);
  if (block) {
    return {
      error: {
        code: 409,
        message: `Voluntário indisponível neste dia (${block.reason || 'bloqueio de agenda'})`,
      },
    };
  }

  const conflict = await checkPersonConflict(userId, service.service_date);
  if (conflict) {
    return {
      error: {
        code: 409,
        message: `Conflito: voluntário já escalado em ${conflict.title} na mesma data`,
      },
    };
  }

  const { rows: targetRows } = await query('SELECT id, name, ministry_id, active FROM users WHERE id = $1 LIMIT 1', [userId]);
  const target = targetRows[0];
  if (!target || !target.active) {
    return { error: { code: 404, message: 'Voluntário não encontrado/ativo' } };
  }

  if (service.ministry_id) {
    const { rows: memberRows } = await query(
      `SELECT 1
       FROM user_ministries
       WHERE user_id = $1
         AND ministry_id = $2
       LIMIT 1`,
      [userId, service.ministry_id],
    );
    if (!memberRows[0]) {
      return { error: { code: 409, message: 'Voluntário não pertence ao ministério deste culto' } };
    }
  }

  const { rows } = await query(
    `INSERT INTO service_assignments (service_id, user_id, team_role, status)
     VALUES ($1, $2, $3, 'PENDENTE')
     RETURNING id, service_id, user_id, team_role, status`,
    [serviceId, userId, teamRole.trim()],
  );

  const assignment = rows[0];
  const approval = await createApprovalRequest({
    assignmentId: assignment.id,
    ministryId: service.ministry_id,
    requestedBy: actorUserId,
  });

  await notifyUserMultiChannel({
    userId,
    ministryId: service.ministry_id,
    template: 'NOVA_ESCALA',
    event: 'ASSIGNMENT_CREATED',
    payload: {
      serviceDate: service.service_date,
      serviceTitle: service.title,
      teamRole: assignment.team_role,
      approvalStatus: approval.status,
    },
  });

  await writeAudit(actorUserId, 'ASSIGN_VOLUNTEER', 'SERVICE', serviceId, service.ministry_id, {
    assignmentId: assignment.id,
    userId,
    teamRole: assignment.team_role,
    approvalStatus: approval.status,
  });

  return { assignment, approvalStatus: approval.status };
}

async function initDb() {
  await query('CREATE EXTENSION IF NOT EXISTS pgcrypto;');

  await query(`
    CREATE TABLE IF NOT EXISTS ministries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL UNIQUE,
      description TEXT DEFAULT ''
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      phone TEXT DEFAULT '',
      role TEXT NOT NULL CHECK (role IN ('ADMIN', 'LIDER_MINISTERIO', 'VOLUNTARIO')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      ministry_id UUID REFERENCES ministries(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS user_ministries (
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      ministry_id UUID NOT NULL REFERENCES ministries(id) ON DELETE CASCADE,
      is_leader BOOLEAN NOT NULL DEFAULT FALSE,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (user_id, ministry_id)
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS songs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      title TEXT NOT NULL,
      key TEXT NOT NULL,
      bpm INTEGER,
      web_link TEXT,
      tags TEXT[] NOT NULL DEFAULT '{}',
      ministry_id UUID REFERENCES ministries(id) ON DELETE SET NULL,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS services (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      service_date DATE NOT NULL,
      service_time TIME,
      title TEXT NOT NULL,
      notes TEXT DEFAULT '',
      tags TEXT[] NOT NULL DEFAULT '{}',
      ministry_id UUID REFERENCES ministries(id) ON DELETE SET NULL,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS service_setlist (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      service_id UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
      song_id UUID NOT NULL REFERENCES songs(id) ON DELETE RESTRICT,
      position INTEGER NOT NULL,
      note TEXT DEFAULT '',
      UNIQUE(service_id, position)
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS service_assignments (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      service_id UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      team_role TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDENTE' CHECK (status IN ('PENDENTE', 'CONFIRMADO', 'RECUSADO')),
      UNIQUE(service_id, user_id, team_role)
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS availability_blocks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      ministry_id UUID REFERENCES ministries(id) ON DELETE SET NULL,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      reason TEXT DEFAULT '',
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK (start_date <= end_date)
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS approval_requests (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      assignment_id UUID NOT NULL UNIQUE REFERENCES service_assignments(id) ON DELETE CASCADE,
      requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
      approver_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      status TEXT NOT NULL CHECK (status IN ('PENDENTE', 'APROVADO', 'REJEITADO')),
      decision_note TEXT DEFAULT '',
      decided_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS notification_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      ministry_id UUID REFERENCES ministries(id) ON DELETE SET NULL,
      channel TEXT NOT NULL CHECK (channel IN ('WHATSAPP', 'EMAIL', 'PUSH')),
      template TEXT NOT NULL,
      event TEXT NOT NULL,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL CHECK (status IN ('PENDENTE', 'ENVIADO', 'FALHA')),
      error_message TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      sent_at TIMESTAMPTZ
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS assignment_swap_requests (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      assignment_id UUID NOT NULL REFERENCES service_assignments(id) ON DELETE CASCADE,
      requester_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      requested_to_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      reason TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL CHECK (status IN ('PENDENTE', 'APROVADA', 'REJEITADA', 'CANCELADA')),
      approver_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      decision_note TEXT DEFAULT '',
      decided_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      entity TEXT NOT NULL,
      entity_id UUID,
      ministry_id UUID REFERENCES ministries(id) ON DELETE SET NULL,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await query('ALTER TABLE songs ADD COLUMN IF NOT EXISTS web_link TEXT;');
  await query('ALTER TABLE services ADD COLUMN IF NOT EXISTS service_time TIME;');
  await query("ALTER TABLE services ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';");

  await query('CREATE INDEX IF NOT EXISTS idx_services_date ON services(service_date);');
  await query('CREATE INDEX IF NOT EXISTS idx_assignments_user ON service_assignments(user_id);');
  await query('CREATE INDEX IF NOT EXISTS idx_user_ministries_user ON user_ministries(user_id);');
  await query('CREATE INDEX IF NOT EXISTS idx_user_ministries_ministry ON user_ministries(ministry_id);');
  await query('CREATE INDEX IF NOT EXISTS idx_availability_user_dates ON availability_blocks(user_id, start_date, end_date);');
  await query('CREATE INDEX IF NOT EXISTS idx_notifications_user ON notification_logs(user_id, created_at DESC);');
  await query('CREATE INDEX IF NOT EXISTS idx_swap_assignment ON assignment_swap_requests(assignment_id, status);');

  const { rows: louvorRows } = await query(`SELECT id FROM ministries WHERE upper(name) = 'LOUVOR' LIMIT 1`);
  if (!louvorRows[0]) {
    await query(
      `INSERT INTO ministries (name, description)
       VALUES ('LOUVOR', 'Ministério de música e adoração')
       ON CONFLICT (name) DO NOTHING`,
    );
  }
  const { rows: louvorRowsAfter } = await query(`SELECT id FROM ministries WHERE upper(name) = 'LOUVOR' LIMIT 1`);
  const louvorId = louvorRowsAfter[0]?.id || null;

  const { rows: ministryRows } = await query('SELECT id FROM ministries ORDER BY name LIMIT 1');
  let ministryId = ministryRows[0]?.id;

  if (!ministryId) {
    const inserted = await query(
      `INSERT INTO ministries (name, description)
       VALUES ('Louvor Sede', 'Ministério principal de louvor') RETURNING id`,
    );
    ministryId = inserted.rows[0].id;
  }

  const { rows: userRows } = await query('SELECT id FROM users LIMIT 1');
  if (!userRows.length) {
    const adminPass = await bcrypt.hash('admin123', 10);
    const liderPass = await bcrypt.hash('lider123', 10);
    const volPass = await bcrypt.hash('voluntario123', 10);

    await query(
      `INSERT INTO users (name, email, password_hash, role, phone, ministry_id)
       VALUES
       ('Administrador', 'admin@igreja.local', $1, 'ADMIN', '(11) 90000-0000', $4),
       ('Líder Louvor', 'lider@igreja.local', $2, 'LIDER_MINISTERIO', '(11) 91111-1111', $4),
       ('Voluntário Exemplo', 'voluntario@igreja.local', $3, 'VOLUNTARIO', '(11) 92222-2222', $4)
      `,
      [adminPass, liderPass, volPass, ministryId],
    );
  }

  await query(
    `INSERT INTO user_ministries (user_id, ministry_id, is_leader, created_by)
     SELECT u.id, u.ministry_id, (u.role = 'LIDER_MINISTERIO'), NULL
     FROM users u
     WHERE u.ministry_id IS NOT NULL
     ON CONFLICT (user_id, ministry_id) DO NOTHING`,
  );

  if (louvorId) {
    await query(
      `INSERT INTO user_ministries (user_id, ministry_id, is_leader, created_by)
       SELECT u.id, $1, (u.role = 'LIDER_MINISTERIO'), NULL
       FROM users u
       WHERE u.email IN ('lider@igreja.local', 'voluntario@igreja.local')
       ON CONFLICT (user_id, ministry_id) DO NOTHING`,
      [louvorId],
    );
  }
}

app.get('/api/health', async (_req, res) => {
  const ping = await query('SELECT now() AS now');
  res.json({ ok: true, dbTime: ping.rows[0].now });
});

app.get('/api/metrics', async (_req, res) => {
  const [users, services, assignments] = await Promise.all([
    query('SELECT COUNT(*)::int AS total FROM users'),
    query('SELECT COUNT(*)::int AS total FROM services'),
    query('SELECT COUNT(*)::int AS total FROM service_assignments'),
  ]);

  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(
    [
      '# HELP app_users_total Total users',
      '# TYPE app_users_total gauge',
      `app_users_total ${users.rows[0].total}`,
      '# HELP app_services_total Total services',
      '# TYPE app_services_total gauge',
      `app_services_total ${services.rows[0].total}`,
      '# HELP app_assignments_total Total assignments',
      '# TYPE app_assignments_total gauge',
      `app_assignments_total ${assignments.rows[0].total}`,
    ].join('\n'),
  );
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Email e senha são obrigatórios' });

  const { rows } = await query(
    `SELECT u.id, u.name, u.email, u.role, u.active, u.ministry_id, u.password_hash,
            coalesce(array_agg(um.ministry_id) FILTER (WHERE um.ministry_id IS NOT NULL), ARRAY[]::uuid[]) AS ministry_ids,
            coalesce(array_agg(um.ministry_id) FILTER (WHERE um.is_leader = true AND um.ministry_id IS NOT NULL), ARRAY[]::uuid[]) AS leader_ministry_ids
     FROM users u
     LEFT JOIN user_ministries um ON um.user_id = u.id
     WHERE lower(u.email) = lower($1)
     GROUP BY u.id
     LIMIT 1`,
    [email],
  );

  const user = rows[0];
  if (!user || !user.active) return res.status(401).json({ message: 'Credenciais inválidas' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ message: 'Credenciais inválidas' });

  const ministryIds = Array.from(new Set([...(user.ministry_ids || []), ...(user.ministry_id ? [user.ministry_id] : [])]));
  const leaderMinistryIds = Array.from(new Set(user.leader_ministry_ids || []));
  const louvorId = await getLouvorMinistryId();
  const canAccessRepertoire = user.role === ROLE_ADMIN || (louvorId ? ministryIds.includes(louvorId) : false);

  const token = signToken({ ...user, ministry_ids: ministryIds, leader_ministry_ids: leaderMinistryIds });
  return res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      ministryId: user.ministry_id,
      ministryIds,
      leaderMinistryIds,
      canAccessRepertoire,
    },
  });
});

app.get('/api/auth/me', authRequired, async (req, res) => {
  const { rows } = await query(
    `SELECT u.id, u.name, u.email, u.role, u.active, u.phone, u.ministry_id,
            coalesce(array_agg(um.ministry_id) FILTER (WHERE um.ministry_id IS NOT NULL), ARRAY[]::uuid[]) AS ministry_ids,
            coalesce(array_agg(um.ministry_id) FILTER (WHERE um.is_leader = true AND um.ministry_id IS NOT NULL), ARRAY[]::uuid[]) AS leader_ministry_ids
     FROM users u
     LEFT JOIN user_ministries um ON um.user_id = u.id
     WHERE u.id = $1
     GROUP BY u.id
     LIMIT 1`,
    [req.user.sub],
  );
  if (!rows[0]) return res.status(404).json({ message: 'Usuário não encontrado' });
  const louvorId = await getLouvorMinistryId();
  const ministryIds = Array.from(new Set([...(rows[0].ministry_ids || []), ...(rows[0].ministry_id ? [rows[0].ministry_id] : [])]));
  return res.json({
    ...rows[0],
    ministry_ids: ministryIds,
    leader_ministry_ids: Array.from(new Set(rows[0].leader_ministry_ids || [])),
    can_access_repertoire: rows[0].role === ROLE_ADMIN || (louvorId ? ministryIds.includes(louvorId) : false),
  });
});

app.post('/api/auth/change-password', authRequired, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Senha atual e nova senha são obrigatórias' });
  }
  if (String(newPassword).length < 6) {
    return res.status(400).json({ message: 'A nova senha deve ter pelo menos 6 caracteres' });
  }

  const { rows } = await query(
    'SELECT id, password_hash, role, ministry_id FROM users WHERE id = $1 LIMIT 1',
    [req.user.sub],
  );
  const user = rows[0];
  if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });

  const ok = await bcrypt.compare(String(currentPassword), user.password_hash);
  if (!ok) return res.status(401).json({ message: 'Senha atual inválida' });

  const nextHash = await bcrypt.hash(String(newPassword), 10);
  await query('UPDATE users SET password_hash = $1 WHERE id = $2', [nextHash, user.id]);

  await writeAudit(req.user.sub, 'CHANGE_PASSWORD', 'USER', user.id, user.ministry_id, {});
  return res.status(200).json({ message: 'Senha atualizada com sucesso' });
});

app.get('/api/ministries', authRequired, async (_req, res) => {
  const { rows } = await query('SELECT id, name, description FROM ministries ORDER BY name');
  res.json(rows);
});

app.post('/api/ministries', authRequired, roleRequired(ROLE_ADMIN), async (req, res) => {
  const { name, description = '' } = req.body;
  if (!name) return res.status(400).json({ message: 'Nome é obrigatório' });

  const { rows } = await query(
    'INSERT INTO ministries (name, description) VALUES ($1, $2) RETURNING id, name, description',
    [name.trim(), description.trim()],
  );
  await writeAudit(req.user.sub, 'CREATE', 'MINISTRY', rows[0].id, rows[0].id, rows[0]);
  res.status(201).json(rows[0]);
});

app.get('/api/users', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const args = [];
  let where = '';
  if (req.user.role === ROLE_LEADER) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where = `WHERE EXISTS (
      SELECT 1
      FROM user_ministries x
      WHERE x.user_id = u.id
        AND x.ministry_id = ANY($1::uuid[])
    ) AND u.role <> 'ADMIN'`;
  }

  const { rows } = await query(
    `SELECT u.id, u.name, u.email, u.role, u.active, u.phone, u.ministry_id,
            coalesce(array_agg(um.ministry_id) FILTER (WHERE um.ministry_id IS NOT NULL), ARRAY[]::uuid[]) AS ministry_ids
     FROM users u
     LEFT JOIN user_ministries um ON um.user_id = u.id
     ${where}
     GROUP BY u.id
     ORDER BY u.name`,
    args,
  );
  res.json(rows);
});

app.post('/api/users', authRequired, roleRequired(ROLE_ADMIN), async (req, res) => {
  const { name, email, password, role, phone = '', ministryId = null, ministryIds = [] } = req.body;
  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: 'Nome, email, senha e perfil são obrigatórios' });
  }
  if (![ROLE_ADMIN, ROLE_LEADER, ROLE_VOL].includes(role)) {
    return res.status(400).json({ message: 'Perfil inválido' });
  }

  const dedupMinistryIds = Array.from(new Set([...(Array.isArray(ministryIds) ? ministryIds : []), ...(ministryId ? [ministryId] : [])]));
  if (role === ROLE_LEADER && dedupMinistryIds.length === 0) {
    return res.status(400).json({ message: 'Para criar Líder, informe ao menos um ministério existente' });
  }

  if (dedupMinistryIds.length) {
    const { rows: checkRows } = await query(
      'SELECT id FROM ministries WHERE id = ANY($1::uuid[])',
      [dedupMinistryIds],
    );
    if (checkRows.length !== dedupMinistryIds.length) {
      return res.status(400).json({ message: 'Um ou mais ministérios informados não existem' });
    }
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const targetMinistryId = dedupMinistryIds[0] || null;
  const { rows } = await query(
    `INSERT INTO users (name, email, password_hash, role, phone, ministry_id)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, name, email, role, phone, active, ministry_id`,
    [name.trim(), email.trim().toLowerCase(), passwordHash, role, phone.trim(), targetMinistryId],
  );

  for (const mid of dedupMinistryIds) {
    await query(
      `INSERT INTO user_ministries (user_id, ministry_id, is_leader, created_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, ministry_id) DO UPDATE SET is_leader = EXCLUDED.is_leader`,
      [rows[0].id, mid, role === ROLE_LEADER, req.user.sub],
    );
  }

  await writeAudit(req.user.sub, 'CREATE', 'USER', rows[0].id, rows[0].ministry_id, {
    email: rows[0].email,
    role: rows[0].role,
    active: rows[0].active,
    ministryIds: dedupMinistryIds,
  });
  res.status(201).json(rows[0]);
});

app.patch('/api/users/:id/ministries', authRequired, roleRequired(ROLE_ADMIN), async (req, res) => {
  const { id } = req.params;
  const inputIds = Array.isArray(req.body.ministryIds) ? req.body.ministryIds.filter(Boolean) : [];
  const ministryIds = Array.from(new Set(inputIds));

  const { rows: targetRows } = await query(
    'SELECT id, role, name, email FROM users WHERE id = $1 LIMIT 1',
    [id],
  );
  const target = targetRows[0];
  if (!target) return res.status(404).json({ message: 'Usuário não encontrado' });

  if (target.role === ROLE_ADMIN) {
    return res.status(409).json({ message: 'Usuário ADMIN não pode ter ministérios alterados' });
  }
  if (target.role === ROLE_LEADER && ministryIds.length === 0) {
    return res.status(400).json({ message: 'Líder precisa ter ao menos um ministério' });
  }

  if (ministryIds.length) {
    const { rows: checkRows } = await query('SELECT id FROM ministries WHERE id = ANY($1::uuid[])', [ministryIds]);
    if (checkRows.length !== ministryIds.length) {
      return res.status(400).json({ message: 'Um ou mais ministérios informados não existem' });
    }
  }

  await query('DELETE FROM user_ministries WHERE user_id = $1', [target.id]);
  for (const mid of ministryIds) {
    await query(
      `INSERT INTO user_ministries (user_id, ministry_id, is_leader, created_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, ministry_id) DO UPDATE SET is_leader = EXCLUDED.is_leader`,
      [target.id, mid, target.role === ROLE_LEADER, req.user.sub],
    );
  }

  await query('UPDATE users SET ministry_id = $1 WHERE id = $2', [ministryIds[0] || null, target.id]);

  await writeAudit(req.user.sub, 'UPDATE_USER_MINISTRIES', 'USER', target.id, ministryIds[0] || null, {
    userEmail: target.email,
    role: target.role,
    ministryIds,
  });

  const { rows } = await query(
    `SELECT u.id, u.name, u.email, u.role, u.active, u.phone, u.ministry_id,
            coalesce(array_agg(um.ministry_id) FILTER (WHERE um.ministry_id IS NOT NULL), ARRAY[]::uuid[]) AS ministry_ids
     FROM users u
     LEFT JOIN user_ministries um ON um.user_id = u.id
     WHERE u.id = $1
     GROUP BY u.id`,
    [target.id],
  );

  return res.json(rows[0]);
});

app.patch('/api/users/:id/active', authRequired, roleRequired(ROLE_ADMIN), async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;

  const { rows: targetRows } = await query('SELECT id, ministry_id, role, active FROM users WHERE id = $1', [id]);
  const target = targetRows[0];
  if (!target) return res.status(404).json({ message: 'Usuário não encontrado' });

  if (!Boolean(active) && target.id === req.user.sub) {
    return res.status(409).json({ message: 'Admin não pode desativar a própria conta' });
  }
  if (!Boolean(active) && target.role === ROLE_ADMIN) {
    return res.status(409).json({ message: 'Conta ADMIN não pode ser desativada' });
  }

  const { rows } = await query(
    `UPDATE users SET active = $1 WHERE id = $2
     RETURNING id, name, email, role, active, phone, ministry_id`,
    [Boolean(active), id],
  );
  await writeAudit(req.user.sub, 'UPDATE_ACTIVE', 'USER', rows[0].id, rows[0].ministry_id, {
    active: rows[0].active,
  });
  res.json(rows[0]);
});

app.get('/api/availability-blocks', authRequired, async (req, res) => {
  const { userId } = req.query;
  const args = [];
  let where = '';

  if (req.user.role === ROLE_VOL) {
    args.push(req.user.sub);
    where = ' WHERE ab.user_id = $1 ';
  } else if (req.user.role === ROLE_LEADER) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where = ' WHERE ab.ministry_id = ANY($1::uuid[]) ';
    if (userId) {
      args.push(userId);
      where += ` AND ab.user_id = $${args.length} `;
    }
  } else if (userId) {
    args.push(userId);
    where = ' WHERE ab.user_id = $1 ';
  }

  const { rows } = await query(
    `SELECT ab.id, ab.user_id, ab.start_date, ab.end_date, ab.reason, ab.created_at, u.name AS user_name
     FROM availability_blocks ab
     JOIN users u ON u.id = ab.user_id
     ${where}
     ORDER BY ab.start_date DESC`,
    args,
  );

  res.json(rows);
});

app.post('/api/availability-blocks', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER, ROLE_VOL), async (req, res) => {
  const { userId, startDate, endDate, reason = '' } = req.body;
  if (!startDate || !endDate) {
    return res.status(400).json({ message: 'Datas inicial e final são obrigatórias' });
  }

  const targetUserId = req.user.role === ROLE_VOL ? req.user.sub : userId;
  if (!targetUserId) return res.status(400).json({ message: 'Voluntário é obrigatório' });

  const { rows: userRows } = await query('SELECT id, ministry_id FROM users WHERE id = $1 LIMIT 1', [targetUserId]);
  const target = userRows[0];
  if (!target) return res.status(404).json({ message: 'Voluntário não encontrado' });

  if (req.user.role === ROLE_LEADER && !hasMinistryAccess(req, target.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para bloquear agenda deste usuário' });
  }

  const { rows } = await query(
    `INSERT INTO availability_blocks (user_id, ministry_id, start_date, end_date, reason, created_by)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, user_id, start_date, end_date, reason`,
    [targetUserId, target.ministry_id, startDate, endDate, reason.trim(), req.user.sub],
  );

  await writeAudit(req.user.sub, 'CREATE', 'AVAILABILITY_BLOCK', rows[0].id, target.ministry_id, rows[0]);
  res.status(201).json(rows[0]);
});

app.delete('/api/availability-blocks/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER, ROLE_VOL), async (req, res) => {
  const { rows } = await query('SELECT id, user_id, ministry_id FROM availability_blocks WHERE id = $1 LIMIT 1', [req.params.id]);
  const block = rows[0];
  if (!block) return res.status(404).json({ message: 'Bloqueio não encontrado' });

  const isOwner = req.user.role === ROLE_VOL && req.user.sub === block.user_id;
  const canManage = req.user.role === ROLE_ADMIN || (req.user.role === ROLE_LEADER && hasMinistryAccess(req, block.ministry_id));
  if (!isOwner && !canManage) return res.status(403).json({ message: 'Sem permissão para remover bloqueio' });

  await query('DELETE FROM availability_blocks WHERE id = $1', [req.params.id]);
  await writeAudit(req.user.sub, 'DELETE', 'AVAILABILITY_BLOCK', block.id, block.ministry_id, {});
  res.status(204).send();
});

app.get('/api/songs', authRequired, async (req, res) => {
  const louvorId = await getLouvorMinistryId();
  const canAccessRepertoire = req.user.role === ROLE_ADMIN || (louvorId && getScopedMinistryIds(req).includes(louvorId));
  if (!canAccessRepertoire) {
    return res.status(403).json({ message: 'Repertório disponível apenas para usuários do ministério LOUVOR' });
  }

  const q = String(req.query.q || '').trim();
  const args = [];
  const conditions = [];

  if (hasRole(req.user, [ROLE_LEADER, ROLE_VOL]) && louvorId) {
    args.push(louvorId);
    conditions.push('s.ministry_id = $1');
  }

  if (q) {
    args.push(`%${q}%`);
    const idx = args.length;
    conditions.push(`(s.title ILIKE $${idx} OR s.key ILIKE $${idx} OR array_to_string(s.tags, ',') ILIKE $${idx})`);
  }

  const where = conditions.length ? ` WHERE ${conditions.join(' AND ')} ` : '';

  const { rows } = await query(
    `SELECT s.id, s.title, s.key, s.bpm, s.web_link, s.tags, s.ministry_id, m.name AS ministry_name
     FROM songs s
     LEFT JOIN ministries m ON m.id = s.ministry_id
     ${where}
     ORDER BY s.title`,
    args,
  );

  res.json(rows);
});

app.post('/api/songs', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const louvorId = await getLouvorMinistryId();
  const canAccessRepertoire = req.user.role === ROLE_ADMIN || (louvorId && getScopedMinistryIds(req).includes(louvorId));
  if (!canAccessRepertoire || !louvorId) {
    return res.status(403).json({ message: 'Somente membros do ministério LOUVOR podem gerenciar repertório' });
  }

  const { title, key, bpm = null, webLink = '', tags = [], ministryId = null } = req.body;
  if (!title || !key) return res.status(400).json({ message: 'Título e tom são obrigatórios' });

  const targetMinistryId = louvorId;
  const parsedTags = parseTags(tags);

  const { rows } = await query(
    `INSERT INTO songs (title, key, bpm, web_link, tags, ministry_id, created_by)
     VALUES ($1, $2, $3, $4, $5::text[], $6, $7)
     RETURNING id, title, key, bpm, web_link, tags, ministry_id`,
    [title.trim(), key.trim(), bpm ? Number(bpm) : null, webLink.trim(), parsedTags, targetMinistryId, req.user.sub],
  );
  await writeAudit(req.user.sub, 'CREATE', 'SONG', rows[0].id, rows[0].ministry_id, {
    title: rows[0].title,
    key: rows[0].key,
  });
  res.status(201).json(rows[0]);
});

app.delete('/api/songs/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const louvorId = await getLouvorMinistryId();
  const canAccessRepertoire = req.user.role === ROLE_ADMIN || (louvorId && getScopedMinistryIds(req).includes(louvorId));
  if (!canAccessRepertoire) {
    return res.status(403).json({ message: 'Somente membros do ministério LOUVOR podem gerenciar repertório' });
  }

  const { rows } = await query('SELECT ministry_id FROM songs WHERE id = $1', [req.params.id]);
  const song = rows[0];
  if (!song) return res.status(404).json({ message: 'Música não encontrada' });

  if (!canManageMinistry(req, song.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para remover esta música' });
  }

  await query('DELETE FROM songs WHERE id = $1', [req.params.id]);
  await writeAudit(req.user.sub, 'DELETE', 'SONG', req.params.id, song.ministry_id, {});
  res.status(204).send();
});

app.get('/api/services', authRequired, async (req, res) => {
  const from = req.query.from || '1900-01-01';
  const to = req.query.to || '2999-12-31';
  const q = String(req.query.q || '').trim();
  const serviceDate = String(req.query.serviceDate || '').trim();

  const args = [from, to];
  const conditions = ['s.service_date BETWEEN $1 AND $2'];

  if (serviceDate) {
    args.push(serviceDate);
    conditions.push(`s.service_date = $${args.length}`);
  }

  if (q) {
    args.push(`%${q}%`);
    const idx = args.length;
    conditions.push(`(s.title ILIKE $${idx} OR to_char(s.service_date, 'DD-MM-YYYY') ILIKE $${idx})`);
  }

  if (hasRole(req.user, [ROLE_LEADER, ROLE_VOL])) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    conditions.push(`s.ministry_id = ANY($${args.length}::uuid[])`);
  }

  const { rows: services } = await query(
    `SELECT s.id, s.service_date, s.service_time, s.title, s.notes, s.tags, s.ministry_id, m.name AS ministry_name
     FROM services s
     LEFT JOIN ministries m ON m.id = s.ministry_id
     WHERE ${conditions.join(' AND ')}
     ORDER BY s.service_date ASC, s.service_time ASC NULLS LAST`,
    args,
  );

  const ids = services.map((s) => s.id);
  if (!ids.length) return res.json([]);

  const { rows: setlist } = await query(
    `SELECT ss.service_id, ss.id, ss.position, ss.note, so.title AS song_title, so.key AS song_key
     FROM service_setlist ss
     JOIN songs so ON so.id = ss.song_id
     WHERE ss.service_id = ANY($1::uuid[])
     ORDER BY ss.service_id, ss.position ASC`,
    [ids],
  );

  const { rows: assignments } = await query(
    `SELECT sa.id, sa.service_id, sa.user_id, sa.team_role, sa.status, u.name AS user_name,
            coalesce(ar.status, 'SEM_APROVACAO') AS approval_status,
            ar.decision_note
     FROM service_assignments sa
     JOIN users u ON u.id = sa.user_id
     LEFT JOIN approval_requests ar ON ar.assignment_id = sa.id
     WHERE sa.service_id = ANY($1::uuid[])
     ORDER BY sa.service_id, sa.team_role`,
    [ids],
  );

  const response = services.map((service) => ({
    ...service,
    setlist: setlist.filter((item) => item.service_id === service.id),
    assignments: assignments.filter((item) => item.service_id === service.id),
  }));

  res.json(response);
});

app.post('/api/services', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const { serviceDate, serviceTime = null, title, notes = '', tags = [], ministryId = null } = req.body;
  if (!serviceDate || !title) return res.status(400).json({ message: 'Data e título são obrigatórios' });

  const scoped = getScopedMinistryIds(req);
  const targetMinistryId = req.user.role === ROLE_LEADER ? scoped[0] || null : ministryId || req.user.ministryId || null;
  const parsedTags = parseTags(tags);

  const { rows } = await query(
    `INSERT INTO services (service_date, service_time, title, notes, tags, ministry_id, created_by)
     VALUES ($1, $2, $3, $4, $5::text[], $6, $7)
     RETURNING id, service_date, service_time, title, notes, tags, ministry_id`,
    [serviceDate, serviceTime || null, title.trim(), notes.trim(), parsedTags, targetMinistryId, req.user.sub],
  );
  await writeAudit(req.user.sub, 'CREATE', 'SERVICE', rows[0].id, rows[0].ministry_id, {
    serviceDate: rows[0].service_date,
    title: rows[0].title,
  });
  res.status(201).json(rows[0]);
});

app.patch('/api/services/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const { id } = req.params;
  const { serviceDate, serviceTime, title, notes, tags } = req.body;

  const { rows: existingRows } = await query(
    `SELECT id, service_date, service_time, title, notes, tags, ministry_id
     FROM services WHERE id = $1 LIMIT 1`,
    [id],
  );
  const existing = existingRows[0];
  if (!existing) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, existing.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para editar este culto' });
  }

  const nextServiceDate = serviceDate || existing.service_date;
  const nextServiceTime = typeof serviceTime === 'undefined' ? existing.service_time : serviceTime || null;
  const nextTitle = (title || existing.title || '').trim();
  const nextNotes = typeof notes === 'undefined' ? existing.notes : String(notes || '').trim();
  const nextTags = typeof tags === 'undefined' ? existing.tags : parseTags(tags);

  if (!nextServiceDate || !nextTitle) {
    return res.status(400).json({ message: 'Data e título do culto são obrigatórios' });
  }

  const { rows } = await query(
    `UPDATE services
     SET service_date = $1,
         service_time = $2,
         title = $3,
         notes = $4,
         tags = $5::text[]
     WHERE id = $6
     RETURNING id, service_date, service_time, title, notes, tags, ministry_id`,
    [nextServiceDate, nextServiceTime, nextTitle, nextNotes, nextTags, id],
  );

  await writeAudit(req.user.sub, 'UPDATE', 'SERVICE', id, existing.ministry_id, {
    before: {
      serviceDate: existing.service_date,
      serviceTime: existing.service_time,
      title: existing.title,
      notes: existing.notes,
      tags: existing.tags,
    },
    after: {
      serviceDate: rows[0].service_date,
      serviceTime: rows[0].service_time,
      title: rows[0].title,
      notes: rows[0].notes,
      tags: rows[0].tags,
    },
  });

  res.json(rows[0]);
});

app.delete('/api/services/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const { id } = req.params;
  const { rows } = await query(
    `SELECT id, service_date, service_time, title, ministry_id
     FROM services WHERE id = $1 LIMIT 1`,
    [id],
  );
  const service = rows[0];
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para excluir este culto' });
  }

  await query('DELETE FROM services WHERE id = $1', [id]);
  await writeAudit(req.user.sub, 'DELETE', 'SERVICE', id, service.ministry_id, {
    serviceDate: service.service_date,
    serviceTime: service.service_time,
    title: service.title,
  });

  res.status(204).send();
});

app.get('/api/services/:id', authRequired, async (req, res) => {
  const service = await getServiceWithMinistry(req.params.id);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });

  if (hasRole(req.user, [ROLE_LEADER, ROLE_VOL]) && !hasMinistryAccess(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const [setlistResult, assignmentsResult] = await Promise.all([
    query(
      `SELECT ss.id, ss.position, ss.note, so.id AS song_id, so.title AS song_title, so.key AS song_key, so.web_link
       FROM service_setlist ss
       JOIN songs so ON so.id = ss.song_id
       WHERE ss.service_id = $1
       ORDER BY ss.position ASC`,
      [service.id],
    ),
    query(
      `SELECT sa.id, sa.user_id, sa.team_role, sa.status, u.name AS user_name,
              coalesce(ar.status, 'SEM_APROVACAO') AS approval_status,
              ar.decision_note
       FROM service_assignments sa
       JOIN users u ON u.id = sa.user_id
       LEFT JOIN approval_requests ar ON ar.assignment_id = sa.id
       WHERE sa.service_id = $1
       ORDER BY sa.team_role ASC`,
      [service.id],
    ),
  ]);

  res.json({
    ...service,
    setlist: setlistResult.rows,
    assignments: assignmentsResult.rows,
  });
});

app.post('/api/services/:id/setlist', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const { id: serviceId } = req.params;
  const { songId, position, note = '' } = req.body;

  if (!songId || !position) {
    return res.status(400).json({ message: 'Música e posição são obrigatórias' });
  }

  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const { rows } = await query(
    `INSERT INTO service_setlist (service_id, song_id, position, note)
     VALUES ($1, $2, $3, $4)
     RETURNING id, service_id, song_id, position, note`,
    [serviceId, songId, Number(position), note.trim()],
  );
  await writeAudit(req.user.sub, 'ADD_SETLIST_ITEM', 'SERVICE', serviceId, service.ministry_id, rows[0]);
  res.status(201).json(rows[0]);
});

app.patch('/api/services/:serviceId/setlist/:itemId', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const { serviceId, itemId } = req.params;
  const { position, note } = req.body;

  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const { rows: existingRows } = await query(
    'SELECT id, position, note FROM service_setlist WHERE id = $1 AND service_id = $2 LIMIT 1',
    [itemId, serviceId],
  );
  const existing = existingRows[0];
  if (!existing) return res.status(404).json({ message: 'Item de repertório não encontrado' });

  const nextPosition = Number(position || existing.position);
  const nextNote = typeof note === 'undefined' ? existing.note : String(note || '').trim();
  if (!Number.isInteger(nextPosition) || nextPosition < 1) {
    return res.status(400).json({ message: 'Posição inválida' });
  }

  if (nextPosition !== existing.position) {
    const { rows: occupiedRows } = await query(
      'SELECT id FROM service_setlist WHERE service_id = $1 AND position = $2 AND id <> $3 LIMIT 1',
      [serviceId, nextPosition, itemId],
    );
    if (occupiedRows[0]) {
      return res.status(409).json({ message: 'Já existe música nesta posição do repertório' });
    }
  }

  const { rows } = await query(
    `UPDATE service_setlist
     SET position = $1, note = $2
     WHERE id = $3
     RETURNING id, service_id, song_id, position, note`,
    [nextPosition, nextNote, itemId],
  );

  await writeAudit(req.user.sub, 'UPDATE_SETLIST_ITEM', 'SERVICE', serviceId, service.ministry_id, {
    itemId,
    before: { position: existing.position, note: existing.note },
    after: { position: rows[0].position, note: rows[0].note },
  });

  res.json(rows[0]);
});

app.delete('/api/services/:serviceId/setlist/:itemId', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const { serviceId, itemId } = req.params;
  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const { rows } = await query(
    'SELECT id, position, note FROM service_setlist WHERE id = $1 AND service_id = $2 LIMIT 1',
    [itemId, serviceId],
  );
  const item = rows[0];
  if (!item) return res.status(404).json({ message: 'Item de repertório não encontrado' });

  await query('DELETE FROM service_setlist WHERE id = $1', [itemId]);
  await writeAudit(req.user.sub, 'DELETE_SETLIST_ITEM', 'SERVICE', serviceId, service.ministry_id, {
    itemId,
    position: item.position,
    note: item.note,
  });
  res.status(204).send();
});

app.post('/api/services/:id/assignments', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const { id: serviceId } = req.params;
  const { userId, teamRole } = req.body;

  if (!userId || !teamRole) {
    return res.status(400).json({ message: 'Voluntário e função são obrigatórios' });
  }

  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const result = await createAssignmentWithRules({
    serviceId,
    userId,
    teamRole,
    actorUserId: req.user.sub,
  });

  if (result.error) return res.status(result.error.code).json({ message: result.error.message });

  res.status(201).json({ ...result.assignment, approvalStatus: result.approvalStatus });
});

app.post('/api/services/:id/self-assign', authRequired, roleRequired(ROLE_VOL), async (req, res) => {
  const { id: serviceId } = req.params;
  const { teamRole } = req.body;

  if (!teamRole) return res.status(400).json({ message: 'Função na escala é obrigatória' });

  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });

  if (service.ministry_id && !hasMinistryAccess(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Você não pode se inscrever em culto de outro ministério' });
  }

  const result = await createAssignmentWithRules({
    serviceId,
    userId: req.user.sub,
    teamRole,
    actorUserId: req.user.sub,
  });

  if (result.error) return res.status(result.error.code).json({ message: result.error.message });

  res.status(201).json({ ...result.assignment, approvalStatus: result.approvalStatus });
});

app.post('/api/planning/repeat-service', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const {
    sourceServiceId,
    startDate,
    endDate,
    intervalDays = 7,
    copySetlist = true,
    copyAssignments = true,
    titlePrefix = '',
  } = req.body;

  if (!sourceServiceId || !startDate || !endDate) {
    return res.status(400).json({ message: 'sourceServiceId, startDate e endDate são obrigatórios' });
  }

  const source = await getServiceWithMinistry(sourceServiceId);
  if (!source) return res.status(404).json({ message: 'Culto de origem não encontrado' });
  if (!canManageMinistry(req, source.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para repetir este culto' });
  }

  const { rows: sourceSetlist } = await query(
    'SELECT song_id, position, note FROM service_setlist WHERE service_id = $1 ORDER BY position',
    [sourceServiceId],
  );
  const { rows: sourceAssignments } = await query(
    'SELECT user_id, team_role FROM service_assignments WHERE service_id = $1 ORDER BY team_role',
    [sourceServiceId],
  );

  const start = asDateOnly(startDate);
  const end = asDateOnly(endDate);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) {
    return res.status(400).json({ message: 'Período inválido para repetição' });
  }

  const createdServices = [];
  const skipped = [];

  for (let dt = new Date(start); dt <= end; dt.setDate(dt.getDate() + Number(intervalDays))) {
    const serviceDate = dateToISO(dt);

    const { rows: existingRows } = await query(
      `SELECT id FROM services
       WHERE service_date = $1
         AND title = $2
         AND ministry_id IS NOT DISTINCT FROM $3
         AND service_time IS NOT DISTINCT FROM $4
       LIMIT 1`,
      [serviceDate, `${titlePrefix}${source.title}`.trim(), source.ministry_id, source.service_time],
    );

    if (existingRows[0]) {
      skipped.push({ date: serviceDate, reason: 'Culto já existe' });
      continue;
    }

    const { rows: insertedRows } = await query(
      `INSERT INTO services (service_date, service_time, title, notes, tags, ministry_id, created_by)
       VALUES ($1, $2, $3, $4, $5::text[], $6, $7)
       RETURNING id, service_date, service_time, title`,
      [
        serviceDate,
        source.service_time || null,
        `${titlePrefix}${source.title}`.trim(),
        source.notes || '',
        source.tags || [],
        source.ministry_id,
        req.user.sub,
      ],
    );

    const created = insertedRows[0];

    if (copySetlist) {
      for (const item of sourceSetlist) {
        await query(
          `INSERT INTO service_setlist (service_id, song_id, position, note)
           VALUES ($1, $2, $3, $4)`,
          [created.id, item.song_id, item.position, item.note || ''],
        );
      }
    }

    const assignmentWarnings = [];
    if (copyAssignments) {
      for (const item of sourceAssignments) {
        const result = await createAssignmentWithRules({
          serviceId: created.id,
          userId: item.user_id,
          teamRole: item.team_role,
          actorUserId: req.user.sub,
        });

        if (result.error) {
          assignmentWarnings.push({ userId: item.user_id, reason: result.error.message });
        }
      }
    }

    createdServices.push({
      id: created.id,
      serviceDate: created.service_date,
      title: created.title,
      assignmentWarnings,
    });
  }

  await writeAudit(req.user.sub, 'REPEAT_SERVICE_PLAN', 'SERVICE', sourceServiceId, source.ministry_id, {
    startDate,
    endDate,
    intervalDays,
    createdCount: createdServices.length,
    skippedCount: skipped.length,
  });

  res.status(201).json({ createdServices, skipped });
});

app.post('/api/services/bulk', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const {
    startDate,
    endDate,
    weekdays = [0],
    ministryId = null,
    notes = '',
    tags = [],
    timeSlots = [],
  } = req.body;

  if (!startDate || !endDate) {
    return res.status(400).json({ message: 'startDate e endDate são obrigatórios' });
  }

  const parsedWeekdays = Array.isArray(weekdays)
    ? weekdays.map((w) => Number(w)).filter((w) => w >= 0 && w <= 6)
    : [];
  if (!parsedWeekdays.length) {
    return res.status(400).json({ message: 'Informe ao menos um dia da semana válido (0-6)' });
  }

  const parsedSlots = Array.isArray(timeSlots)
    ? timeSlots
        .map((slot) => ({
          title: String(slot.title || '').trim(),
          serviceTime: String(slot.serviceTime || '').trim() || null,
          notes: String(slot.notes || notes || '').trim(),
        }))
        .filter((slot) => slot.title)
    : [];
  if (!parsedSlots.length) {
    return res.status(400).json({ message: 'Informe ao menos um turno/título de culto' });
  }

  const scoped = getScopedMinistryIds(req);
  const targetMinistryId = req.user.role === ROLE_LEADER ? scoped[0] || null : ministryId || req.user.ministryId || null;
  const parsedTags = parseTags(tags);

  const start = asDateOnly(startDate);
  const end = asDateOnly(endDate);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) {
    return res.status(400).json({ message: 'Período inválido' });
  }

  const createdServices = [];
  const skipped = [];

  for (let dt = new Date(start); dt <= end; dt.setDate(dt.getDate() + 1)) {
    const weekday = dt.getDay();
    if (!parsedWeekdays.includes(weekday)) continue;

    const serviceDate = dateToISO(dt);

    for (const slot of parsedSlots) {
      const { rows: existingRows } = await query(
        `SELECT id FROM services
         WHERE service_date = $1
           AND title = $2
           AND ministry_id IS NOT DISTINCT FROM $3
           AND service_time IS NOT DISTINCT FROM $4
         LIMIT 1`,
        [serviceDate, slot.title, targetMinistryId, slot.serviceTime],
      );

      if (existingRows[0]) {
        skipped.push({ date: serviceDate, title: slot.title, reason: 'Culto já existe' });
        continue;
      }

      const { rows } = await query(
        `INSERT INTO services (service_date, service_time, title, notes, tags, ministry_id, created_by)
         VALUES ($1, $2, $3, $4, $5::text[], $6, $7)
         RETURNING id, service_date, service_time, title`,
        [serviceDate, slot.serviceTime, slot.title, slot.notes, parsedTags, targetMinistryId, req.user.sub],
      );

      createdServices.push(rows[0]);
    }
  }

  await writeAudit(req.user.sub, 'BULK_CREATE_SERVICES', 'SERVICE', null, targetMinistryId, {
    startDate,
    endDate,
    weekdays: parsedWeekdays,
    createdCount: createdServices.length,
    skippedCount: skipped.length,
  });

  res.status(201).json({ createdServices, skipped });
});

app.get('/api/approvals/pending', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const args = [];
  let where = " WHERE ar.status = 'PENDENTE' ";
  if (req.user.role === ROLE_LEADER) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where += ' AND s.ministry_id = ANY($1::uuid[]) ';
  }

  const { rows } = await query(
    `SELECT ar.id, ar.assignment_id, ar.status, ar.created_at,
            sa.team_role, sa.user_id, u.name AS user_name,
            s.id AS service_id, s.title AS service_title, s.service_date,
            m.name AS ministry_name
     FROM approval_requests ar
     JOIN service_assignments sa ON sa.id = ar.assignment_id
     JOIN services s ON s.id = sa.service_id
     JOIN users u ON u.id = sa.user_id
     LEFT JOIN ministries m ON m.id = s.ministry_id
     ${where}
     ORDER BY ar.created_at ASC`,
    args,
  );

  res.json(rows);
});

app.patch('/api/approvals/:assignmentId', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const { decision, note = '' } = req.body;
  if (!['APROVAR', 'REJEITAR'].includes(decision)) {
    return res.status(400).json({ message: 'Decisão inválida' });
  }
  if (!isUuid(req.params.assignmentId)) {
    return res.status(400).json({ message: 'ID de escala inválido' });
  }

  const { rows } = await query(
    `SELECT ar.id, ar.status, sa.id AS assignment_id, sa.user_id, sa.service_id, s.ministry_id, s.service_date, s.title
     FROM approval_requests ar
     JOIN service_assignments sa ON sa.id = ar.assignment_id
     JOIN services s ON s.id = sa.service_id
     WHERE sa.id = $1
     LIMIT 1`,
    [req.params.assignmentId],
  );

  const approval = rows[0];
  if (!approval) return res.status(404).json({ message: 'Solicitação de aprovação não encontrada' });
  if (!canManageMinistry(req, approval.ministry_id)) return res.status(403).json({ message: 'Sem permissão para aprovar esta escala' });

  const newApprovalStatus = decision === 'APROVAR' ? 'APROVADO' : 'REJEITADO';
  const newAssignmentStatus = decision === 'APROVAR' ? 'PENDENTE' : 'RECUSADO';

  await query(
    `UPDATE approval_requests
     SET status = $1, decision_note = $2, approver_user_id = $3, decided_at = now()
     WHERE id = $4`,
    [newApprovalStatus, note.trim(), req.user.sub, approval.id],
  );

  await query('UPDATE service_assignments SET status = $1 WHERE id = $2', [newAssignmentStatus, approval.assignment_id]);

  await notifyUserMultiChannel({
    userId: approval.user_id,
    ministryId: approval.ministry_id,
    template: 'DECISAO_APROVACAO_ESCALA',
    event: 'APPROVAL_DECISION',
    payload: {
      decision: newApprovalStatus,
      note: note.trim(),
      serviceTitle: approval.title,
      serviceDate: approval.service_date,
    },
  });

  await writeAudit(req.user.sub, 'APPROVAL_DECISION', 'ASSIGNMENT', approval.assignment_id, approval.ministry_id, {
    decision: newApprovalStatus,
    note: note.trim(),
  });

  res.json({ assignmentId: approval.assignment_id, approvalStatus: newApprovalStatus, assignmentStatus: newAssignmentStatus });
});

app.patch('/api/assignments/:id/status', authRequired, async (req, res) => {
  const { status } = req.body;
  const allowed = ['PENDENTE', 'CONFIRMADO', 'RECUSADO'];
  if (!allowed.includes(status)) {
    return res.status(400).json({ message: 'Status inválido' });
  }
  if (!isUuid(req.params.id)) {
    return res.status(400).json({ message: 'ID de escala inválido' });
  }

  const { rows: currentRows } = await query(
    `SELECT sa.id, sa.user_id, sa.team_role, s.ministry_id, s.title, s.service_date,
            coalesce(ar.status, 'SEM_APROVACAO') AS approval_status
     FROM service_assignments sa
     JOIN services s ON s.id = sa.service_id
     LEFT JOIN approval_requests ar ON ar.assignment_id = sa.id
     WHERE sa.id = $1`,
    [req.params.id],
  );

  const assignment = currentRows[0];
  if (!assignment) return res.status(404).json({ message: 'Escala não encontrada' });

  const canSelfUpdate = req.user.role === ROLE_VOL && req.user.sub === assignment.user_id;
  const canLeaderUpdate = canManageMinistry(req, assignment.ministry_id);
  if (!canSelfUpdate && !canLeaderUpdate) {
    return res.status(403).json({ message: 'Sem permissão para alterar este status' });
  }

  if (canSelfUpdate && assignment.approval_status === 'PENDENTE' && status !== 'PENDENTE') {
    await query(
      `UPDATE approval_requests
       SET status = 'APROVADO',
           decision_note = coalesce(nullif(decision_note, ''), 'Autoaprovado pela confirmação do voluntário'),
           approver_user_id = $1,
           decided_at = now()
       WHERE assignment_id = $2`,
      [req.user.sub, assignment.id],
    );
  }

  const { rows } = await query(
    `UPDATE service_assignments SET status = $1 WHERE id = $2
     RETURNING id, service_id, user_id, team_role, status`,
    [status, req.params.id],
  );

  await notifyUserMultiChannel({
    userId: assignment.user_id,
    ministryId: assignment.ministry_id,
    template: 'STATUS_ESCALA_ALTERADO',
    event: 'ASSIGNMENT_STATUS_UPDATED',
    payload: {
      status,
      serviceTitle: assignment.title,
      serviceDate: assignment.service_date,
      teamRole: assignment.team_role,
    },
  });

  await writeAudit(req.user.sub, 'UPDATE_ASSIGNMENT_STATUS', 'ASSIGNMENT', rows[0].id, assignment.ministry_id, {
    status: rows[0].status,
  });

  res.json(rows[0]);
});

app.post('/api/assignments/:id/swap-request', authRequired, roleRequired(ROLE_VOL), async (req, res) => {
  if (!isUuid(req.params.id)) {
    return res.status(400).json({ message: 'ID de escala inválido' });
  }

  const { reason = '', requestedToUserId = null } = req.body;
  if (!String(reason).trim()) {
    return res.status(400).json({ message: 'Motivo da troca é obrigatório' });
  }

  const { rows: assignmentRows } = await query(
    `SELECT sa.id, sa.user_id, sa.status, sa.team_role, s.id AS service_id, s.title, s.service_date, s.ministry_id
     FROM service_assignments sa
     JOIN services s ON s.id = sa.service_id
     WHERE sa.id = $1
     LIMIT 1`,
    [req.params.id],
  );
  const assignment = assignmentRows[0];
  if (!assignment) return res.status(404).json({ message: 'Escala não encontrada' });
  if (assignment.user_id !== req.user.sub) {
    return res.status(403).json({ message: 'Você só pode solicitar troca da sua própria escala' });
  }
  if (assignment.status === 'RECUSADO') {
    return res.status(409).json({ message: 'Escala já recusada, troca não é necessária' });
  }

  const { rows: pendingRows } = await query(
    `SELECT id
     FROM assignment_swap_requests
     WHERE assignment_id = $1
       AND requester_user_id = $2
       AND status = 'PENDENTE'
     LIMIT 1`,
    [assignment.id, req.user.sub],
  );
  if (pendingRows[0]) {
    return res.status(409).json({ message: 'Já existe uma solicitação de troca pendente para esta escala' });
  }

  const requestedTo = requestedToUserId && isUuid(requestedToUserId) ? requestedToUserId : null;
  const { rows } = await query(
    `INSERT INTO assignment_swap_requests (assignment_id, requester_user_id, requested_to_user_id, reason, status)
     VALUES ($1, $2, $3, $4, 'PENDENTE')
     RETURNING id, assignment_id, requester_user_id, requested_to_user_id, reason, status, created_at`,
    [assignment.id, req.user.sub, requestedTo, String(reason).trim()],
  );

  const { rows: leaderRows } = await query(
    `SELECT id
     FROM users
     WHERE role = 'LIDER_MINISTERIO'
       AND active = true
       AND ministry_id IS NOT DISTINCT FROM $1
     ORDER BY created_at ASC
     LIMIT 1`,
    [assignment.ministry_id],
  );

  if (leaderRows[0]?.id) {
    await notifyUserMultiChannel({
      userId: leaderRows[0].id,
      ministryId: assignment.ministry_id,
      template: 'SOLICITACAO_TROCA_ESCALA',
      event: 'SWAP_REQUEST_CREATED',
      payload: {
        assignmentId: assignment.id,
        serviceId: assignment.service_id,
        serviceTitle: assignment.title,
        serviceDate: assignment.service_date,
        teamRole: assignment.team_role,
        requesterUserId: req.user.sub,
        reason: String(reason).trim(),
      },
    });
  }

  await writeAudit(req.user.sub, 'REQUEST_SWAP', 'ASSIGNMENT', assignment.id, assignment.ministry_id, {
    reason: String(reason).trim(),
    requestedToUserId: requestedTo,
  });

  res.status(201).json(rows[0]);
});

app.get('/api/swap-requests', authRequired, async (req, res) => {
  const status = String(req.query.status || 'PENDENTE').toUpperCase();
  const allowedStatus = ['PENDENTE', 'APROVADA', 'REJEITADA', 'CANCELADA'];
  if (!allowedStatus.includes(status)) {
    return res.status(400).json({ message: 'Status inválido' });
  }

  let where = ' WHERE sr.status = $1 ';
  const args = [status];

  if (req.user.role === ROLE_VOL) {
    args.push(req.user.sub);
    where += ` AND sr.requester_user_id = $${args.length} `;
  } else if (req.user.role === ROLE_LEADER) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where += ` AND s.ministry_id = ANY($${args.length}::uuid[]) `;
  }

  const { rows } = await query(
    `SELECT sr.id, sr.assignment_id, sr.reason, sr.status, sr.decision_note, sr.created_at, sr.decided_at,
            sr.requester_user_id, ru.name AS requester_name,
            sr.requested_to_user_id, tu.name AS requested_to_name,
            sr.approver_user_id, au.name AS approver_name,
            s.id AS service_id, s.title AS service_title, s.service_date, s.ministry_id,
            sa.team_role
     FROM assignment_swap_requests sr
     JOIN service_assignments sa ON sa.id = sr.assignment_id
     JOIN services s ON s.id = sa.service_id
     JOIN users ru ON ru.id = sr.requester_user_id
     LEFT JOIN users tu ON tu.id = sr.requested_to_user_id
     LEFT JOIN users au ON au.id = sr.approver_user_id
     ${where}
     ORDER BY sr.created_at DESC
     LIMIT 300`,
    args,
  );

  res.json(rows);
});

app.patch('/api/swap-requests/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  if (!isUuid(req.params.id)) {
    return res.status(400).json({ message: 'ID de solicitação inválido' });
  }

  const { decision, note = '' } = req.body;
  if (!['APROVAR', 'REJEITAR'].includes(decision)) {
    return res.status(400).json({ message: 'Decisão inválida' });
  }

  const { rows: requestRows } = await query(
    `SELECT sr.id, sr.status, sr.assignment_id, sr.requester_user_id, sa.team_role, sa.service_id, s.title, s.service_date, s.ministry_id
     FROM assignment_swap_requests sr
     JOIN service_assignments sa ON sa.id = sr.assignment_id
     JOIN services s ON s.id = sa.service_id
     WHERE sr.id = $1
     LIMIT 1`,
    [req.params.id],
  );
  const swap = requestRows[0];
  if (!swap) return res.status(404).json({ message: 'Solicitação de troca não encontrada' });
  if (!canManageMinistry(req, swap.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para decidir esta solicitação' });
  }
  if (swap.status !== 'PENDENTE') {
    return res.status(409).json({ message: 'Solicitação já foi decidida' });
  }

  const finalStatus = decision === 'APROVAR' ? 'APROVADA' : 'REJEITADA';
  await query(
    `UPDATE assignment_swap_requests
     SET status = $1,
         approver_user_id = $2,
         decision_note = $3,
         decided_at = now()
     WHERE id = $4`,
    [finalStatus, req.user.sub, String(note || '').trim(), swap.id],
  );

  if (decision === 'APROVAR') {
    await query(`UPDATE service_assignments SET status = 'RECUSADO' WHERE id = $1`, [swap.assignment_id]);
    await query(
      `UPDATE approval_requests
       SET status = 'REJEITADO',
           decision_note = coalesce(nullif(decision_note, ''), 'Escala liberada por troca aprovada'),
           approver_user_id = $1,
           decided_at = now()
       WHERE assignment_id = $2`,
      [req.user.sub, swap.assignment_id],
    );
  }

  await notifyUserMultiChannel({
    userId: swap.requester_user_id,
    ministryId: swap.ministry_id,
    template: 'DECISAO_TROCA_ESCALA',
    event: 'SWAP_REQUEST_DECISION',
    payload: {
      decision: finalStatus,
      note: String(note || '').trim(),
      serviceTitle: swap.title,
      serviceDate: swap.service_date,
      teamRole: swap.team_role,
    },
  });

  await writeAudit(req.user.sub, 'SWAP_DECISION', 'ASSIGNMENT', swap.assignment_id, swap.ministry_id, {
    swapRequestId: swap.id,
    decision: finalStatus,
    note: String(note || '').trim(),
  });

  res.json({ id: swap.id, status: finalStatus });
});

app.get('/api/audit-logs', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const args = [];
  let where = '';
  if (req.user.role === ROLE_LEADER) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where = ' WHERE al.ministry_id = ANY($1::uuid[]) ';
  }

  const { rows } = await query(
    `SELECT al.id, al.action, al.entity, al.entity_id, al.ministry_id, al.payload, al.created_at, u.name AS actor_name
     FROM audit_logs al
     LEFT JOIN users u ON u.id = al.actor_user_id
     ${where}
     ORDER BY al.created_at DESC
     LIMIT 300`,
    args,
  );

  res.json(rows);
});

app.get('/api/notifications', authRequired, async (req, res) => {
  const args = [];
  let where = '';

  if (req.user.role === ROLE_VOL) {
    args.push(req.user.sub);
    where = ' WHERE nl.user_id = $1 ';
  } else if (req.user.role === ROLE_LEADER) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where = ' WHERE nl.ministry_id = ANY($1::uuid[]) ';
  }

  const { rows } = await query(
    `SELECT nl.id, nl.channel, nl.template, nl.event, nl.status, nl.payload, nl.created_at, nl.sent_at, u.name AS user_name
     FROM notification_logs nl
     LEFT JOIN users u ON u.id = nl.user_id
     ${where}
     ORDER BY nl.created_at DESC
     LIMIT 300`,
    args,
  );

  res.json(rows);
});

app.post('/api/notifications/test', authRequired, async (req, res) => {
  const { channel = 'PUSH' } = req.body;
  if (!['WHATSAPP', 'EMAIL', 'PUSH'].includes(channel)) {
    return res.status(400).json({ message: 'Canal inválido' });
  }

  await notifyUserMultiChannel({
    userId: req.user.sub,
    ministryId: getScopedMinistryIds(req)[0] || req.user.ministryId || null,
    template: 'TESTE_CANAL',
    event: 'TEST_NOTIFICATION',
    payload: { initiatedBy: req.user.email, requestedChannel: channel },
    channels: [channel],
  });

  res.status(201).json({ message: `Notificação de teste registrada no canal ${channel}` });
});

app.post('/api/notifications/reminders/pending-confirmations', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), async (req, res) => {
  const args = [];
  let where = `
    WHERE sa.status = 'PENDENTE'
      AND s.service_date >= current_date
  `;

  if (req.user.role === ROLE_LEADER) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.status(201).json({ reminders: 0 });
    args.push(scoped);
    where += ` AND s.ministry_id = ANY($${args.length}::uuid[]) `;
  }

  const { rows } = await query(
    `SELECT sa.id AS assignment_id, sa.user_id, sa.team_role, s.id AS service_id, s.title, s.service_date, s.ministry_id
     FROM service_assignments sa
     JOIN services s ON s.id = sa.service_id
     ${where}
     ORDER BY s.service_date ASC
     LIMIT 500`,
    args,
  );

  let sent = 0;
  for (const row of rows) {
    await notifyUserMultiChannel({
      userId: row.user_id,
      ministryId: row.ministry_id,
      template: 'LEMBRETE_CONFIRMACAO_ESCALA',
      event: 'PENDING_CONFIRMATION_REMINDER',
      payload: {
        assignmentId: row.assignment_id,
        serviceId: row.service_id,
        serviceTitle: row.title,
        serviceDate: row.service_date,
        teamRole: row.team_role,
      },
    });
    sent += 1;
  }

  await writeAudit(req.user.sub, 'SEND_PENDING_CONFIRMATION_REMINDERS', 'ASSIGNMENT', null, getScopedMinistryIds(req)[0] || null, {
    reminders: sent,
  });

  res.status(201).json({ reminders: sent });
});

app.get('/api/dashboard', authRequired, async (req, res) => {
  const params = [];
  let whereUsers = '';
  let whereSongs = '';
  let whereServices = '';
  let whereAssignments = '';
  let whereApprovals = '';

  if (req.user.role !== ROLE_ADMIN) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) {
      return res.json({ users: 0, songs: 0, services: 0, blocks: 0, pendingApprovals: 0, pendingSwaps: 0, assignments: [] });
    }
    params.push(scoped);
    whereUsers = ' WHERE EXISTS (SELECT 1 FROM user_ministries um WHERE um.user_id = users.id AND um.ministry_id = ANY($1::uuid[])) ';
    whereSongs = ' WHERE ministry_id = ANY($1::uuid[]) ';
    whereServices = ' WHERE ministry_id = ANY($1::uuid[]) ';
    whereAssignments = ' WHERE s.ministry_id = ANY($1::uuid[]) ';
    whereApprovals = ' WHERE s.ministry_id = ANY($1::uuid[]) ';
  }

  const [usersCount, songsCount, servicesCount, assignmentStats, pendingApprovals, blocksCount, pendingSwaps] = await Promise.all([
    query(`SELECT COUNT(*)::int AS total FROM users ${whereUsers}`, params),
    query(`SELECT COUNT(*)::int AS total FROM songs ${whereSongs}`, params),
    query(`SELECT COUNT(*)::int AS total FROM services ${whereServices}`, params),
    query(
      `SELECT status, COUNT(*)::int AS total
       FROM service_assignments sa
       JOIN services s ON s.id = sa.service_id
       ${whereAssignments}
       GROUP BY status`,
      params,
    ),
    query(
      `SELECT COUNT(*)::int AS total
       FROM approval_requests ar
       JOIN service_assignments sa ON sa.id = ar.assignment_id
       JOIN services s ON s.id = sa.service_id
       ${whereApprovals} ${whereApprovals ? ' AND ' : ' WHERE '} ar.status = 'PENDENTE'`,
      params,
    ),
    query(
      `SELECT COUNT(*)::int AS total
       FROM availability_blocks ab
       ${req.user.role === ROLE_ADMIN ? '' : 'WHERE ab.ministry_id = ANY($1::uuid[])'}`,
      req.user.role === ROLE_ADMIN ? [] : params,
    ),
    query(
      `SELECT COUNT(*)::int AS total
       FROM assignment_swap_requests sr
       JOIN service_assignments sa ON sa.id = sr.assignment_id
       JOIN services s ON s.id = sa.service_id
       ${whereApprovals} ${whereApprovals ? ' AND ' : ' WHERE '} sr.status = 'PENDENTE'`,
      params,
    ),
  ]);

  res.json({
    users: usersCount.rows[0]?.total || 0,
    songs: songsCount.rows[0]?.total || 0,
    services: servicesCount.rows[0]?.total || 0,
    blocks: blocksCount.rows[0]?.total || 0,
    pendingApprovals: pendingApprovals.rows[0]?.total || 0,
    pendingSwaps: pendingSwaps.rows[0]?.total || 0,
    assignments: assignmentStats.rows,
  });
});

app.use('/app', express.static(path.join(__dirname, '..', 'public')));
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.use((err, _req, res, _next) => {
  // eslint-disable-next-line no-console
  console.error(err);
  res.status(500).json({ message: 'Erro interno no servidor' });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      // eslint-disable-next-line no-console
      console.log(`API rodando na porta ${PORT}`);
    });
  })
  .catch((error) => {
    // eslint-disable-next-line no-console
    console.error('Falha ao iniciar aplicação:', error);
    process.exit(1);
  });
