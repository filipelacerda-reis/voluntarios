require('dotenv').config();
const bcrypt = require('bcryptjs');
const { query } = require('../src/db');

async function migrate() {
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

migrate()
  .then(() => {
    // eslint-disable-next-line no-console
    console.log('Migração concluída com sucesso');
    process.exit(0);
  })
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error('Falha na migração:', err);
    process.exit(1);
  });
