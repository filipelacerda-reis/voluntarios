const bcrypt = require('bcryptjs');
const { query } = require('../db');
const { writeAudit } = require('../services/audit.service');
const { getScopedMinistryIds } = require('../services/access.service');
const { ROLE_ADMIN, ROLE_LEADER, ROLE_VOL } = require('../constants/roles');

async function listUsers(req, res) {
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
}

async function createUser(req, res) {
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
    const { rows: checkRows } = await query('SELECT id FROM ministries WHERE id = ANY($1::uuid[])', [dedupMinistryIds]);
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
}

async function updateUserMinistries(req, res) {
  const { id } = req.params;
  const inputIds = Array.isArray(req.body.ministryIds) ? req.body.ministryIds.filter(Boolean) : [];
  const ministryIds = Array.from(new Set(inputIds));

  const { rows: targetRows } = await query('SELECT id, role, name, email FROM users WHERE id = $1 LIMIT 1', [id]);
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
}

async function setUserActive(req, res) {
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
  await writeAudit(req.user.sub, 'UPDATE_ACTIVE', 'USER', rows[0].id, rows[0].ministry_id, { active: rows[0].active });
  res.json(rows[0]);
}

module.exports = { listUsers, createUser, updateUserMinistries, setUserActive };
