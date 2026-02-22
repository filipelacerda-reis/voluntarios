const bcrypt = require('bcryptjs');
const { query } = require('../db');
const { signToken } = require('../auth');
const { getLouvorMinistryId } = require('../services/access.service');
const { writeAudit } = require('../services/audit.service');
const { ROLE_ADMIN } = require('../constants/roles');

async function login(req, res) {
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
}

async function me(req, res) {
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
}

async function changePassword(req, res) {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Senha atual e nova senha são obrigatórias' });
  }
  if (String(newPassword).length < 6) {
    return res.status(400).json({ message: 'A nova senha deve ter pelo menos 6 caracteres' });
  }

  const { rows } = await query('SELECT id, password_hash, ministry_id FROM users WHERE id = $1 LIMIT 1', [req.user.sub]);
  const user = rows[0];
  if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });

  const ok = await bcrypt.compare(String(currentPassword), user.password_hash);
  if (!ok) return res.status(401).json({ message: 'Senha atual inválida' });

  const nextHash = await bcrypt.hash(String(newPassword), 10);
  await query('UPDATE users SET password_hash = $1 WHERE id = $2', [nextHash, user.id]);

  await writeAudit(req.user.sub, 'CHANGE_PASSWORD', 'USER', user.id, user.ministry_id, {});
  return res.status(200).json({ message: 'Senha atualizada com sucesso' });
}

module.exports = { login, me, changePassword };
