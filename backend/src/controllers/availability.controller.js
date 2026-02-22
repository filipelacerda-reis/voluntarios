const { query } = require('../db');
const { ROLE_ADMIN, ROLE_LEADER, ROLE_VOL } = require('../constants/roles');
const { getScopedMinistryIds, hasMinistryAccess } = require('../services/access.service');
const { writeAudit } = require('../services/audit.service');

async function listAvailability(req, res) {
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
}

async function createAvailability(req, res) {
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
}

async function deleteAvailability(req, res) {
  const { rows } = await query('SELECT id, user_id, ministry_id FROM availability_blocks WHERE id = $1 LIMIT 1', [req.params.id]);
  const block = rows[0];
  if (!block) return res.status(404).json({ message: 'Bloqueio não encontrado' });

  const isOwner = req.user.role === ROLE_VOL && req.user.sub === block.user_id;
  const canManage = req.user.role === ROLE_ADMIN || (req.user.role === ROLE_LEADER && hasMinistryAccess(req, block.ministry_id));
  if (!isOwner && !canManage) return res.status(403).json({ message: 'Sem permissão para remover bloqueio' });

  await query('DELETE FROM availability_blocks WHERE id = $1', [req.params.id]);
  await writeAudit(req.user.sub, 'DELETE', 'AVAILABILITY_BLOCK', block.id, block.ministry_id, {});
  res.status(204).send();
}

module.exports = { listAvailability, createAvailability, deleteAvailability };
