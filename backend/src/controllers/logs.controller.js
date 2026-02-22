const { query } = require('../db');
const { getScopedMinistryIds } = require('../services/access.service');

async function listAuditLogs(req, res) {
  const page = Math.max(1, Number.parseInt(String(req.query.page || '1'), 10) || 1);
  const limit = Math.min(200, Math.max(1, Number.parseInt(String(req.query.limit || '300'), 10) || 300));
  const offset = (page - 1) * limit;
  const args = [];
  let where = '';
  if (req.user.role === 'LIDER_MINISTERIO') {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json({ items: [], page, limit, total: 0, hasMore: false });
    args.push(scoped);
    where = ' WHERE al.ministry_id = ANY($1::uuid[]) ';
  }

  const { rows: countRows } = await query(
    `SELECT COUNT(*)::int AS total
     FROM audit_logs al
     ${where}`,
    args,
  );
  const total = Number(countRows[0]?.total || 0);

  const { rows } = await query(
    `SELECT al.id, al.action, al.entity, al.entity_id, al.ministry_id, al.payload, al.created_at, u.name AS actor_name
     FROM audit_logs al
     LEFT JOIN users u ON u.id = al.actor_user_id
     ${where}
     ORDER BY al.created_at DESC
     LIMIT $${args.length + 1}
     OFFSET $${args.length + 2}`,
    [...args, limit, offset],
  );

  res.json({
    items: rows,
    page,
    limit,
    total,
    hasMore: offset + rows.length < total,
  });
}

module.exports = { listAuditLogs };
