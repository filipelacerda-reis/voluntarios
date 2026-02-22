const { query } = require('../db');
const { getScopedMinistryIds } = require('../services/access.service');

async function getDashboard(req, res) {
  const params = [];
  let whereUsers = '';
  let whereSongs = '';
  let whereServices = '';
  let whereAssignments = '';
  let whereApprovals = '';

  if (req.user.role !== 'ADMIN') {
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
       ${req.user.role === 'ADMIN' ? '' : 'WHERE ab.ministry_id = ANY($1::uuid[])'}`,
      req.user.role === 'ADMIN' ? [] : params,
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
}

module.exports = { getDashboard };
