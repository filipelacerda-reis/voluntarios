const { query } = require('../db');
const { ROLE_ADMIN, ROLE_LEADER } = require('../constants/roles');

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

module.exports = { canManageMinistry, getScopedMinistryIds, hasMinistryAccess, getLouvorMinistryId };
