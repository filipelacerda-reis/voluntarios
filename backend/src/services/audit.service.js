const { query } = require('../db');

async function writeAudit(actorUserId, action, entity, entityId, ministryId, payload = {}) {
  await query(
    `INSERT INTO audit_logs (actor_user_id, action, entity, entity_id, ministry_id, payload)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
    [actorUserId, action, entity, entityId, ministryId, JSON.stringify(payload)],
  );
}

module.exports = { writeAudit };
