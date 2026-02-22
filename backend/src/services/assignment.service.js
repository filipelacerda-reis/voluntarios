const { query } = require('../db');
const { notifyUserMultiChannel } = require('./notification.service');
const { writeAudit } = require('./audit.service');

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
  const approval = await createApprovalRequest({ assignmentId: assignment.id, ministryId: service.ministry_id, requestedBy: actorUserId });

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

module.exports = {
  getServiceWithMinistry,
  checkAvailabilityBlock,
  createApprovalRequest,
  createAssignmentWithRules,
};
