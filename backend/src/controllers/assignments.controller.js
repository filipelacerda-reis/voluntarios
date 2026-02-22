const { query } = require('../db');
const { isUuid } = require('../utils/parsers');
const { ROLE_VOL } = require('../constants/roles');
const { canManageMinistry } = require('../services/access.service');
const { notifyUserMultiChannel } = require('../services/notification.service');
const { writeAudit } = require('../services/audit.service');

async function updateAssignmentStatus(req, res) {
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
    payload: { status, serviceTitle: assignment.title, serviceDate: assignment.service_date, teamRole: assignment.team_role },
  });

  await writeAudit(req.user.sub, 'UPDATE_ASSIGNMENT_STATUS', 'ASSIGNMENT', rows[0].id, assignment.ministry_id, {
    status: rows[0].status,
  });

  res.json(rows[0]);
}

module.exports = { updateAssignmentStatus };
