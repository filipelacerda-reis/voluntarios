const { query } = require('../db');
const { getScopedMinistryIds, canManageMinistry } = require('../services/access.service');
const { writeAudit } = require('../services/audit.service');
const { notifyUserMultiChannel } = require('../services/notification.service');
const { isUuid } = require('../utils/parsers');

async function listPendingApprovals(req, res) {
  const args = [];
  let where = " WHERE ar.status = 'PENDENTE' ";
  if (req.user.role === 'LIDER_MINISTERIO') {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where += ' AND s.ministry_id = ANY($1::uuid[]) ';
  }

  const { rows } = await query(
    `SELECT ar.id, ar.assignment_id, ar.status, ar.created_at,
            sa.team_role, sa.user_id, u.name AS user_name,
            s.id AS service_id, s.title AS service_title, s.service_date,
            m.name AS ministry_name
     FROM approval_requests ar
     JOIN service_assignments sa ON sa.id = ar.assignment_id
     JOIN services s ON s.id = sa.service_id
     JOIN users u ON u.id = sa.user_id
     LEFT JOIN ministries m ON m.id = s.ministry_id
     ${where}
     ORDER BY ar.created_at ASC`,
    args,
  );

  res.json(rows);
}

async function decideApproval(req, res) {
  const { decision, note = '' } = req.body;
  if (!['APROVAR', 'REJEITAR'].includes(decision)) {
    return res.status(400).json({ message: 'Decisão inválida' });
  }
  if (!isUuid(req.params.assignmentId)) {
    return res.status(400).json({ message: 'ID de escala inválido' });
  }

  const { rows } = await query(
    `SELECT ar.id, ar.status, sa.id AS assignment_id, sa.user_id, sa.service_id, s.ministry_id, s.service_date, s.title
     FROM approval_requests ar
     JOIN service_assignments sa ON sa.id = ar.assignment_id
     JOIN services s ON s.id = sa.service_id
     WHERE sa.id = $1
     LIMIT 1`,
    [req.params.assignmentId],
  );

  const approval = rows[0];
  if (!approval) return res.status(404).json({ message: 'Solicitação de aprovação não encontrada' });
  if (!canManageMinistry(req, approval.ministry_id)) return res.status(403).json({ message: 'Sem permissão para aprovar esta escala' });

  const newApprovalStatus = decision === 'APROVAR' ? 'APROVADO' : 'REJEITADO';
  const newAssignmentStatus = decision === 'APROVAR' ? 'PENDENTE' : 'RECUSADO';

  await query(
    `UPDATE approval_requests
     SET status = $1, decision_note = $2, approver_user_id = $3, decided_at = now()
     WHERE id = $4`,
    [newApprovalStatus, note.trim(), req.user.sub, approval.id],
  );

  await query('UPDATE service_assignments SET status = $1 WHERE id = $2', [newAssignmentStatus, approval.assignment_id]);

  await notifyUserMultiChannel({
    userId: approval.user_id,
    ministryId: approval.ministry_id,
    template: 'DECISAO_APROVACAO_ESCALA',
    event: 'APPROVAL_DECISION',
    payload: { decision: newApprovalStatus, note: note.trim(), serviceTitle: approval.title, serviceDate: approval.service_date },
  });

  await writeAudit(req.user.sub, 'APPROVAL_DECISION', 'ASSIGNMENT', approval.assignment_id, approval.ministry_id, {
    decision: newApprovalStatus,
    note: note.trim(),
  });

  res.json({ assignmentId: approval.assignment_id, approvalStatus: newApprovalStatus, assignmentStatus: newAssignmentStatus });
}

module.exports = { listPendingApprovals, decideApproval };
