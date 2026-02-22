const { query } = require('../db');
const { isUuid } = require('../utils/parsers');
const { canManageMinistry, getScopedMinistryIds } = require('../services/access.service');
const { writeAudit } = require('../services/audit.service');
const { notifyUserMultiChannel } = require('../services/notification.service');

async function createSwapRequest(req, res) {
  if (!isUuid(req.params.id)) {
    return res.status(400).json({ message: 'ID de escala inválido' });
  }

  const { reason = '', requestedToUserId = null } = req.body;
  if (!String(reason).trim()) {
    return res.status(400).json({ message: 'Motivo da troca é obrigatório' });
  }

  const { rows: assignmentRows } = await query(
    `SELECT sa.id, sa.user_id, sa.status, sa.team_role, s.id AS service_id, s.title, s.service_date, s.ministry_id
     FROM service_assignments sa
     JOIN services s ON s.id = sa.service_id
     WHERE sa.id = $1
     LIMIT 1`,
    [req.params.id],
  );
  const assignment = assignmentRows[0];
  if (!assignment) return res.status(404).json({ message: 'Escala não encontrada' });
  if (assignment.user_id !== req.user.sub) {
    return res.status(403).json({ message: 'Você só pode solicitar troca da sua própria escala' });
  }
  if (assignment.status === 'RECUSADO') {
    return res.status(409).json({ message: 'Escala já recusada, troca não é necessária' });
  }

  const { rows: pendingRows } = await query(
    `SELECT id
     FROM assignment_swap_requests
     WHERE assignment_id = $1
       AND requester_user_id = $2
       AND status = 'PENDENTE'
     LIMIT 1`,
    [assignment.id, req.user.sub],
  );
  if (pendingRows[0]) {
    return res.status(409).json({ message: 'Já existe uma solicitação de troca pendente para esta escala' });
  }

  const requestedTo = requestedToUserId && isUuid(requestedToUserId) ? requestedToUserId : null;
  const { rows } = await query(
    `INSERT INTO assignment_swap_requests (assignment_id, requester_user_id, requested_to_user_id, reason, status)
     VALUES ($1, $2, $3, $4, 'PENDENTE')
     RETURNING id, assignment_id, requester_user_id, requested_to_user_id, reason, status, created_at`,
    [assignment.id, req.user.sub, requestedTo, String(reason).trim()],
  );

  const { rows: leaderRows } = await query(
    `SELECT id
     FROM users
     WHERE role = 'LIDER_MINISTERIO'
       AND active = true
       AND ministry_id IS NOT DISTINCT FROM $1
     ORDER BY created_at ASC
     LIMIT 1`,
    [assignment.ministry_id],
  );

  if (leaderRows[0]?.id) {
    await notifyUserMultiChannel({
      userId: leaderRows[0].id,
      ministryId: assignment.ministry_id,
      template: 'SOLICITACAO_TROCA_ESCALA',
      event: 'SWAP_REQUEST_CREATED',
      payload: {
        assignmentId: assignment.id,
        serviceId: assignment.service_id,
        serviceTitle: assignment.title,
        serviceDate: assignment.service_date,
        teamRole: assignment.team_role,
        requesterUserId: req.user.sub,
        reason: String(reason).trim(),
      },
    });
  }

  await writeAudit(req.user.sub, 'REQUEST_SWAP', 'ASSIGNMENT', assignment.id, assignment.ministry_id, {
    reason: String(reason).trim(),
    requestedToUserId: requestedTo,
  });

  res.status(201).json(rows[0]);
}

async function listSwapRequests(req, res) {
  const status = String(req.query.status || 'PENDENTE').toUpperCase();
  const allowedStatus = ['PENDENTE', 'APROVADA', 'REJEITADA', 'CANCELADA'];
  if (!allowedStatus.includes(status)) {
    return res.status(400).json({ message: 'Status inválido' });
  }

  let where = ' WHERE sr.status = $1 ';
  const args = [status];

  if (req.user.role === 'VOLUNTARIO') {
    args.push(req.user.sub);
    where += ` AND sr.requester_user_id = $${args.length} `;
  } else if (req.user.role === 'LIDER_MINISTERIO') {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where += ` AND s.ministry_id = ANY($${args.length}::uuid[]) `;
  }

  const { rows } = await query(
    `SELECT sr.id, sr.assignment_id, sr.reason, sr.status, sr.decision_note, sr.created_at, sr.decided_at,
            sr.requester_user_id, ru.name AS requester_name,
            sr.requested_to_user_id, tu.name AS requested_to_name,
            sr.approver_user_id, au.name AS approver_name,
            s.id AS service_id, s.title AS service_title, s.service_date, s.ministry_id,
            sa.team_role
     FROM assignment_swap_requests sr
     JOIN service_assignments sa ON sa.id = sr.assignment_id
     JOIN services s ON s.id = sa.service_id
     JOIN users ru ON ru.id = sr.requester_user_id
     LEFT JOIN users tu ON tu.id = sr.requested_to_user_id
     LEFT JOIN users au ON au.id = sr.approver_user_id
     ${where}
     ORDER BY sr.created_at DESC
     LIMIT 300`,
    args,
  );

  res.json(rows);
}

async function decideSwapRequest(req, res) {
  if (!isUuid(req.params.id)) {
    return res.status(400).json({ message: 'ID de solicitação inválido' });
  }

  const { decision, note = '' } = req.body;
  if (!['APROVAR', 'REJEITAR'].includes(decision)) {
    return res.status(400).json({ message: 'Decisão inválida' });
  }

  const { rows: requestRows } = await query(
    `SELECT sr.id, sr.status, sr.assignment_id, sr.requester_user_id, sa.team_role, sa.service_id, s.title, s.service_date, s.ministry_id
     FROM assignment_swap_requests sr
     JOIN service_assignments sa ON sa.id = sr.assignment_id
     JOIN services s ON s.id = sa.service_id
     WHERE sr.id = $1
     LIMIT 1`,
    [req.params.id],
  );
  const swap = requestRows[0];
  if (!swap) return res.status(404).json({ message: 'Solicitação de troca não encontrada' });
  if (!canManageMinistry(req, swap.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para decidir esta solicitação' });
  }
  if (swap.status !== 'PENDENTE') {
    return res.status(409).json({ message: 'Solicitação já foi decidida' });
  }

  const finalStatus = decision === 'APROVAR' ? 'APROVADA' : 'REJEITADA';
  await query(
    `UPDATE assignment_swap_requests
     SET status = $1,
         approver_user_id = $2,
         decision_note = $3,
         decided_at = now()
     WHERE id = $4`,
    [finalStatus, req.user.sub, String(note || '').trim(), swap.id],
  );

  if (decision === 'APROVAR') {
    await query(`UPDATE service_assignments SET status = 'RECUSADO' WHERE id = $1`, [swap.assignment_id]);
    await query(
      `UPDATE approval_requests
       SET status = 'REJEITADO',
           decision_note = coalesce(nullif(decision_note, ''), 'Escala liberada por troca aprovada'),
           approver_user_id = $1,
           decided_at = now()
       WHERE assignment_id = $2`,
      [req.user.sub, swap.assignment_id],
    );
  }

  await notifyUserMultiChannel({
    userId: swap.requester_user_id,
    ministryId: swap.ministry_id,
    template: 'DECISAO_TROCA_ESCALA',
    event: 'SWAP_REQUEST_DECISION',
    payload: { decision: finalStatus, note: String(note || '').trim(), serviceTitle: swap.title, serviceDate: swap.service_date, teamRole: swap.team_role },
  });

  await writeAudit(req.user.sub, 'SWAP_DECISION', 'ASSIGNMENT', swap.assignment_id, swap.ministry_id, {
    swapRequestId: swap.id,
    decision: finalStatus,
    note: String(note || '').trim(),
  });

  res.json({ id: swap.id, status: finalStatus });
}

module.exports = { createSwapRequest, listSwapRequests, decideSwapRequest };
