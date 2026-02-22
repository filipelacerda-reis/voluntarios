const { query } = require('../db');
const { getScopedMinistryIds } = require('../services/access.service');
const { notifyUserMultiChannel } = require('../services/notification.service');
const { writeAudit } = require('../services/audit.service');

async function listNotifications(req, res) {
  const args = [];
  let where = '';

  if (req.user.role === 'VOLUNTARIO') {
    args.push(req.user.sub);
    where = ' WHERE nl.user_id = $1 ';
  } else if (req.user.role === 'LIDER_MINISTERIO') {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    where = ' WHERE nl.ministry_id = ANY($1::uuid[]) ';
  }

  const { rows } = await query(
    `SELECT nl.id, nl.channel, nl.template, nl.event, nl.status, nl.payload, nl.created_at, nl.sent_at, u.name AS user_name
     FROM notification_logs nl
     LEFT JOIN users u ON u.id = nl.user_id
     ${where}
     ORDER BY nl.created_at DESC
     LIMIT 300`,
    args,
  );

  res.json(rows);
}

async function testNotification(req, res) {
  const { channel = 'PUSH' } = req.body;
  if (!['WHATSAPP', 'EMAIL', 'PUSH'].includes(channel)) {
    return res.status(400).json({ message: 'Canal inválido' });
  }

  await notifyUserMultiChannel({
    userId: req.user.sub,
    ministryId: getScopedMinistryIds(req)[0] || req.user.ministryId || null,
    template: 'TESTE_CANAL',
    event: 'TEST_NOTIFICATION',
    payload: { initiatedBy: req.user.email, requestedChannel: channel },
    channels: [channel],
  });

  res.status(201).json({ message: `Notificação de teste registrada no canal ${channel}` });
}

async function sendPendingConfirmationReminders(req, res) {
  const args = [];
  let where = `
    WHERE sa.status = 'PENDENTE'
      AND s.service_date >= current_date
  `;

  if (req.user.role === 'LIDER_MINISTERIO') {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.status(201).json({ reminders: 0 });
    args.push(scoped);
    where += ` AND s.ministry_id = ANY($${args.length}::uuid[]) `;
  }

  const { rows } = await query(
    `SELECT sa.id AS assignment_id, sa.user_id, sa.team_role, s.id AS service_id, s.title, s.service_date, s.ministry_id
     FROM service_assignments sa
     JOIN services s ON s.id = sa.service_id
     ${where}
     ORDER BY s.service_date ASC
     LIMIT 500`,
    args,
  );

  let sent = 0;
  for (const row of rows) {
    await notifyUserMultiChannel({
      userId: row.user_id,
      ministryId: row.ministry_id,
      template: 'LEMBRETE_CONFIRMACAO_ESCALA',
      event: 'PENDING_CONFIRMATION_REMINDER',
      payload: {
        assignmentId: row.assignment_id,
        serviceId: row.service_id,
        serviceTitle: row.title,
        serviceDate: row.service_date,
        teamRole: row.team_role,
      },
    });
    sent += 1;
  }

  await writeAudit(req.user.sub, 'SEND_PENDING_CONFIRMATION_REMINDERS', 'ASSIGNMENT', null, getScopedMinistryIds(req)[0] || null, {
    reminders: sent,
  });

  res.status(201).json({ reminders: sent });
}

module.exports = { listNotifications, testNotification, sendPendingConfirmationReminders };
