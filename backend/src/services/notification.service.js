const nodemailer = require('nodemailer');
const { query } = require('../db');

let smtpTransporter = null;

function getSmtpTransporter() {
  if (smtpTransporter) return smtpTransporter;
  smtpTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT || 587) === 465,
    auth:
      process.env.SMTP_USER && process.env.SMTP_PASS
        ? {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
          }
        : undefined,
  });
  return smtpTransporter;
}

async function createNotification({ userId, ministryId, channel, template, event, payload, status = 'ENVIADO', sentAt = true }) {
  const { rows } = await query(
    `INSERT INTO notification_logs (user_id, ministry_id, channel, template, event, payload, status, sent_at)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, CASE WHEN $8 THEN now() ELSE NULL END)
     RETURNING id`,
    [userId, ministryId, channel, template, event, JSON.stringify(payload || {}), status, sentAt],
  );
  return rows[0]?.id;
}

async function getUserForEmail(userId) {
  const { rows } = await query(`SELECT id, name, email FROM users WHERE id = $1 LIMIT 1`, [userId]);
  return rows[0] || null;
}

function buildEmailMessage({ template, event, payload, user }) {
  const serviceLabel = payload?.serviceTitle ? ` - ${payload.serviceTitle}` : '';
  const dateLabel = payload?.serviceDate ? ` (${payload.serviceDate})` : '';
  return {
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: user.email,
    subject: `[Voluntario Hub] ${template || event || 'Notificacao'}${serviceLabel}`,
    text: `Ola ${user.name || ''},\n\nVoce recebeu uma notificacao do Voluntario Hub.\nEvento: ${event || '-'}\nTemplate: ${template || '-'}${dateLabel}\n\nDetalhes:\n${JSON.stringify(payload || {}, null, 2)}\n`,
  };
}

async function sendEmailNotification({ userId, ministryId, template, event, payload }) {
  try {
    if (!process.env.SMTP_HOST || !process.env.SMTP_PORT || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
      throw new Error('SMTP nao configurado. Defina SMTP_HOST, SMTP_PORT, SMTP_USER e SMTP_PASS');
    }
    const user = await getUserForEmail(userId);
    if (!user?.email) {
      throw new Error('Usuario sem email para envio');
    }
    const transporter = getSmtpTransporter();
    const message = buildEmailMessage({ template, event, payload, user });
    await transporter.sendMail(message);
    await createNotification({ userId, ministryId, channel: 'EMAIL', template, event, payload, status: 'ENVIADO', sentAt: true });
  } catch (error) {
    await createNotification({
      userId,
      ministryId,
      channel: 'EMAIL',
      template,
      event,
      payload: {
        ...(payload || {}),
        error: error.message,
      },
      status: 'FALHA',
      sentAt: false,
    });
  }
}

async function notifyUserMultiChannel({ userId, ministryId, template, event, payload, channels = ['WHATSAPP', 'EMAIL', 'PUSH'] }) {
  for (const channel of channels) {
    if (channel === 'EMAIL') {
      await sendEmailNotification({ userId, ministryId, template, event, payload });
      continue;
    }
    await createNotification({ userId, ministryId, channel, template, event, payload, status: 'ENVIADO', sentAt: true });
  }
}

module.exports = { createNotification, notifyUserMultiChannel };
