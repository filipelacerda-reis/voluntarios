const cron = require('node-cron');
const { query } = require('../db');
const { notifyUserMultiChannel } = require('../services/notification.service');

const REMINDER_CRON = '0 9 * * *';
const REMINDER_TZ = 'America/Sao_Paulo';

async function runPendingConfirmationRemindersJob() {
  const { rows } = await query(
    `SELECT sa.id AS assignment_id, sa.user_id, sa.team_role,
            s.id AS service_id, s.title, s.service_date, s.ministry_id
     FROM service_assignments sa
     JOIN services s ON s.id = sa.service_id
     WHERE sa.status = 'PENDENTE'
       AND s.service_date >= current_date
     ORDER BY s.service_date ASC
     LIMIT 1000`,
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
        source: 'cron_09h_brasilia',
      },
    });
    sent += 1;
  }

  return { processed: rows.length, remindersSent: sent };
}

function startRemindersJob() {
  cron.schedule(
    REMINDER_CRON,
    async () => {
      try {
        const result = await runPendingConfirmationRemindersJob();
        // eslint-disable-next-line no-console
        console.log(`[job:reminders] processed=${result.processed} remindersSent=${result.remindersSent}`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('[job:reminders] failed:', err);
      }
    },
    { timezone: REMINDER_TZ },
  );

  // eslint-disable-next-line no-console
  console.log(`[job:reminders] scheduled '${REMINDER_CRON}' timezone='${REMINDER_TZ}'`);
}

module.exports = { startRemindersJob, runPendingConfirmationRemindersJob };
