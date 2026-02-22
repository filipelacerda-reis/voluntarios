const { query } = require('../db');
const { asDateOnly, dateToISO, parseTags } = require('../utils/parsers');
const { ROLE_LEADER } = require('../constants/roles');
const { getServiceWithMinistry, createAssignmentWithRules } = require('../services/assignment.service');
const { canManageMinistry, getScopedMinistryIds } = require('../services/access.service');
const { writeAudit } = require('../services/audit.service');

async function repeatService(req, res) {
  const { sourceServiceId, startDate, endDate, intervalDays = 7, copySetlist = true, copyAssignments = true, titlePrefix = '' } = req.body;

  if (!sourceServiceId || !startDate || !endDate) {
    return res.status(400).json({ message: 'sourceServiceId, startDate e endDate são obrigatórios' });
  }

  const source = await getServiceWithMinistry(sourceServiceId);
  if (!source) return res.status(404).json({ message: 'Culto de origem não encontrado' });
  if (!canManageMinistry(req, source.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para repetir este culto' });
  }

  const { rows: sourceSetlist } = await query('SELECT song_id, position, note FROM service_setlist WHERE service_id = $1 ORDER BY position', [
    sourceServiceId,
  ]);
  const { rows: sourceAssignments } = await query('SELECT user_id, team_role FROM service_assignments WHERE service_id = $1 ORDER BY team_role', [
    sourceServiceId,
  ]);

  const start = asDateOnly(startDate);
  const end = asDateOnly(endDate);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) {
    return res.status(400).json({ message: 'Período inválido para repetição' });
  }

  const createdServices = [];
  const skipped = [];

  for (let dt = new Date(start); dt <= end; dt.setDate(dt.getDate() + Number(intervalDays))) {
    const serviceDate = dateToISO(dt);

    const { rows: existingRows } = await query(
      `SELECT id FROM services
       WHERE service_date = $1
         AND title = $2
         AND ministry_id IS NOT DISTINCT FROM $3
         AND service_time IS NOT DISTINCT FROM $4
       LIMIT 1`,
      [serviceDate, `${titlePrefix}${source.title}`.trim(), source.ministry_id, source.service_time],
    );

    if (existingRows[0]) {
      skipped.push({ date: serviceDate, reason: 'Culto já existe' });
      continue;
    }

    const { rows: insertedRows } = await query(
      `INSERT INTO services (service_date, service_time, title, notes, tags, ministry_id, created_by)
       VALUES ($1, $2, $3, $4, $5::text[], $6, $7)
       RETURNING id, service_date, service_time, title`,
      [
        serviceDate,
        source.service_time || null,
        `${titlePrefix}${source.title}`.trim(),
        source.notes || '',
        source.tags || [],
        source.ministry_id,
        req.user.sub,
      ],
    );

    const created = insertedRows[0];

    if (copySetlist) {
      for (const item of sourceSetlist) {
        await query(`INSERT INTO service_setlist (service_id, song_id, position, note) VALUES ($1, $2, $3, $4)`, [
          created.id,
          item.song_id,
          item.position,
          item.note || '',
        ]);
      }
    }

    const assignmentWarnings = [];
    if (copyAssignments) {
      for (const item of sourceAssignments) {
        const result = await createAssignmentWithRules({
          serviceId: created.id,
          userId: item.user_id,
          teamRole: item.team_role,
          actorUserId: req.user.sub,
        });

        if (result.error) assignmentWarnings.push({ userId: item.user_id, reason: result.error.message });
      }
    }

    createdServices.push({ id: created.id, serviceDate: created.service_date, title: created.title, assignmentWarnings });
  }

  await writeAudit(req.user.sub, 'REPEAT_SERVICE_PLAN', 'SERVICE', sourceServiceId, source.ministry_id, {
    startDate,
    endDate,
    intervalDays,
    createdCount: createdServices.length,
    skippedCount: skipped.length,
  });

  res.status(201).json({ createdServices, skipped });
}

async function bulkServices(req, res) {
  const { startDate, endDate, weekdays = [0], ministryId = null, notes = '', tags = [], timeSlots = [] } = req.body;

  if (!startDate || !endDate) {
    return res.status(400).json({ message: 'startDate e endDate são obrigatórios' });
  }

  const parsedWeekdays = Array.isArray(weekdays) ? weekdays.map((w) => Number(w)).filter((w) => w >= 0 && w <= 6) : [];
  if (!parsedWeekdays.length) {
    return res.status(400).json({ message: 'Informe ao menos um dia da semana válido (0-6)' });
  }

  const parsedSlots = Array.isArray(timeSlots)
    ? timeSlots
        .map((slot) => ({
          title: String(slot.title || '').trim(),
          serviceTime: String(slot.serviceTime || '').trim() || null,
          notes: String(slot.notes || notes || '').trim(),
        }))
        .filter((slot) => slot.title)
    : [];
  if (!parsedSlots.length) {
    return res.status(400).json({ message: 'Informe ao menos um turno/título de culto' });
  }

  const scoped = getScopedMinistryIds(req);
  const targetMinistryId = req.user.role === ROLE_LEADER ? scoped[0] || null : ministryId || req.user.ministryId || null;
  const parsedTags = parseTags(tags);

  const start = asDateOnly(startDate);
  const end = asDateOnly(endDate);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start > end) {
    return res.status(400).json({ message: 'Período inválido' });
  }

  const createdServices = [];
  const skipped = [];

  for (let dt = new Date(start); dt <= end; dt.setDate(dt.getDate() + 1)) {
    const weekday = dt.getDay();
    if (!parsedWeekdays.includes(weekday)) continue;

    const serviceDate = dateToISO(dt);

    for (const slot of parsedSlots) {
      const { rows: existingRows } = await query(
        `SELECT id FROM services
         WHERE service_date = $1
           AND title = $2
           AND ministry_id IS NOT DISTINCT FROM $3
           AND service_time IS NOT DISTINCT FROM $4
         LIMIT 1`,
        [serviceDate, slot.title, targetMinistryId, slot.serviceTime],
      );

      if (existingRows[0]) {
        skipped.push({ date: serviceDate, title: slot.title, reason: 'Culto já existe' });
        continue;
      }

      const { rows } = await query(
        `INSERT INTO services (service_date, service_time, title, notes, tags, ministry_id, created_by)
         VALUES ($1, $2, $3, $4, $5::text[], $6, $7)
         RETURNING id, service_date, service_time, title`,
        [serviceDate, slot.serviceTime, slot.title, slot.notes, parsedTags, targetMinistryId, req.user.sub],
      );

      createdServices.push(rows[0]);
    }
  }

  await writeAudit(req.user.sub, 'BULK_CREATE_SERVICES', 'SERVICE', null, targetMinistryId, {
    startDate,
    endDate,
    weekdays: parsedWeekdays,
    createdCount: createdServices.length,
    skippedCount: skipped.length,
  });

  res.status(201).json({ createdServices, skipped });
}

module.exports = { repeatService, bulkServices };
