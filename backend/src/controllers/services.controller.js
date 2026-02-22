const { query } = require('../db');
const { parseTags, hasRole } = require('../utils/parsers');
const { ROLE_ADMIN, ROLE_LEADER, ROLE_VOL } = require('../constants/roles');
const { getScopedMinistryIds, canManageMinistry, hasMinistryAccess } = require('../services/access.service');
const { writeAudit } = require('../services/audit.service');
const { getServiceWithMinistry, createAssignmentWithRules } = require('../services/assignment.service');

async function listServices(req, res) {
  const from = req.query.from || '1900-01-01';
  const to = req.query.to || '2999-12-31';
  const q = String(req.query.q || '').trim();
  const serviceDate = String(req.query.serviceDate || '').trim();

  const args = [from, to];
  const conditions = ['s.service_date BETWEEN $1 AND $2'];

  if (serviceDate) {
    args.push(serviceDate);
    conditions.push(`s.service_date = $${args.length}`);
  }

  if (q) {
    args.push(`%${q}%`);
    const idx = args.length;
    conditions.push(`(s.title ILIKE $${idx} OR to_char(s.service_date, 'DD-MM-YYYY') ILIKE $${idx})`);
  }

  if (hasRole(req.user, [ROLE_LEADER, ROLE_VOL])) {
    const scoped = getScopedMinistryIds(req);
    if (!scoped.length) return res.json([]);
    args.push(scoped);
    conditions.push(`s.ministry_id = ANY($${args.length}::uuid[])`);
  }

  const { rows: services } = await query(
    `SELECT s.id, s.service_date, s.service_time, s.title, s.notes, s.tags, s.ministry_id, m.name AS ministry_name
     FROM services s
     LEFT JOIN ministries m ON m.id = s.ministry_id
     WHERE ${conditions.join(' AND ')}
     ORDER BY s.service_date ASC, s.service_time ASC NULLS LAST`,
    args,
  );

  const ids = services.map((s) => s.id);
  if (!ids.length) return res.json([]);

  const { rows: setlist } = await query(
    `SELECT ss.service_id, ss.id, ss.position, ss.note, so.title AS song_title, so.key AS song_key
     FROM service_setlist ss
     JOIN songs so ON so.id = ss.song_id
     WHERE ss.service_id = ANY($1::uuid[])
     ORDER BY ss.service_id, ss.position ASC`,
    [ids],
  );

  const { rows: assignments } = await query(
    `SELECT sa.id, sa.service_id, sa.user_id, sa.team_role, sa.status, u.name AS user_name,
            coalesce(ar.status, 'SEM_APROVACAO') AS approval_status,
            ar.decision_note
     FROM service_assignments sa
     JOIN users u ON u.id = sa.user_id
     LEFT JOIN approval_requests ar ON ar.assignment_id = sa.id
     WHERE sa.service_id = ANY($1::uuid[])
     ORDER BY sa.service_id, sa.team_role`,
    [ids],
  );

  const response = services.map((service) => ({
    ...service,
    setlist: setlist.filter((item) => item.service_id === service.id),
    assignments: assignments.filter((item) => item.service_id === service.id),
  }));

  res.json(response);
}

async function createService(req, res) {
  const { serviceDate, serviceTime = null, title, notes = '', tags = [], ministryId = null } = req.body;
  if (!serviceDate || !title) return res.status(400).json({ message: 'Data e título são obrigatórios' });

  const scoped = getScopedMinistryIds(req);
  const targetMinistryId = req.user.role === ROLE_LEADER ? scoped[0] || null : ministryId || req.user.ministryId || null;
  const parsedTags = parseTags(tags);

  const { rows } = await query(
    `INSERT INTO services (service_date, service_time, title, notes, tags, ministry_id, created_by)
     VALUES ($1, $2, $3, $4, $5::text[], $6, $7)
     RETURNING id, service_date, service_time, title, notes, tags, ministry_id`,
    [serviceDate, serviceTime || null, title.trim(), notes.trim(), parsedTags, targetMinistryId, req.user.sub],
  );
  await writeAudit(req.user.sub, 'CREATE', 'SERVICE', rows[0].id, rows[0].ministry_id, {
    serviceDate: rows[0].service_date,
    title: rows[0].title,
  });
  res.status(201).json(rows[0]);
}

async function updateService(req, res) {
  const { id } = req.params;
  const { serviceDate, serviceTime, title, notes, tags } = req.body;

  const { rows: existingRows } = await query(
    `SELECT id, service_date, service_time, title, notes, tags, ministry_id
     FROM services WHERE id = $1 LIMIT 1`,
    [id],
  );
  const existing = existingRows[0];
  if (!existing) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, existing.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para editar este culto' });
  }

  const nextServiceDate = serviceDate || existing.service_date;
  const nextServiceTime = typeof serviceTime === 'undefined' ? existing.service_time : serviceTime || null;
  const nextTitle = (title || existing.title || '').trim();
  const nextNotes = typeof notes === 'undefined' ? existing.notes : String(notes || '').trim();
  const nextTags = typeof tags === 'undefined' ? existing.tags : parseTags(tags);

  if (!nextServiceDate || !nextTitle) {
    return res.status(400).json({ message: 'Data e título do culto são obrigatórios' });
  }

  const { rows } = await query(
    `UPDATE services
     SET service_date = $1,
         service_time = $2,
         title = $3,
         notes = $4,
         tags = $5::text[]
     WHERE id = $6
     RETURNING id, service_date, service_time, title, notes, tags, ministry_id`,
    [nextServiceDate, nextServiceTime, nextTitle, nextNotes, nextTags, id],
  );

  await writeAudit(req.user.sub, 'UPDATE', 'SERVICE', id, existing.ministry_id, {
    before: {
      serviceDate: existing.service_date,
      serviceTime: existing.service_time,
      title: existing.title,
      notes: existing.notes,
      tags: existing.tags,
    },
    after: {
      serviceDate: rows[0].service_date,
      serviceTime: rows[0].service_time,
      title: rows[0].title,
      notes: rows[0].notes,
      tags: rows[0].tags,
    },
  });

  res.json(rows[0]);
}

async function deleteService(req, res) {
  const { id } = req.params;
  const { rows } = await query(
    `SELECT id, service_date, service_time, title, ministry_id
     FROM services WHERE id = $1 LIMIT 1`,
    [id],
  );
  const service = rows[0];
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para excluir este culto' });
  }

  await query('DELETE FROM services WHERE id = $1', [id]);
  await writeAudit(req.user.sub, 'DELETE', 'SERVICE', id, service.ministry_id, {
    serviceDate: service.service_date,
    serviceTime: service.service_time,
    title: service.title,
  });

  res.status(204).send();
}

async function getServiceDetails(req, res) {
  const service = await getServiceWithMinistry(req.params.id);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });

  if (hasRole(req.user, [ROLE_LEADER, ROLE_VOL]) && !hasMinistryAccess(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const [setlistRows, assignmentRows] = await Promise.all([
    query(
      `SELECT ss.id, ss.position, ss.note, ss.song_id, so.title AS song_title, so.key AS song_key
       FROM service_setlist ss
       JOIN songs so ON so.id = ss.song_id
       WHERE ss.service_id = $1
       ORDER BY ss.position ASC`,
      [req.params.id],
    ),
    query(
      `SELECT sa.id, sa.user_id, sa.team_role, sa.status, u.name AS user_name,
              coalesce(ar.status, 'SEM_APROVACAO') AS approval_status,
              ar.decision_note
       FROM service_assignments sa
       JOIN users u ON u.id = sa.user_id
       LEFT JOIN approval_requests ar ON ar.assignment_id = sa.id
       WHERE sa.service_id = $1
       ORDER BY sa.team_role`,
      [req.params.id],
    ),
  ]);

  res.json({ ...service, setlist: setlistRows.rows, assignments: assignmentRows.rows });
}

async function addSetlist(req, res) {
  const { id: serviceId } = req.params;
  const { songId, position, note = '' } = req.body;

  if (!songId || !position) {
    return res.status(400).json({ message: 'Música e posição são obrigatórias' });
  }

  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const { rows } = await query(
    `INSERT INTO service_setlist (service_id, song_id, position, note)
     VALUES ($1, $2, $3, $4)
     RETURNING id, service_id, song_id, position, note`,
    [serviceId, songId, Number(position), note.trim()],
  );
  await writeAudit(req.user.sub, 'ADD_SETLIST_ITEM', 'SERVICE', serviceId, service.ministry_id, rows[0]);
  res.status(201).json(rows[0]);
}

async function updateSetlist(req, res) {
  const { serviceId, itemId } = req.params;
  const { position, note } = req.body;

  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const { rows: existingRows } = await query('SELECT id, position, note FROM service_setlist WHERE id = $1 AND service_id = $2 LIMIT 1', [
    itemId,
    serviceId,
  ]);
  const existing = existingRows[0];
  if (!existing) return res.status(404).json({ message: 'Item de repertório não encontrado' });

  const nextPosition = Number(position || existing.position);
  const nextNote = typeof note === 'undefined' ? existing.note : String(note || '').trim();
  if (!Number.isInteger(nextPosition) || nextPosition < 1) {
    return res.status(400).json({ message: 'Posição inválida' });
  }

  if (nextPosition !== existing.position) {
    const { rows: occupiedRows } = await query('SELECT id FROM service_setlist WHERE service_id = $1 AND position = $2 AND id <> $3 LIMIT 1', [
      serviceId,
      nextPosition,
      itemId,
    ]);
    if (occupiedRows[0]) {
      return res.status(409).json({ message: 'Já existe música nesta posição do repertório' });
    }
  }

  const { rows } = await query(
    `UPDATE service_setlist
     SET position = $1, note = $2
     WHERE id = $3
     RETURNING id, service_id, song_id, position, note`,
    [nextPosition, nextNote, itemId],
  );

  await writeAudit(req.user.sub, 'UPDATE_SETLIST_ITEM', 'SERVICE', serviceId, service.ministry_id, {
    itemId,
    before: { position: existing.position, note: existing.note },
    after: { position: rows[0].position, note: rows[0].note },
  });

  res.json(rows[0]);
}

async function deleteSetlist(req, res) {
  const { serviceId, itemId } = req.params;
  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const { rows } = await query('SELECT id, position, note FROM service_setlist WHERE id = $1 AND service_id = $2 LIMIT 1', [itemId, serviceId]);
  const item = rows[0];
  if (!item) return res.status(404).json({ message: 'Item de repertório não encontrado' });

  await query('DELETE FROM service_setlist WHERE id = $1', [itemId]);
  await writeAudit(req.user.sub, 'DELETE_SETLIST_ITEM', 'SERVICE', serviceId, service.ministry_id, {
    itemId,
    position: item.position,
    note: item.note,
  });
  res.status(204).send();
}

async function assignUser(req, res) {
  const { id: serviceId } = req.params;
  const { userId, teamRole } = req.body;

  if (!userId || !teamRole) {
    return res.status(400).json({ message: 'Voluntário e função são obrigatórios' });
  }

  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });
  if (!canManageMinistry(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para este culto' });
  }

  const result = await createAssignmentWithRules({ serviceId, userId, teamRole, actorUserId: req.user.sub });
  if (result.error) return res.status(result.error.code).json({ message: result.error.message });

  res.status(201).json({ ...result.assignment, approvalStatus: result.approvalStatus });
}

async function selfAssign(req, res) {
  const { id: serviceId } = req.params;
  const { teamRole } = req.body;

  if (!teamRole) return res.status(400).json({ message: 'Função na escala é obrigatória' });

  const service = await getServiceWithMinistry(serviceId);
  if (!service) return res.status(404).json({ message: 'Culto não encontrado' });

  if (service.ministry_id && !hasMinistryAccess(req, service.ministry_id)) {
    return res.status(403).json({ message: 'Você não pode se inscrever em culto de outro ministério' });
  }

  const result = await createAssignmentWithRules({ serviceId, userId: req.user.sub, teamRole, actorUserId: req.user.sub });
  if (result.error) return res.status(result.error.code).json({ message: result.error.message });

  res.status(201).json({ ...result.assignment, approvalStatus: result.approvalStatus });
}

module.exports = {
  listServices,
  createService,
  updateService,
  deleteService,
  getServiceDetails,
  addSetlist,
  updateSetlist,
  deleteSetlist,
  assignUser,
  selfAssign,
};
