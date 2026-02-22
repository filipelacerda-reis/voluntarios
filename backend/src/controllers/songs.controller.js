const { query } = require('../db');
const { parseTags, hasRole } = require('../utils/parsers');
const { ROLE_ADMIN, ROLE_LEADER, ROLE_VOL } = require('../constants/roles');
const { getLouvorMinistryId, getScopedMinistryIds, canManageMinistry } = require('../services/access.service');
const { writeAudit } = require('../services/audit.service');

async function listSongs(req, res) {
  const louvorId = await getLouvorMinistryId();
  const canAccessRepertoire = req.user.role === ROLE_ADMIN || (louvorId && getScopedMinistryIds(req).includes(louvorId));
  if (!canAccessRepertoire) {
    return res.status(403).json({ message: 'Repertório disponível apenas para usuários do ministério LOUVOR' });
  }

  const q = String(req.query.q || '').trim();
  const args = [];
  const conditions = [];

  if (hasRole(req.user, [ROLE_LEADER, ROLE_VOL]) && louvorId) {
    args.push(louvorId);
    conditions.push('s.ministry_id = $1');
  }

  if (q) {
    args.push(`%${q}%`);
    const idx = args.length;
    conditions.push(`(s.title ILIKE $${idx} OR s.key ILIKE $${idx} OR array_to_string(s.tags, ',') ILIKE $${idx})`);
  }

  const where = conditions.length ? ` WHERE ${conditions.join(' AND ')} ` : '';

  const { rows } = await query(
    `SELECT s.id, s.title, s.key, s.bpm, s.web_link, s.tags, s.ministry_id, m.name AS ministry_name
     FROM songs s
     LEFT JOIN ministries m ON m.id = s.ministry_id
     ${where}
     ORDER BY s.title`,
    args,
  );

  res.json(rows);
}

async function createSong(req, res) {
  const louvorId = await getLouvorMinistryId();
  const canAccessRepertoire = req.user.role === ROLE_ADMIN || (louvorId && getScopedMinistryIds(req).includes(louvorId));
  if (!canAccessRepertoire || !louvorId) {
    return res.status(403).json({ message: 'Somente membros do ministério LOUVOR podem gerenciar repertório' });
  }

  const { title, key, bpm = null, webLink = '', tags = [] } = req.body;
  if (!title || !key) return res.status(400).json({ message: 'Título e tom são obrigatórios' });

  const targetMinistryId = louvorId;
  const parsedTags = parseTags(tags);

  const { rows } = await query(
    `INSERT INTO songs (title, key, bpm, web_link, tags, ministry_id, created_by)
     VALUES ($1, $2, $3, $4, $5::text[], $6, $7)
     RETURNING id, title, key, bpm, web_link, tags, ministry_id`,
    [title.trim(), key.trim(), bpm ? Number(bpm) : null, webLink.trim(), parsedTags, targetMinistryId, req.user.sub],
  );
  await writeAudit(req.user.sub, 'CREATE', 'SONG', rows[0].id, rows[0].ministry_id, {
    title: rows[0].title,
    key: rows[0].key,
  });
  res.status(201).json(rows[0]);
}

async function deleteSong(req, res) {
  const louvorId = await getLouvorMinistryId();
  const canAccessRepertoire = req.user.role === ROLE_ADMIN || (louvorId && getScopedMinistryIds(req).includes(louvorId));
  if (!canAccessRepertoire) {
    return res.status(403).json({ message: 'Somente membros do ministério LOUVOR podem gerenciar repertório' });
  }

  const { rows } = await query('SELECT ministry_id FROM songs WHERE id = $1', [req.params.id]);
  const song = rows[0];
  if (!song) return res.status(404).json({ message: 'Música não encontrada' });

  if (!canManageMinistry(req, song.ministry_id)) {
    return res.status(403).json({ message: 'Sem permissão para remover esta música' });
  }

  await query('DELETE FROM songs WHERE id = $1', [req.params.id]);
  await writeAudit(req.user.sub, 'DELETE', 'SONG', req.params.id, song.ministry_id, {});
  res.status(204).send();
}

module.exports = { listSongs, createSong, deleteSong };
