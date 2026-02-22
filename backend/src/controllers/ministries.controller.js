const { query } = require('../db');
const { writeAudit } = require('../services/audit.service');

async function listMinistries(_req, res) {
  const { rows } = await query('SELECT id, name, description FROM ministries ORDER BY name');
  res.json(rows);
}

async function createMinistry(req, res) {
  const { name, description = '' } = req.body;
  if (!name) return res.status(400).json({ message: 'Nome é obrigatório' });

  const { rows } = await query('INSERT INTO ministries (name, description) VALUES ($1, $2) RETURNING id, name, description', [
    name.trim(),
    description.trim(),
  ]);
  await writeAudit(req.user.sub, 'CREATE', 'MINISTRY', rows[0].id, rows[0].id, rows[0]);
  res.status(201).json(rows[0]);
}

module.exports = { listMinistries, createMinistry };
