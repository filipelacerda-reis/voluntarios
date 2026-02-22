const { query } = require('../db');

async function health(_req, res) {
  const ping = await query('SELECT now() AS now');
  res.json({ ok: true, dbTime: ping.rows[0].now });
}

module.exports = { health };
