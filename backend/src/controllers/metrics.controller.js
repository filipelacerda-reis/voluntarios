const { query } = require('../db');

async function metrics(_req, res) {
  const [users, services, assignments] = await Promise.all([
    query('SELECT COUNT(*)::int AS total FROM users'),
    query('SELECT COUNT(*)::int AS total FROM services'),
    query('SELECT COUNT(*)::int AS total FROM service_assignments'),
  ]);

  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(
    [
      '# HELP app_users_total Total users',
      '# TYPE app_users_total gauge',
      `app_users_total ${users.rows[0].total}`,
      '# HELP app_services_total Total services',
      '# TYPE app_services_total gauge',
      `app_services_total ${services.rows[0].total}`,
      '# HELP app_assignments_total Total assignments',
      '# TYPE app_assignments_total gauge',
      `app_assignments_total ${assignments.rows[0].total}`,
    ].join('\n'),
  );
}

module.exports = { metrics };
