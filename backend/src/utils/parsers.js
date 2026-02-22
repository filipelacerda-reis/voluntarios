function asDateOnly(value) {
  return new Date(`${value}T00:00:00`);
}

function dateToISO(d) {
  return d.toISOString().slice(0, 10);
}

function parseTags(input) {
  if (!input) return [];
  if (Array.isArray(input)) return input.map((item) => String(item).trim()).filter(Boolean);
  return String(input)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function isUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function hasRole(user, roles) {
  return user && roles.includes(user.role);
}

module.exports = { asDateOnly, dateToISO, parseTags, isUuid, hasRole };
