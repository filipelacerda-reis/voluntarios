const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'change-me';

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      ministryId: user.ministry_id,
      ministryIds: Array.isArray(user.ministry_ids) ? user.ministry_ids : [],
      leaderMinistryIds: Array.isArray(user.leader_ministry_ids) ? user.leader_ministry_ids : [],
      name: user.name,
      email: user.email,
    },
    SECRET,
    { expiresIn: '12h' },
  );
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const [, token] = header.split(' ');
  if (!token) {
    return res.status(401).json({ message: 'Token ausente' });
  }

  try {
    req.user = jwt.verify(token, SECRET);
    return next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' });
  }
}

function roleRequired(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Sem permissão para esta ação' });
    }
    return next();
  };
}

module.exports = {
  signToken,
  authRequired,
  roleRequired,
};
