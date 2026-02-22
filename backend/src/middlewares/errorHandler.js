function errorHandler(err, _req, res, _next) {
  // eslint-disable-next-line no-console
  console.error(err);
  const status = Number(err.statusCode || err.status || 500);
  const message = status >= 500 ? 'Erro interno no servidor' : err.message || 'Erro na requisição';
  res.status(status).json({ message });
}

module.exports = { errorHandler };
