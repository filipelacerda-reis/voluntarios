const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/logs.controller');

const router = Router();
router.get('/audit-logs', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.listAuditLogs));

module.exports = router;
