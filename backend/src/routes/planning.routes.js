const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/planning.controller');

const router = Router();
router.post('/planning/repeat-service', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.repeatService));
router.post('/services/bulk', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.bulkServices));

module.exports = router;
