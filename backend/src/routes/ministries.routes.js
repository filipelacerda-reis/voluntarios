const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/ministries.controller');

const router = Router();
router.get('/ministries', authRequired, asyncHandler(controller.listMinistries));
router.post('/ministries', authRequired, roleRequired(ROLE_ADMIN), asyncHandler(controller.createMinistry));

module.exports = router;
