const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER, ROLE_VOL } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/availability.controller');

const router = Router();
router.get('/availability-blocks', authRequired, asyncHandler(controller.listAvailability));
router.post('/availability-blocks', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER, ROLE_VOL), asyncHandler(controller.createAvailability));
router.delete('/availability-blocks/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER, ROLE_VOL), asyncHandler(controller.deleteAvailability));

module.exports = router;
