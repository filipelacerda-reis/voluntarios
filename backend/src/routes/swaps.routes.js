const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER, ROLE_VOL } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/swaps.controller');

const router = Router();
router.post('/assignments/:id/swap-request', authRequired, roleRequired(ROLE_VOL), asyncHandler(controller.createSwapRequest));
router.get('/swap-requests', authRequired, asyncHandler(controller.listSwapRequests));
router.patch('/swap-requests/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.decideSwapRequest));

module.exports = router;
