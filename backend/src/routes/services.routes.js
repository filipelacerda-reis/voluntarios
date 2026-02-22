const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER, ROLE_VOL } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/services.controller');

const router = Router();
router.get('/services', authRequired, asyncHandler(controller.listServices));
router.post('/services', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.createService));
router.patch('/services/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.updateService));
router.delete('/services/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.deleteService));
router.get('/services/:id', authRequired, asyncHandler(controller.getServiceDetails));

router.post('/services/:id/setlist', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.addSetlist));
router.patch('/services/:serviceId/setlist/:itemId', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.updateSetlist));
router.delete('/services/:serviceId/setlist/:itemId', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.deleteSetlist));

router.post('/services/:id/assignments', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.assignUser));
router.post('/services/:id/self-assign', authRequired, roleRequired(ROLE_VOL), asyncHandler(controller.selfAssign));

module.exports = router;
