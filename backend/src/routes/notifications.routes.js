const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/notifications.controller');

const router = Router();
router.get('/notifications', authRequired, asyncHandler(controller.listNotifications));
router.post('/notifications/test', authRequired, asyncHandler(controller.testNotification));
router.post('/notifications/reminders/pending-confirmations', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.sendPendingConfirmationReminders));

module.exports = router;
