const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/approvals.controller');

const router = Router();
router.get('/approvals/pending', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.listPendingApprovals));
router.patch('/approvals/:assignmentId', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.decideApproval));

module.exports = router;
