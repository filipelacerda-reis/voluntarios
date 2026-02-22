const { Router } = require('express');
const { authRequired } = require('../auth');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/assignments.controller');

const router = Router();
router.patch('/assignments/:id/status', authRequired, asyncHandler(controller.updateAssignmentStatus));

module.exports = router;
