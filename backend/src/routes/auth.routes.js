const { Router } = require('express');
const { authRequired } = require('../auth');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/auth.controller');

const router = Router();
router.post('/auth/login', asyncHandler(controller.login));
router.get('/auth/me', authRequired, asyncHandler(controller.me));
router.post('/auth/change-password', authRequired, asyncHandler(controller.changePassword));

module.exports = router;
