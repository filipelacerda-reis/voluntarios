const { Router } = require('express');
const { authRequired } = require('../auth');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/dashboard.controller');

const router = Router();
router.get('/dashboard', authRequired, asyncHandler(controller.getDashboard));

module.exports = router;
