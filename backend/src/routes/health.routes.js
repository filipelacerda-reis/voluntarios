const { Router } = require('express');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/health.controller');

const router = Router();
router.get('/health', asyncHandler(controller.health));

module.exports = router;
