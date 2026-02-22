const { Router } = require('express');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/metrics.controller');

const router = Router();
router.get('/metrics', asyncHandler(controller.metrics));

module.exports = router;
