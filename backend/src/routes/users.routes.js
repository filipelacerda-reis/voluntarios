const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/users.controller');

const router = Router();
router.get('/users', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.listUsers));
router.post('/users', authRequired, roleRequired(ROLE_ADMIN), asyncHandler(controller.createUser));
router.patch('/users/:id/ministries', authRequired, roleRequired(ROLE_ADMIN), asyncHandler(controller.updateUserMinistries));
router.patch('/users/:id/active', authRequired, roleRequired(ROLE_ADMIN), asyncHandler(controller.setUserActive));

module.exports = router;
