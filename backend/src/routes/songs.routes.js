const { Router } = require('express');
const { authRequired, roleRequired } = require('../auth');
const { ROLE_ADMIN, ROLE_LEADER } = require('../constants/roles');
const { asyncHandler } = require('../utils/asyncHandler');
const controller = require('../controllers/songs.controller');

const router = Router();
router.get('/songs', authRequired, asyncHandler(controller.listSongs));
router.post('/songs', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.createSong));
router.delete('/songs/:id', authRequired, roleRequired(ROLE_ADMIN, ROLE_LEADER), asyncHandler(controller.deleteSong));

module.exports = router;
