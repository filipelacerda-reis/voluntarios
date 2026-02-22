const { Router } = require('express');

const healthRoutes = require('./health.routes');
const metricsRoutes = require('./metrics.routes');
const authRoutes = require('./auth.routes');
const ministriesRoutes = require('./ministries.routes');
const usersRoutes = require('./users.routes');
const availabilityRoutes = require('./availability.routes');
const songsRoutes = require('./songs.routes');
const servicesRoutes = require('./services.routes');
const planningRoutes = require('./planning.routes');
const approvalsRoutes = require('./approvals.routes');
const assignmentsRoutes = require('./assignments.routes');
const swapsRoutes = require('./swaps.routes');
const notificationsRoutes = require('./notifications.routes');
const logsRoutes = require('./logs.routes');
const dashboardRoutes = require('./dashboard.routes');

const router = Router();

router.use(healthRoutes);
router.use(metricsRoutes);
router.use(authRoutes);
router.use(ministriesRoutes);
router.use(usersRoutes);
router.use(availabilityRoutes);
router.use(songsRoutes);
router.use(servicesRoutes);
router.use(planningRoutes);
router.use(approvalsRoutes);
router.use(assignmentsRoutes);
router.use(swapsRoutes);
router.use(notificationsRoutes);
router.use(logsRoutes);
router.use(dashboardRoutes);

module.exports = router;
