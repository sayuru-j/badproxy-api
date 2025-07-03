const express = require("express");
const xrayService = require("../services/xrayService");

const router = express.Router();

/**
 * @swagger
 * /api/system/status:
 *   get:
 *     summary: Get system and Xray status
 *     tags: [System]
 *     responses:
 *       200:
 *         description: System status information
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SystemStatus'
 */
router.get("/status", async (req, res, next) => {
  try {
    const xrayStatus = await xrayService.getStatus();
    const users = await xrayService.getUsers();

    res.json({
      xray: xrayStatus,
      userCount: users.length,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
