const express = require("express");
const xrayService = require("../services/xrayService");

const router = express.Router();

/**
 * @swagger
 * /api/xray/status:
 *   get:
 *     summary: Get Xray service status
 *     tags: [Xray]
 *     responses:
 *       200:
 *         description: Xray service status
 */
router.get("/status", async (req, res, next) => {
  try {
    const status = await xrayService.getStatus();
    res.json(status);
  } catch (error) {
    next(error);
  }
});

/**
 * @swagger
 * /api/xray/restart:
 *   post:
 *     summary: Restart Xray service
 *     tags: [Xray]
 *     responses:
 *       200:
 *         description: Xray service restarted successfully
 */
router.post("/restart", async (req, res, next) => {
  try {
    await xrayService.restartXray();
    res.json({ message: "Xray service restarted successfully" });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
