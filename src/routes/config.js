const express = require("express");
const xrayService = require("../services/xrayService");
const logger = require("../utils/logger");

const router = express.Router();

/**
 * @swagger
 * /api/config:
 *   get:
 *     summary: Get current Xray configuration
 *     tags: [Configuration]
 *     responses:
 *       200:
 *         description: Current Xray configuration
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/XrayConfig'
 */
router.get("/", async (req, res, next) => {
  try {
    const config = await xrayService.getConfig();
    res.json(config);
  } catch (error) {
    next(error);
  }
});

/**
 * @swagger
 * /api/config:
 *   put:
 *     summary: Update Xray configuration
 *     tags: [Configuration]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/XrayConfig'
 *     responses:
 *       200:
 *         description: Configuration updated successfully
 */
router.put("/", async (req, res, next) => {
  try {
    await xrayService.saveConfig(req.body);
    await xrayService.restartXray();

    logger.info("Configuration updated and Xray restarted");
    res.json({ message: "Configuration updated successfully" });
  } catch (error) {
    next(error);
  }
});

/**
 * @swagger
 * /api/config/reload:
 *   post:
 *     summary: Reload Xray service
 *     tags: [Configuration]
 *     responses:
 *       200:
 *         description: Xray service reloaded successfully
 */
router.post("/reload", async (req, res, next) => {
  try {
    await xrayService.restartXray();
    res.json({ message: "Xray service reloaded successfully" });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
