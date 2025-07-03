const express = require("express");
const { v4: uuidv4 } = require("uuid");
const { userSchema } = require("../utils/validation");
const xrayService = require("../services/xrayService");
const logger = require("../utils/logger");

const router = express.Router();

/**
 * @swagger
 * /api/users:
 *   get:
 *     summary: Get all VMess users
 *     tags: [Users]
 *     responses:
 *       200:
 *         description: List of users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 */
router.get("/", async (req, res, next) => {
  try {
    const users = await xrayService.getUsers();
    res.json(users);
  } catch (error) {
    next(error);
  }
});

/**
 * @swagger
 * /api/users:
 *   post:
 *     summary: Add a new VMess user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               alterId:
 *                 type: integer
 *                 default: 0
 *               level:
 *                 type: integer
 *                 default: 0
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 */
router.post("/", async (req, res, next) => {
  try {
    const { error, value } = userSchema.validate(req.body);
    if (error) {
      error.isJoi = true;
      return next(error);
    }

    const user = {
      id: uuidv4(),
      email: value.email,
      alterId: value.alterId,
      level: value.level,
      createdAt: new Date().toISOString(),
    };

    await xrayService.addUser(user);
    await xrayService.restartXray();

    logger.info(`User created: ${user.email}`);
    res.status(201).json(user);
  } catch (error) {
    next(error);
  }
});

/**
 * @swagger
 * /api/users/{id}:
 *   delete:
 *     summary: Delete a VMess user
 *     tags: [Users]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID or email
 *     responses:
 *       200:
 *         description: User deleted successfully
 */
router.delete("/:id", async (req, res, next) => {
  try {
    const userId = req.params.id;
    const removedUser = await xrayService.removeUser(userId);
    await xrayService.restartXray();

    logger.info(`User deleted: ${removedUser.email}`);
    res.json({
      message: "User deleted successfully",
      user: removedUser,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * @swagger
 * /api/users/generate-uuid:
 *   post:
 *     summary: Generate a new UUID
 *     tags: [Users]
 *     responses:
 *       200:
 *         description: Generated UUID
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 uuid:
 *                   type: string
 *                   format: uuid
 */
router.post("/generate-uuid", (req, res) => {
  res.json({ uuid: uuidv4() });
});

module.exports = router;
