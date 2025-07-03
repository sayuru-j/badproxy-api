const Joi = require("joi");

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  alterId: Joi.number().integer().min(0).max(65535).default(0),
  level: Joi.number().integer().min(0).max(255).default(0),
});

const xrayConfigSchema = Joi.object({
  port: Joi.number().integer().min(1).max(65535).required(),
  protocol: Joi.string().valid("vmess").required(),
  settings: Joi.object().required(),
});

module.exports = {
  userSchema,
  xrayConfigSchema,
};
