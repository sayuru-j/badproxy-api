const logger = require("../utils/logger");

const errorHandler = (err, req, res, next) => {
  logger.error(err.message, {
    stack: err.stack,
    url: req.url,
    method: req.method,
  });

  if (err.isJoi) {
    return res.status(400).json({
      error: "Validation Error",
      message: err.details[0].message,
    });
  }

  if (err.type === "XRAY_ERROR") {
    return res.status(500).json({
      error: "Xray Configuration Error",
      message: err.message,
    });
  }

  res.status(err.status || 500).json({
    error: err.message || "Internal Server Error",
    ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
  });
};

module.exports = errorHandler;
