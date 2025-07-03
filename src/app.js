const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const swaggerJSDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
require("dotenv").config();

const logger = require("./utils/logger");
const errorHandler = require("./middleware/errorHandler");

// Route imports
const configRoutes = require("./routes/config");
const userRoutes = require("./routes/users");
const systemRoutes = require("./routes/system");
const xrayRoutes = require("./routes/xray");

const app = express();
const PORT = process.env.PORT || 3000;

// Environment-based configuration
const isDevelopment = process.env.NODE_ENV === 'development' || process.env.NODE_ENV !== 'production';

// CORS configuration - Allow all origins in development
const corsOptions = {
  origin: isDevelopment ? "*" : ["https://yourdomain.com"], // Restrict in production
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  credentials: !isDevelopment // Only allow credentials in production with specific origins
};

// Middleware - Configure helmet based on environment
app.use(helmet({
  crossOriginOpenerPolicy: isDevelopment ? false : { policy: "same-origin" },
  crossOriginResourcePolicy: isDevelopment ? false : { policy: "cross-origin" },
  crossOriginEmbedderPolicy: isDevelopment ? false : true,
  contentSecurityPolicy: isDevelopment ? false : {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: isDevelopment ? false : {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
app.use(cors(corsOptions));
app.use(express.json());

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Bad Proxy API",
      version: "1.0.0",
      description: "API for managing Xray VMess proxy configurations",
    },
    servers: [
      {
        url: isDevelopment ? `http://localhost:${PORT}` : `https://yourdomain.com`,
        description: isDevelopment ? "Development server" : "Production server",
      },
    ],
    components: {
      schemas: {
        User: {
          type: "object",
          required: ["email"],
          properties: {
            id: {
              type: "string",
              format: "uuid",
              description: "User UUID",
            },
            email: {
              type: "string",
              format: "email",
              description: "User email address",
            },
            alterId: {
              type: "integer",
              default: 0,
              description: "VMess alter ID",
            },
            level: {
              type: "integer",
              default: 0,
              description: "User level",
            },
            createdAt: {
              type: "string",
              format: "date-time",
            },
          },
        },
        XrayConfig: {
          type: "object",
          properties: {
            log: {
              type: "object",
            },
            inbounds: {
              type: "array",
              items: {
                type: "object",
              },
            },
            outbounds: {
              type: "array",
              items: {
                type: "object",
              },
            },
            routing: {
              type: "object",
            },
          },
        },
        SystemStatus: {
          type: "object",
          properties: {
            xrayStatus: {
              type: "string",
              enum: ["running", "stopped", "error"],
            },
            version: {
              type: "string",
            },
            uptime: {
              type: "string",
            },
            connections: {
              type: "integer",
            },
          },
        },
      },
    },
  },
  apis: ["./src/routes/*.js"],
};

const specs = swaggerJSDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));

// Routes
app.use("/api/config", configRoutes);
app.use("/api/users", userRoutes);
app.use("/api/system", systemRoutes);
app.use("/api/xray", xrayRoutes);

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Error handling
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Swagger UI available at http://localhost:${PORT}/api-docs`);
});

module.exports = app;