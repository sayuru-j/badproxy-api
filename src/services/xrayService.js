const fs = require("fs").promises;
const path = require("path");
const { exec } = require("child_process");
const { promisify } = require("util");
const logger = require("../utils/logger");

const execAsync = promisify(exec);

class XrayService {
  constructor() {
    this.configPath = process.env.XRAY_CONFIG_PATH || "/etc/xray/config.json";
    this.xrayBinary = process.env.XRAY_BINARY || "/usr/local/bin/xray";
  }

  async getConfig() {
    try {
      const configData = await fs.readFile(this.configPath, "utf8");
      return JSON.parse(configData);
    } catch (error) {
      if (error.code === "ENOENT") {
        return this.getDefaultConfig();
      }
      throw error;
    }
  }

  async saveConfig(config) {
    try {
      // Backup current config
      await this.backupConfig();

      // Validate config structure
      if (!this.validateConfig(config)) {
        throw new Error("Invalid Xray configuration structure");
      }

      await fs.writeFile(this.configPath, JSON.stringify(config, null, 2));
      logger.info("Xray configuration saved successfully");
      return true;
    } catch (error) {
      logger.error("Failed to save Xray configuration:", error);
      throw error;
    }
  }

  async backupConfig() {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const backupPath = `${this.configPath}.backup.${timestamp}`;

      const configExists = await fs
        .access(this.configPath)
        .then(() => true)
        .catch(() => false);
      if (configExists) {
        await fs.copyFile(this.configPath, backupPath);
        logger.info(`Configuration backed up to ${backupPath}`);
      }
    } catch (error) {
      logger.warn("Failed to backup configuration:", error);
    }
  }

  validateConfig(config) {
    return (
      config &&
      config.inbounds &&
      Array.isArray(config.inbounds) &&
      config.outbounds &&
      Array.isArray(config.outbounds)
    );
  }

  async restartXray() {
    try {
      await execAsync("systemctl restart xray");
      logger.info("Xray service restarted successfully");
      return true;
    } catch (error) {
      logger.error("Failed to restart Xray service:", error);
      throw new Error("Failed to restart Xray service");
    }
  }

  async getStatus() {
    try {
      const { stdout } = await execAsync("systemctl is-active xray");
      const isActive = stdout.trim() === "active";

      let version = "unknown";
      try {
        const { stdout: versionOutput } = await execAsync(
          `${this.xrayBinary} version`
        );
        version = versionOutput.split("\n")[0];
      } catch (err) {
        logger.warn("Could not get Xray version:", err.message);
      }

      return {
        status: isActive ? "running" : "stopped",
        version,
        configPath: this.configPath,
      };
    } catch (error) {
      logger.error("Failed to get Xray status:", error);
      return {
        status: "error",
        error: error.message,
      };
    }
  }

  getDefaultConfig() {
    return {
      log: {
        loglevel: "warning",
      },
      inbounds: [
        {
          port: 10086,
          protocol: "vmess",
          settings: {
            clients: [],
          },
          streamSettings: {
            network: "tcp",
          },
        },
      ],
      outbounds: [
        {
          protocol: "freedom",
          settings: {},
        },
      ],
    };
  }

  async addUser(user) {
    const config = await this.getConfig();
    const vmessInbound = config.inbounds.find(
      (inbound) => inbound.protocol === "vmess"
    );

    if (!vmessInbound) {
      throw new Error("No VMess inbound configuration found");
    }

    if (!vmessInbound.settings.clients) {
      vmessInbound.settings.clients = [];
    }

    // Check if user already exists
    const existingUser = vmessInbound.settings.clients.find(
      (client) => client.email === user.email || client.id === user.id
    );

    if (existingUser) {
      throw new Error("User already exists");
    }

    vmessInbound.settings.clients.push({
      id: user.id,
      email: user.email,
      alterId: user.alterId || 0,
      level: user.level || 0,
    });

    await this.saveConfig(config);
    return user;
  }

  async removeUser(userId) {
    const config = await this.getConfig();
    const vmessInbound = config.inbounds.find(
      (inbound) => inbound.protocol === "vmess"
    );

    if (!vmessInbound || !vmessInbound.settings.clients) {
      throw new Error("No VMess clients found");
    }

    const userIndex = vmessInbound.settings.clients.findIndex(
      (client) => client.id === userId || client.email === userId
    );

    if (userIndex === -1) {
      throw new Error("User not found");
    }

    const removedUser = vmessInbound.settings.clients.splice(userIndex, 1)[0];
    await this.saveConfig(config);
    return removedUser;
  }

  async getUsers() {
    const config = await this.getConfig();
    const vmessInbound = config.inbounds.find(
      (inbound) => inbound.protocol === "vmess"
    );

    if (!vmessInbound || !vmessInbound.settings.clients) {
      return [];
    }

    return vmessInbound.settings.clients.map((client) => ({
      id: client.id,
      email: client.email,
      alterId: client.alterId,
      level: client.level,
    }));
  }
}

module.exports = new XrayService();
