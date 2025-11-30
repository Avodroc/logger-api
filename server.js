import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import rateLimit from "express-rate-limit";
import geoip from "geoip-lite";

const app = express();
app.use(cors());
app.use(express.json());

// Rate limiter
const limiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
app.use(limiter);

// MySQL connection pool using environment variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Check code
app.post("/check", async (req, res) => {
  const start = Date.now();
  const { code } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const ua = req.headers["user-agent"] || "";

  // Defaults since UAParser is removed
  const browserName = "Unknown";
  const osName = "Unknown";
  const deviceType = "Unknown";
  const languages = req.headers["accept-language"] || null;

  // GeoIP lookup
  const geo = geoip.lookup(ip) || {};
  const country = geo.country || null;
  const region = geo.region || null;
  const city = geo.city || null;

  try {
    const [row] = await pool.query(
      "SELECT * FROM access_codes WHERE code = ? LIMIT 1",
      [code]
    );

    const valid = row.length > 0;
    const url = valid ? row[0].url : null;
    const status = valid ? "Success" : "Failed";

    // Count previous attempts
    const [attemptRow] = await pool.query(
      "SELECT COUNT(*) AS attempts FROM logs WHERE code = ? AND ip = ?",
      [code, ip]
    );
    const attempt_number = attemptRow[0].attempts + 1;

    // Insert log
    await pool.query(
      `INSERT INTO logs 
      (code, url, status, browser, user_agent, referer, device_type, os, browser_name, languages, attempt_number, ip, country, region, city, response_ms) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        code,
        url,
        status,
        ua,
        ua,
        req.headers.referer || null,
        deviceType,
        osName,
        browserName,
        languages,
        attempt_number,
        ip,
        country,
        region,
        city,
        Date.now() - start,
      ]
    );

    res.json({ valid, url });
  } catch (err) {
    console.error("Check endpoint error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Start server
const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Server running on port ${port}`));
