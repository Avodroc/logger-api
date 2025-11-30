import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bcrypt from "bcrypt";
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
  const languages = req.headers["accept-language"] || null;
  const deviceType = /Mobi|Android/i.test(ua) ? "mobile" : "desktop";
  const referer = req.headers.referer || "Direct";

  // GeoIP lookup
  const geo = geoip.lookup(ip) || {};
  const country = geo.country || null;
  const region = geo.region || null;
  const city = geo.city || null;

  try {
    // Get all codes from DB
    const [rows] = await pool.query("SELECT * FROM access_codes");
    let valid = false;
    let url = "Failed";

    for (const row of rows) {
      // Check if code matches hash
      if (await bcrypt.compare(code, row.code_hash)) {
        valid = true;
        url = row.url || "Failed";
        break;
      }
    }

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
        referer,
        deviceType,
        "Unknown", // OS detection removed for now
        "Unknown", // Browser name detection removed for now
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

// Admin logs
app.get("/admin/logs", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM logs ORDER BY created_at DESC");
    res.json(rows);
  } catch (err) {
    console.error("Admin logs error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Start server
const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Server running on port ${port}`));
