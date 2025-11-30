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

// MySQL connection pool (environment variables)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// ---------------- CHECK CODE ----------------
app.post("/check", async (req, res) => {
  const start = Date.now();
  const { code } = req.body;
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const ua = req.headers["user-agent"] || "";
  const referer = req.headers.referer || null;
  const device_type = /Mobi|Android/i.test(ua) ? "mobile" : "desktop";
  const languages = req.headers["accept-language"] || null;

  const geo = geoip.lookup(ip) || {};
  const country = geo.country || null;
  const region = geo.region || null;
  const city = geo.city || null;

  try {
    // Fetch all hashed codes
    const [rows] = await pool.query("SELECT * FROM access_codes WHERE code_hash IS NOT NULL");

    let valid = false;
    let url = null;

    for (let row of rows) {
      const match = await bcrypt.compare(code, row.code_hash);
      if (match) {
        valid = true;
        url = row.url;
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
        url || "Failed",
        status,
        ua,
        ua,
        referer,
        device_type,
        "Unknown",
        "Unknown",
        languages,
        attempt_number,
        ip,
        country,
        region,
        city,
        Date.now() - start,
      ]
    );

    res.json({ valid, url: url || "Failed" });
  } catch (err) {
    console.error("Check endpoint error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ---------------- ADMIN ADD CODE ----------------
app.post("/admin/add", async (req, res) => {
  const { code, url } = req.body;

  if (!code || !url) {
    return res.status(400).json({ error: "Code and URL required" });
  }

  try {
    // Hash the code before storing
    const hash = await bcrypt.hash(code, 10);

    await pool.query(
      "INSERT INTO access_codes (code_hash, url) VALUES (?, ?)",
      [hash, url]
    );

    res.json({ success: true, message: "Code added and hashed successfully" });
  } catch (err) {
    console.error("Admin add error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Start server
const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`Server running on port ${port}`));
