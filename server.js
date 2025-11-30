import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bcrypt from "bcrypt";
import fetch from "node-fetch";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- DB connection ---
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// --- Helpers ---
const getClientIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "";
};

const getDeviceType = (ua) => /Mobi|Android/i.test(ua) ? "mobile" : "desktop";

// --- Rate limiting ---
const validateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts, slow down." }
});

// --- Check endpoint ---
app.post("/check", validateLimiter, async (req, res) => {
  const { code } = req.body ?? {};
  const ip = getClientIp(req);
  const user_agent = req.headers["user-agent"] || "";
  const referer = req.headers["referer"] || "";
  const device_type = getDeviceType(user_agent);
  const startTime = Date.now();

  if (!code) return res.status(400).json({ error: "Missing code" });

  try {
    const [rows] = await pool.query("SELECT id, code_hash, target_url FROM access_codes");
    let foundUrl = "";
    for (const r of rows) {
      if (await bcrypt.compare(code, r.code_hash)) {
        foundUrl = r.target_url;
        break;
      }
    }

    const status = foundUrl ? "Success" : "Failed";

    // --- GeoIP lookup ---
    let country = null, region = null, city = null;
    try {
      const geo = await fetch(`https://ipapi.co/${ip}/json/`).then(r => r.json());
      country = geo.country_name || null;
      region = geo.region || null;
      city = geo.city || null;
    } catch {}

    // --- Count previous attempts for this code+IP ---
    const [[attemptRow]] = await pool.query(
      "SELECT COUNT(*) AS cnt FROM logs WHERE code = ? AND ip = ?",
      [code, ip]
    );
    const attempt_number = attemptRow?.cnt + 1 || 1;

    const response_ms = Date.now() - startTime;

    // --- Insert log ---
    await pool.execute(
      `INSERT INTO logs 
      (code, url, status, browser, user_agent, referer, device_type, os, browser_name, languages, attempt_number, ip, country, region, city, response_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        code,
        foundUrl,
        status,
        user_agent,
        user_agent,
        referer,
        device_type,
        null, // os (optional parsing if you want)
        null, // browser_name (optional parsing if you want)
        req.headers["accept-language"] || null,
        attempt_number,
        ip,
        country,
        region,
        city,
        response_ms
      ]
    );

    res.json({ valid: Boolean(foundUrl), url: foundUrl });
  } catch (err) {
    console.error("Check endpoint error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- Admin endpoints ---
const requireAdmin = (req, res, next) => {
  const header = req.headers["authorization"];
  const token = header && header.startsWith("Bearer ") ? header.slice(7) : req.query?.token;
  if (!token || token !== process.env.ADMIN_TOKEN) return res.status(401).send("Unauthorized");
  next();
};

app.get("/admin", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT id, target_url, created_at FROM access_codes ORDER BY created_at DESC");
    let html = "<!doctype html><html><head><meta charset='utf-8'><title>Admin</title></head><body>";
    html += "<h2>Access Codes</h2><form method='post' action='/admin/add'>";
    html += "Code: <input name='code' /> Target URL: <input name='url' size='60'/> <button>Add</button></form><hr/><ul>";
    for (const r of rows) {
      html += `<li>ID:${r.id} — ${r.target_url} — ${r.created_at} 
               <form style="display:inline" method="post" action="/admin/delete">
               <input type="hidden" name="id" value="${r.id}"/><button>Delete</button></form></li>`;
    }
    html += "</ul></body></html>";
    res.setHeader("Content-Type", "text/html");
    res.send(html);
  } catch (err) {
    console.error("Admin GET error:", err);
    res.status(500).send("Server error");
  }
});

app.post("/admin/add", requireAdmin, async (req, res) => {
  const code = req.body.code ?? "";
  const url = req.body.url ?? "";
  if (!code || !url) return res.status(400).send("Missing fields");
  try {
    const hash = await bcrypt.hash(code, 10);
    await pool.execute("INSERT INTO access_codes (code_hash, target_url) VALUES (?, ?)", [hash, url]);
    res.redirect("/admin?added=1");
  } catch (err) {
    console.error("Admin add error:", err);
    res.status(500).send("Server error");
  }
});

app.post("/admin/delete", requireAdmin, async (req, res) => {
  const id = parseInt(req.body.id, 10);
  if (!id) return res.status(400).send("Missing id");
  try {
    await pool.execute("DELETE FROM access_codes WHERE id = ?", [id]);
    res.redirect("/admin?deleted=1");
  } catch (err) {
    console.error("Admin delete error:", err);
    res.status(500).send("Server error");
  }
});

// --- Health ---
app.get("/", (req, res) => res.json({ ok: true }));

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
