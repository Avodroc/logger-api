import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import rateLimit from "express-rate-limit";
import bcrypt from "bcrypt";

const app = express();
app.use(cors());
app.use(express.json());

// DB pool using env vars
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

// Basic helpers
const getClientIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.ip || req.connection?.remoteAddress || "";
};

// Rate limiting: 10 requests per minute per IP
const validateLimiter = rateLimit({
  windowMs: 60 * 1000, 
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts, slow down." }
});

// Validate code endpoint
app.post("/check", validateLimiter, async (req, res) => {
  const { code, browser } = req.body ?? {};
  const ip = getClientIp(req);
  const user_agent = req.headers["user-agent"] || browser || "";

  if (typeof code !== "string") {
    return res.status(400).json({ error: "Missing code" });
  }

  try {
    const [rows] = await pool.query("SELECT id, code_hash, target_url FROM access_codes");

    let foundUrl = "";
    for (const r of rows) {
      const match = await bcrypt.compare(code, r.code_hash);
      if (match) {
        foundUrl = r.target_url;
        break;
      }
    }

    const status = foundUrl ? "Success" : "Failed";

    // Log attempt (no platform column)
    await pool.execute(
      "INSERT INTO logs (code, url, status, browser, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
      [code, foundUrl, status, browser || user_agent, ip, user_agent]
    );

    return res.json({ valid: Boolean(foundUrl), url: foundUrl });

  } catch (err) {
    console.error("Check endpoint error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

//
// --- ADMIN PANEL ---
//
const requireAdmin = (req, res, next) => {
  const header = req.headers["authorization"];
  const token = header && header.startsWith("Bearer ") ? header.slice(7) : req.query?.token;
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).send("Unauthorized");
  }
  next();
};

// Admin UI
app.get("/admin", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT id, target_url, created_at FROM access_codes ORDER BY created_at DESC");
    let html = `<!doctype html><html><head><meta charset="utf-8"><title>Admin</title></head><body>
      <h2>Access Codes (hashed)</h2>
      <form method="post" action="/admin/add">
        <label>Code (plaintext): <input name="code" /></label>
        <label>Target URL: <input name="url" size="60"/></label>
        <button type="submit">Add</button>
      </form>
      <hr/><ul>`;
    for (const r of rows) {
      html += `<li>ID:${r.id} — ${r.target_url} — ${r.created_at} 
               <form style="display:inline" method="post" action="/admin/delete">
               <input type="hidden" name="id" value="${r.id}"/><button>Delete</button></form></li>`;
    }
    html += `</ul></body></html>`;
    res.setHeader("Content-Type", "text/html");
    res.send(html);
  } catch (err) {
    console.error("Admin GET error:", err);
    res.status(500).send("Server error");
  }
});

// Parse urlencoded bodies for admin forms
app.use(express.urlencoded({ extended: false }));

// Add a new code
app.post("/admin/add", requireAdmin, async (req, res) => {
  const code = req.body.code ?? "";
  const url = req.body.url ?? "";
  if (!code || !url) return res.status(400).send("Missing fields");

  try {
    const hash = await bcrypt.hash(code, 10);
    await pool.execute("INSERT INTO access_codes (code_hash, target_url) VALUES (?, ?)", [hash, url]);
    return res.redirect("/admin?added=1");
  } catch (err) {
    console.error("Admin add error:", err);
    return res.status(500).send("Server error");
  }
});

// Delete code by ID
app.post("/admin/delete", requireAdmin, async (req, res) => {
  const id = parseInt(req.body.id, 10);
  if (!id) return res.status(400).send("Missing id");
  try {
    await pool.execute("DELETE FROM access_codes WHERE id = ?", [id]);
    return res.redirect("/admin?deleted=1");
  } catch (err) {
    console.error("Admin delete error:", err);
    return res.status(500).send("Server error");
  }
});

// Recent logs
app.get("/admin/logs", requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT id, code, url, status, browser, ip, user_agent, created_at FROM logs ORDER BY created_at DESC LIMIT 200");
    res.json(rows);
  } catch (err) {
    console.error("Admin logs error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Health check
app.get("/", (req, res) => res.json({ ok: true }));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
