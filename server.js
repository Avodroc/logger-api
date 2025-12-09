import express from "express";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();

// ✅ Fix express-rate-limit warning on Render
app.set("trust proxy", true);

app.use(express.json());
app.use(cors());

// ----------------------------------------------------
// NEW: Skip ALL logging/DB/rate-limit for /health
// ----------------------------------------------------
app.use((req, res, next) => {
  if (req.path === "/health") {
    return next();  // do not log, do not rate limit, do not store
  }
  next();
});

// -----------------------------
// DATABASE CONNECTION
// -----------------------------
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

// -----------------------------
// RATE LIMITER
// -----------------------------
const validateLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 5,
  message: { error: "Too many requests, slow down." },
});

// -----------------------------
// UTILS
// -----------------------------
function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip ||
    "Unknown"
  );
}
 
function detectBrowserName(ua) {
  if (!ua) return "Other";
  if (/Edg\//.test(ua) || /Edge\//.test(ua)) return "Edge";
  if (/OPR\/|Opera\//.test(ua)) return "Opera";
  if (/Chrome\//.test(ua) && !/Chromium/.test(ua)) return "Chrome";
  if (/Safari\//.test(ua) && !/Chrome\//.test(ua)) return "Safari";
  if (/Firefox\//.test(ua)) return "Firefox";
  return "Other";
}

function detectDeviceType(ua) {
  const s = ua?.toLowerCase() || "";
  if (/mobile|iphone|android|iemobile|phone/i.test(s)) return "mobile";
  if (/tablet|ipad/i.test(s)) return "tablet";
  if (/bot|crawl|spider|bingpreview|pingdom/i.test(s)) return "bot";
  return "desktop";
}

// -----------------------------
// CHECK ENDPOINT
// -----------------------------
app.post("/check", validateLimiter, async (req, res) => {
  try {
    if (!req.body || typeof req.body.code !== "string") {
      return res.status(400).json({ error: "Missing or invalid code" });
    }

    const rawCode = req.body.code.trim();
    if (!rawCode) return res.status(400).json({ error: "Code cannot be empty" });

    const ip = getClientIp(req);
    const user_agent =
      req.headers["user-agent"] ||
      req.body.browser ||
      "Unknown UA";

    const incomingBrowser = req.body.browser || user_agent;
    const incomingReferer = req.body.referer || req.headers.referer || "";
    const incomingDeviceType = req.body.device_type || "";
    const incomingOS = req.body.os || "";
    const incomingBrowserName = req.body.browser_name || "";
    const incomingLanguages = req.body.languages || "";

    const [rows] = await pool.query(
      "SELECT id, code_hash, target_url FROM access_codes"
    );

    let foundUrl = "";

    for (const row of rows) {
      try {
        const match = await bcrypt.compare(rawCode, row.code_hash);
        if (match) {
          foundUrl = row.target_url;
          break;
        }
      } catch (err) {
        console.error("bcrypt compare error:", err, row.id);
      }
    }

    const status = foundUrl ? "Success" : "Failed";

    // Compute attempt_number
    let attempt_number = 1;
    try {
      const [countRows] = await pool.query(
        "SELECT COUNT(*) AS cnt FROM logs WHERE ip = ? AND code = ?",
        [ip, rawCode]
      );
      const cnt = countRows?.[0]?.cnt ?? 0;
      attempt_number = cnt + 1;
    } catch (err) {
      console.error("Attempt count error:", err);
    }

    const finalDeviceType =
      incomingDeviceType || detectDeviceType(user_agent);

    const finalBrowserName =
      incomingBrowserName || detectBrowserName(user_agent);

    await pool.execute(
      `INSERT INTO logs 
        (code, url, status, browser, referer, device_type, os, browser_name, languages, attempt_number, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        rawCode,
        foundUrl,
        status,
        incomingBrowser,
        incomingReferer,
        finalDeviceType,
        incomingOS,
        finalBrowserName,
        incomingLanguages,
        attempt_number,
        ip,
        user_agent,
      ]
    );

    return res.json({
      valid: Boolean(foundUrl),
      url: foundUrl,
    });
  } catch (err) {
    console.error("Check endpoint error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------------------
// ADMIN: ADD NEW CODE
// -----------------------------
app.post("/admin/add", async (req, res) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");

    if (token !== process.env.ADMIN_TOKEN)
      return res.status(403).send("Forbidden");

    const code = req.body.code;
    const url = req.body.url;

    if (!code || !url)
      return res.status(400).send("Missing code or url");

    const hash = await bcrypt.hash(code, 10);

    await pool.execute(
      "INSERT INTO access_codes (code_hash, target_url) VALUES (?, ?)",
      [hash, url]
    );

    res.redirect("/admin?added=1");
  } catch (err) {
    console.error("Admin add error:", err);
    res.status(500).send("Internal error");
  }
});

// -----------------------------
// HEALTH
// -----------------------------
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

// -----------------------------
// ROOT
// -----------------------------
app.get("/", (req, res) => {
  res.send("Logger API running.");
});

// -----------------------------
// START SERVER
// -----------------------------
const PORT = process.env.PORT || 3001;
app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`)
);
