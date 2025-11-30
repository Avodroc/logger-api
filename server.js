import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import rateLimit from "express-rate-limit";
import fetch from "node-fetch";

const app = express();
app.use(express.json());
app.use(cors());

// RATE LIMITING
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: "Too many requests. Slow down." }
});
app.use(limiter);

// MYSQL CONNECTION
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// ------------------------------
//          CHECK ENDPOINT
// ------------------------------
app.post("/check", async (req, res) => {
    const startTime = Date.now();

    try {
        const { code } = req.body;
        const ip =
            req.headers["x-forwarded-for"] ||
            req.socket.remoteAddress ||
            "Unknown";

        const userAgent =
            req.headers["user-agent"] ||
            "Unknown";

        if (!code) {
            return res.status(400).json({ error: "Missing code" });
        }

        // Lookup code
        const [rows] = await pool.execute(
            "SELECT * FROM access_codes WHERE code = ? LIMIT 1",
            [code]
        );

        const found = rows.length === 1;
        const entry = found ? rows[0] : null;

        // --------------------------
        //      GEOIP LOOKUP
        // --------------------------
        let geo = { country: null, region: null, city: null };

        try {
            const geoReq = await fetch(`https://ipapi.co/${ip}/json/`);
            const geoData = await geoReq.json();

            geo.country = geoData.country_name || null;
            geo.region = geoData.region || null;
            geo.city = geoData.city || null;
        } catch (err) {
            console.log("GeoIP lookup failed:", err);
        }

        const responseTime = Date.now() - startTime;

        // --------------------------
        //      LOG ATTEMPT
        // --------------------------
        await pool.execute(
            `INSERT INTO logs 
            (code, url, status, ip, user_agent, country, region, city, response_ms) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                code,
                found ? entry.target_url : null,
                found ? "Success" : "Fail",
                ip,
                userAgent,
                geo.country,
                geo.region,
                geo.city,
                responseTime
            ]
        );

        // --------------------------
        //   UPDATE SUCCESS/FAIL COUNT
        // --------------------------
        if (found) {
            await pool.execute(
                "UPDATE access_codes SET success_count = success_count + 1 WHERE code = ?",
                [code]
            );
        } else {
            await pool.execute(
                "UPDATE access_codes SET fail_count = fail_count + 1 WHERE code = ?",
                [code]
            );
        }

        if (!found) {
            return res.json({ valid: false });
        }

        return res.json({ valid: true, url: entry.target_url });

    } catch (err) {
        console.error("Check endpoint error:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

// ------------------------------
//      ADMIN: ADD CODE
// ------------------------------
app.post("/admin/add", async (req, res) => {
    try {
        const token = req.headers.authorization?.replace("Bearer ", "") || "";
        if (token !== process.env.ADMIN_TOKEN) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        const { code, url } = req.body;

        await pool.execute(
            "INSERT INTO access_codes (code, target_url) VALUES (?, ?)",
            [code, url]
        );

        return res.json({ added: true });
    } catch (err) {
        console.error("Admin add error:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

// ------------------------------
//           START SERVER
// ------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Server running on port", PORT);
});
