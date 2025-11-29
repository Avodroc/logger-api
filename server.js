import express from "express";
import mysql from "mysql2";
import cors from "cors"; // Added for CORS support

const app = express();

// Enable CORS for all origins (you can restrict to Carrd later if needed)
app.use(cors());
app.use(express.json());

// DB connection pool using Render environment variables
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// Logging endpoint
app.post("/log", (req, res) => {
    const { code, url, status, browser, platform } = req.body;

    const sql = `
        INSERT INTO logs 
        (code, url, status, browser, platform)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.query(sql, [code, url, status, browser, platform], (err) => {
        if (err) {
            console.error("DB Insert Error:", err);
            return res.status(500).json({ success: false, error: "DB error" });
        }

        return res.json({ success: true });
    });
});

// Start server on Render-assigned port
app.listen(process.env.PORT || 3000, () => {
    console.log("API running on Render");
});

//test
