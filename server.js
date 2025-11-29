import express from "express";
import mysql from "mysql2";

const app = express();
app.use(express.json());

// DB connection pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// Main logging endpoint
app.post("/log", (req, res) => {
    const { code, matched, browser, platform, status, ip } = req.body;

    const sql = `
        INSERT INTO Logs 
        (CodeEntered, Matched, Browser, Platform, Status, IP)
        VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(sql, [code, matched, browser, platform, status, ip], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, error: "DB error" });
        }

        return res.json({ success: true });
    });
});

// Render requires using process.env.PORT
app.listen(process.env.PORT || 3000, () => {
    console.log("API running on Render");
});
