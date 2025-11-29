import express from "express";
import mysql from "mysql2";
import cors from "cors";

const app = express();

app.use(cors()); // <-- allows requests from any origin
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
    const { code, url, browser, platform, status } = req.body;

    const sql = `
        INSERT INTO logs 
        (code, url, status, browser, platform)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.query(sql, [code, url, status, browser, platform], (err) => {
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
