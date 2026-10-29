// db.js
const { DatabaseSync } = require('node:sqlite');
// const db = new DatabaseSync('restaurant.db');
const db = new DatabaseSync(process.env.DB_PATH || 'restaurant.db');

db.exec(`
    CREATE TABLE IF NOT EXISTS menu (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        name  TEXT    NOT NULL UNIQUE,
        price INTEGER NOT NULL CHECK (price BETWEEN 1 AND 10000)
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT    NOT NULL UNIQUE,
        password_hash TEXT    NOT NULL,
        role          TEXT    NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'staff')),
        created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS orders (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id),
        status     TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'cooking', 'done', 'cancelled')),
        total      INTEGER NOT NULL,
        created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS order_items (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        menu_id  INTEGER REFERENCES menu(id) ON DELETE SET NULL,
        name     TEXT    NOT NULL,
        price    INTEGER NOT NULL,
        qty      INTEGER NOT NULL CHECK (qty BETWEEN 1 AND 20)
    )
`);

// ใส่ข้อมูลตัวอย่างเฉพาะตอนที่ตารางยังว่าง
const { count } = db.prepare('SELECT COUNT(*) AS count FROM menu').get();
if (count === 0) {
    const insert = db.prepare('INSERT INTO menu (name, price) VALUES (?, ?)');
    insert.run('ส้มตำไทย', 60);
    insert.run('ส้มตำปู', 70);
    insert.run('ส้มตำปูปลาร้า', 80);
}

module.exports = db;