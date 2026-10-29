// server.js (บรรทัดบน ๆ)s
const express = require("express");
const db = require("./db"); // ได้ตัวแปร db จาก db.js
const { hashPassword, verifyPassword, createToken, requireAuth, requireStaff } = require('./auth');
const app = express();
const port = process.env.PORT || 3000;

const cors = require('cors');
app.use(cors({ origin: process.env.CORS_ORIGIN }));

app.use(express.json()); // แปลง body ที่เป็น JSON ไปไว้ใน req.body

app.get('/', (req, res) => {
    res.send('สวัสดีร้านส้มตำ');
});

// route ให้ Render เช็กว่าเซิร์ฟเวอร์ยังมีชีวิต (ต้องอยู่ก่อนตัวจัดการ 404)
app.get('/api/health', (req, res) => {
    res.json({ ok: true });
});

function validateUser(body) {
    if (typeof body !== 'object' || body === null) {
        return [{ field: 'body', message: 'ต้องส่งข้อมูลเป็น JSON object' }];
    }
    const errors = [];
    if (typeof body.email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email.trim())) {
        errors.push({ field: 'email', message: 'รูปแบบอีเมลไม่ถูกต้อง' });
    }
    if (typeof body.password !== 'string' || body.password.length < 8) {
        errors.push({ field: 'password', message: 'รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร' });
    }
    return errors;
}

app.post('/api/auth/register', (req, res) => {
    // server.js ใน route register: อีเมลเจ้าของร้านเป็นพนักงานตั้งแต่สมัคร
    const role = email === process.env.STAFF_EMAIL ? 'staff' : 'customer';
    const result = db.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)')
        .run(email, hashPassword(req.body.password), role);
    res.status(201).json({ id: result.lastInsertRowid, email, role });

    const errors = validateUser(req.body);
    if (errors.length > 0) {
        return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง', details: errors });
    }
    const email = req.body.email.trim().toLowerCase();
    try {
        const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
            .run(email, hashPassword(req.body.password));
    res.status(201).json({ id: result.lastInsertRowid, email, role: 'customer' });
    } catch (err) {
        if (isDuplicate(err)) {
            return res.status(409).json({ error: 'อีเมลนี้สมัครไว้แล้ว' });
    }
    throw err;
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'ต้องส่ง email และ password' });
    }
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase());
    if (!user || !verifyPassword(password, user.password_hash)) {
        return res.status(401).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });
    }
    res.json({ token: createToken(user) });
});

app.get('/api/me', requireAuth, (req, res) => {
    const user = db.prepare('SELECT id, email, role, created_at FROM users WHERE id = ?').get(req.user.sub);
    if (!user) {
        return res.status(404).json({ error: 'ไม่พบผู้ใช้นี้' });
    }
    res.json(user);
});

app.patch('/api/me/password', requireAuth, (req, res) => {
    const { oldPassword, newPassword } = req.body || {};
    if (typeof oldPassword !== 'string' || typeof newPassword !== 'string') {
        return res.status(400).json({ error: 'ต้องส่ง oldPassword และ newPassword'});
    }
    if (newPassword.length < 8) {
        return res.status(400).json({ error: 'รหัสผ่านใหม่ต้องยาวอย่างน้อย 8 ตัวอักษร'});
    }
    if (newPassword === oldPassword) {
        return res.status(400).json({ error: 'รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสเดิม'});
    }
    const user = db.prepare('SELECT id, email, password_hash, role, created_at FROM users WHERE id = ?').get(req.user.sub);
    if (!user) {
        return res.status(404).json({ error: 'ไม่พบผู้ใช้นี้' });
    }
    if (!verifyPassword(oldPassword, user.password_hash)) {
        return res.status(401).json({ error: 'รหัสผ่านเดิมไม่ถูกต้อง' });
    }
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        .run(hashPassword(newPassword), user.id);
    res.json({ message: 'เปลี่ยนรหัสผ่านแล้ว' });
});

function validateMenu(body) {
    if (typeof body !== 'object' || body === null) {
        return [{ field: 'body', message: 'ต้องส่งข้อมูลเป็น JSON object' }];
    }
    const errors = [];
    if (typeof body.name !== 'string' || body.name.trim() === '') {
        errors.push({ field: 'name', message: 'ต้องเป็นข้อความและห้ามว่าง' });
    } else if (body.name.trim().length > 50) {
        errors.push({ field: 'name', message: 'ยาวได้ไม่เกิน 50 ตัวอักษร' });
    }
    if (!Number.isInteger(body.price) || body.price < 1 || body.price > 10000) {
        errors.push({ field: 'price', message: 'ต้องเป็นจำนวนเต็มตั้งแต่ 1 ถึง 10,000' });
    }
    return errors;
}

function checkId(req, res, next) {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: 'id ต้องเป็นจำนวนเต็มบวก' });
    }
    next(); // ผ่าน ส่งต่อให้ฟังก์ชันถัดไป
}

// GET /api/menu และ /api/menu?maxPrice=70
app.get("/api/menu", (req, res) => {
    if (req.query.maxPrice === undefined) {
        return res.json(db.prepare("SELECT * FROM menu ORDER BY id").all());
    }
    const max = Number(req.query.maxPrice);
    if (Number.isNaN(max)) {
        return res.status(400).json({ error: "maxPrice ต้องเป็นตัวเลข" });
    }
    res.json(
        db.prepare("SELECT * FROM menu WHERE price <= ? ORDER BY id").all(max),
    );
});

// GET /api/menu/2
app.get("/api/menu/:id", checkId, (req, res) => {
    const id = Number(req.params.id);
    const item = db.prepare("SELECT * FROM menu WHERE id = ?").get(id);
    if (!item) {
        return res.status(404).json({ error: `ไม่พบเมนู id ${id}` });
    }
    res.json(item);
});

// อ่าน Query string: /api/hello?name=มานี
app.get('/api/hello', (req, res) => {
    const name = req.query.name || 'ลูกค้า';
    res.json({ message: `สวัสดี ${name}` });
});

// กำหนด Status Code เอง
// app.get('/api/secret', (req, res) => {
//     res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ' });
// });

function isDuplicate(err) {
    return err.code === 'ERR_SQLITE_ERROR' && err.message.includes('UNIQUE');
}

app.post('/api/menu', requireAuth, requireStaff, (req, res) => {
    const errors = validateMenu(req.body);
    if (errors.length > 0) {
        return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง', details: errors });
    }
    const name = req.body.name.trim();
    try {
        const result = db.prepare('INSERT INTO menu (name, price) VALUES (?, ?)')
        .run(name, req.body.price);
        const item = db.prepare('SELECT * FROM menu WHERE id = ?').get(result.lastInsertRowid);
        res.status(201).json(item);
    } catch (err) {
        if (isDuplicate(err)) {
        return res.status(409).json({ error: `มีเมนู "${name}" อยู่แล้ว` });
        }
        throw err;   // error อื่นที่เราไม่รู้จัก ส่งต่อให้ตัวจัดการ 500 (หัวข้อ 8.5)
    }
});

app.patch('/api/menu/:id', requireAuth, requireStaff, checkId, (req, res) => {
    const id = Number(req.params.id);
    const item = db.prepare('SELECT * FROM menu WHERE id = ?').get(id);
    if (!item) {
        return res.status(404).json({ error: `ไม่พบเมนู id ${id}` });
    }
    const body = req.body || {};
    const updated = {
        name: body.name !== undefined ? body.name : item.name,
        price: body.price !== undefined ? body.price : item.price
    };
    const errors = validateMenu(updated);
    if (errors.length > 0) {
        return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง', details: errors });
    }
    const name = updated.name.trim();
    try {
        db.prepare('UPDATE menu SET name = ?, price = ? WHERE id = ?').run(name, updated.price, id);
    } catch (err) {
        if (isDuplicate(err)) {
        return res.status(409).json({ error: `มีเมนู "${name}" อยู่แล้ว` });
        }
        throw err;
    }
    res.json(db.prepare('SELECT * FROM menu WHERE id = ?').get(id));
});

app.delete('/api/menu/:id', requireAuth, requireStaff, checkId, (req, res) => {
    const result = db.prepare('DELETE FROM menu WHERE id = ?').run(Number(req.params.id));
    if (result.changes === 0) {
        return res.status(404).json({ error: 'ไม่พบเมนูนี้' });
    }
    res.status(204).end();
});

function validateOrder(body) {
    if (typeof body !== 'object' || body === null || !Array.isArray(body.items) || body.items.length === 0) {
        return [{ field: 'items', message: 'ต้องเป็น array ที่มีอย่างน้อย 1 รายการ' }];
    }
    if (body.items.length > 20) {
        return [{ field: 'items', message: 'สั่งได้ไม่เกิน 20 รายการต่อครั้ง' }];
    }
    const errors = [];
    body.items.forEach((item, i) => {
        if (!item || !Number.isInteger(item.menuId) || item.menuId < 1) {
        errors.push({ field: `items[${i}].menuId`, message: 'ต้องเป็นจำนวนเต็มบวก' });
        }
        if (!item || !Number.isInteger(item.qty) || item.qty < 1 || item.qty > 20) {
        errors.push({ field: `items[${i}].qty`, message: 'ต้องเป็นจำนวนเต็มตั้งแต่ 1 ถึง 20' });
        }
    });
    return errors;
}

app.post('/api/orders', requireAuth, (req, res) => {
    const errors = validateOrder(req.body);
    if (errors.length > 0) {
        return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง', details: errors });
    }
    // ราคามาจากคลังเท่านั้น ไม่เชื่อตัวเลขที่ลูกค้าส่งมา
    const findMenu = db.prepare('SELECT * FROM menu WHERE id = ?');
    const lines = [];
    for (const item of req.body.items) {
        const menu = findMenu.get(item.menuId);
        if (!menu) {
        return res.status(400).json({ error: `ไม่มีเมนู id ${item.menuId}` });
        }
        lines.push({ menu, qty: item.qty });
    }
    const total = lines.reduce((sum, line) => sum + line.menu.price * line.qty, 0);

    let orderId;
    db.exec('BEGIN');
    try {
        ({ lastInsertRowid: orderId } = db.prepare('INSERT INTO orders (user_id, total) VALUES (?, ?)')
        .run(req.user.sub, total));
        const addItem = db.prepare('INSERT INTO order_items (order_id, menu_id, name, price, qty) VALUES (?, ?, ?, ?, ?)');
        for (const line of lines) {
        addItem.run(orderId, line.menu.id, line.menu.name, line.menu.price, line.qty);
        }
        db.exec('COMMIT');
    } catch (err) {
        db.exec('ROLLBACK');
        throw err;
    }
    res.status(201).json(getOrder(orderId));
});

function getOrder(id) {
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
    if (!order) {
        return undefined;
    }
    order.items = db.prepare('SELECT menu_id, name, price, qty FROM order_items WHERE order_id = ? ORDER BY id').all(id);
    return order;
}

app.get('/api/orders', requireAuth, (req, res) => {
    if (req.user.role === 'staff') {
        return res.json(db.prepare(`
        SELECT orders.*, users.email
        FROM orders JOIN users ON users.id = orders.user_id
        ORDER BY orders.id DESC`).all());
    }
    res.json(db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC').all(req.user.sub));
});

app.get('/api/orders/:id', requireAuth, checkId, (req, res) => {
    const order = getOrder(Number(req.params.id));
    // ของคนอื่นตอบ 404 เหมือนไม่มี ไม่บอกว่ามีคำสั่งซื้อนี้อยู่
    if (!order || (req.user.role !== 'staff' && order.user_id !== req.user.sub)) {
        return res.status(404).json({ error: 'ไม่พบคำสั่งซื้อนี้' });
    }
    res.json(order);
});

const NEXT_STATUS = {
    pending: ['cooking', 'cancelled'],
    cooking: ['done'],
    done: [],
    cancelled: []
};

app.patch('/api/orders/:id/status', requireAuth, requireStaff, checkId, (req, res) => {
    const id = Number(req.params.id);
    const { status } = req.body || {};
    if (!Object.hasOwn(NEXT_STATUS, status)) {
        return res.status(400).json({ error: 'status ต้องเป็น pending, cooking, done หรือ cancelled' });
    }
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
    if (!order) {
        return res.status(404).json({ error: 'ไม่พบคำสั่งซื้อนี้' });
    }
    if (!NEXT_STATUS[order.status].includes(status)) {
        return res.status(409).json({ error: `เปลี่ยนจาก ${order.status} เป็น ${status} ไม่ได้` });
    }
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, id);
    res.json(getOrder(id));
});

// ตัวจัดการ 404 เดิมจากบทที่ 6
app.use((req, res) => {
    res.status(404).json({ error: `ไม่พบ ${req.method} ${req.path}` });
});

// ใหม่: error middleware (ต้องมี 4 ตัวแปร และอยู่ล่างสุด)
app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'body ไม่ใช่ JSON ที่ถูกต้อง' });
    }
    console.error(err);    // รายละเอียดเต็มลง Terminal ให้เราอ่าน
    res.status(500).json({ error: 'เกิดข้อผิดพลาดในเซิร์ฟเวอร์ ลองใหม่อีกครั้ง' });
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});