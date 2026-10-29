// auth.js
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error('ไม่พบ JWT_SECRET ในไฟล์ .env')
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    const test = crypto.scryptSync(password, salt, 64);
    return crypto.timingSafeEqual(test, Buffer.from(hash, 'hex'));
}

function createToken(user) {
    return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
}

function requireAuth(req, res, next) {
    const header = req.get('Authorization') || '';
    const [type, token] = header.split(' ');
    if (type !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ' });
    }
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        const message = err.name === 'TokenExpiredError'
        ? 'token หมดอายุ กรุณาเข้าสู่ระบบใหม่'
        : 'token ไม่ถูกต้อง';
        return res.status(401).json({ error: message });
    }
}

function requireStaff(req, res, next) {
    if (req.user.role !== 'staff') {
        return res.status(403).json({ error: 'เฉพาะพนักงานร้านเท่านั้น' });
    }
    next();
}

module.exports = { hashPassword, verifyPassword, createToken, requireAuth, requireStaff };