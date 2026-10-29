// make-staff.js   ใช้: node make-staff.js you@example.com
const db = require('./db');

const email = (process.argv[2] || '').trim().toLowerCase();
const result = db.prepare("UPDATE users SET role = 'staff' WHERE email = ?").run(email);
console.log(result.changes === 1 ? `${email} เป็นพนักงานแล้ว ให้ล็อกอินใหม่เพื่อรับ token ใหม่` : `ไม่พบอีเมล ${email}`);