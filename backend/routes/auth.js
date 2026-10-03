const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const store = require('../db');
const U = require('../lib/util');

const router = express.Router();
const { fail } = U;

const COURSES = ['BSIT', 'BSCS', 'BSED', 'BEED', 'BSBA', 'BSHM', 'BSCrim', 'BSIndTech', 'Other'];
const YEARS = ['1st Year', '2nd Year', '3rd Year', '4th Year', '5th Year'];

function findUser(identifier) {
  const id = String(identifier || '').trim();
  return store.get().users.find((u) => (u.email && U.norm(u.email) === U.norm(id)) || (u.studentId && u.studentId === id));
}
const profileOf = (uid) => store.get().students.find((s) => s.userId === uid) || null;
const fullUser = (u) => ({ ...U.publicUser(u), profile: u.role === 'student' ? profileOf(u.id) : null });

// ---- failed-login lockout (per account identifier) ----
const fails = new Map();
const lockedFor = (key) => { const f = fails.get(key); return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 60000) : 0; };
function noteFail(key) {
  const max = U.settings().security.maxLoginAttempts || 5;
  const f = fails.get(key) || { n: 0, until: 0 }; f.n += 1;
  if (f.n >= max) { f.until = Date.now() + 15 * 60e3; f.n = 0; }
  fails.set(key, f);
}

router.post('/register', U.limiter({ max: 10, windowMs: 3600e3, message: 'Too many sign-ups from this device. Try again later.' }), (req, res) => {
  if (!U.settings().general.allowRegistration) return fail(res, 403, 'Self-registration is turned off. Please visit the clinic.');
  const v = U.validate(req.body, {
    name: { label: 'Full name', required: true, maxLen: 80 },
    studentId: { label: 'Student ID', required: true, pattern: /^\d{4}-\d{4,6}$/, msg: 'Student ID should look like 2024-00123.' },
    email: { label: 'Email', required: true, email: true, maxLen: 120 },
    contact: { label: 'Contact number', required: true, pattern: /^(\+?63|0)9\d{2}[- ]?\d{3}[- ]?\d{4}$/, msg: 'Enter a valid mobile number, e.g. 0912-345-6789.' },
    course: { label: 'Course', required: true, enum: COURSES },
    yearLevel: { label: 'Year level', required: true, enum: YEARS },
    consent: { label: 'Consent' },
  });
  if (v.error) return fail(res, 400, v.error);
  const d = v.data;
  if (d.name.length < 2) return fail(res, 400, 'Please enter your full name.');
  if (!U.validPassword(req.body.password)) return fail(res, 400, U.pwRule());
  if (req.body.confirmPassword !== undefined && req.body.confirmPassword !== req.body.password) return fail(res, 400, 'Passwords do not match.');
  if (req.body.consent !== true) return fail(res, 400, 'Please accept the data privacy and consent policy to continue.');
  if (findUser(d.studentId) || findUser(d.email)) return fail(res, 409, 'An account with that Student ID or email already exists. Try logging in.');

  const db = store.get();
  const user = { id: store.newId('u_'), role: 'student', name: d.name, studentId: d.studentId, email: d.email.toLowerCase(), passwordHash: bcrypt.hashSync(req.body.password, 10), status: 'active', photo: '', createdAt: new Date().toISOString() };
  db.users.push(user);
  db.students.push({ userId: user.id, course: d.course, yearLevel: d.yearLevel, contact: d.contact, birthdate: '', gender: '', bloodType: '', address: '', emergencyContact: '' });
  store.log(user.name, 'Registered', `Student ${user.studentId}`);
  // The account only counts as created once it is safely written to the database.
  const undo = () => { db.users = db.users.filter((x) => x.id !== user.id); db.students = db.students.filter((x) => x.userId !== user.id); };
  if (!store.persist(undo)) return fail(res, 503, 'We could not save your account right now. Please try again in a moment.');
  res.status(201).json({ user: U.publicUser(user) });
});

router.post('/login', U.limiter({ max: 60, windowMs: 15 * 60e3, key: (r) => 'login' + r.ip, message: 'Too many login attempts from this device. Please wait a few minutes.' }), (req, res) => {
  const { identifier, password, role, remember } = req.body || {};
  if (!identifier || !password) return fail(res, 400, 'Enter your Student ID or email and your password.');
  const key = U.norm(identifier);
  const mins = lockedFor(key);
  if (mins) return fail(res, 429, `Too many failed attempts. Try again in ${mins} minute${mins > 1 ? 's' : ''}.`);
  const user = findUser(identifier);
  if (!user || !bcrypt.compareSync(String(password), user.passwordHash)) { noteFail(key); return fail(res, 401, 'Incorrect ID/email or password. Please try again.'); }
  if (user.status === 'disabled') return fail(res, 403, 'This account has been disabled. Contact the clinic administrator.');
  const isStaffSide = user.role === 'staff' || user.role === 'admin';
  if (role === 'student' && isStaffSide) return fail(res, 403, 'This is a clinic staff account. Switch to the Clinic Staff tab.');
  if (role === 'staff' && !isStaffSide) return fail(res, 403, 'This account is not a clinic staff account. Switch to the Student tab.');
  fails.delete(key);
  const token = U.issueToken(user, !!remember);
  store.log(user.name, 'Logged in', user.role);
  store.save();
  res.json({ token, user: U.publicUser(user) });
});

router.post('/logout', U.requireAuth(), (req, res) => {
  const db = store.get(); db.sessions = db.sessions.filter((s) => s.jti !== req.session.jti); store.save();
  res.json({ ok: true });
});

router.get('/me', U.requireAuth(), (req, res) => res.json({ user: fullUser(req.user) }));

// Update own profile. Students can edit contact details; the Student ID is changed only by staff.
router.put('/profile', U.requireAuth(), (req, res) => {
  const isStudent = req.user.role === 'student';
  const spec = { name: { label: 'Full name', required: true, maxLen: 80 }, email: { label: 'Email', required: true, email: true, maxLen: 120 } };
  if (isStudent) Object.assign(spec, {
    contact: { label: 'Contact number', required: true, pattern: /^(\+?63|0)9\d{2}[- ]?\d{3}[- ]?\d{4}$/, msg: 'Enter a valid mobile number, e.g. 0912-345-6789.' },
    course: { label: 'Course', required: true, enum: COURSES }, yearLevel: { label: 'Year level', required: true, enum: YEARS },
  });
  const v = U.validate(req.body, spec); if (v.error) return fail(res, 400, v.error);
  const d = v.data; const other = findUser(d.email);
  if (other && other.id !== req.user.id) return fail(res, 409, 'That email is already used by another account.');
  req.user.name = d.name; req.user.email = d.email.toLowerCase();
  if (req.body.photo !== undefined) {
    const p = String(req.body.photo || '');
    if (p && !/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(p)) return fail(res, 400, 'Profile photo must be a PNG, JPEG or WebP image.');
    if (p.length > 200000) return fail(res, 400, 'Profile photo is too large. Choose a smaller image.');
    req.user.photo = p;
  }
  if (isStudent) { const s = profileOf(req.user.id); if (s) Object.assign(s, { contact: d.contact, course: d.course, yearLevel: d.yearLevel }); }
  store.log(req.user.name, 'Updated profile'); store.save();
  res.json({ user: fullUser(req.user) });
});

router.post('/password', U.requireAuth(), U.limiter({ max: 10, windowMs: 3600e3, key: (r) => 'pw' + r.ip }), (req, res) => {
  const { current, password, confirm } = req.body || {};
  if (!bcrypt.compareSync(String(current || ''), req.user.passwordHash)) return fail(res, 400, 'Your current password is incorrect.');
  if (!U.validPassword(password)) return fail(res, 400, U.pwRule());
  if (password !== confirm) return fail(res, 400, 'New passwords do not match.');
  if (password === current) return fail(res, 400, 'Choose a password different from your current one.');
  req.user.passwordHash = bcrypt.hashSync(password, 10);
  const db = store.get(); db.sessions = db.sessions.filter((s) => s.userId !== req.user.id || s.jti === req.session.jti); // sign out other devices
  store.log(req.user.name, 'Changed password'); store.save();
  res.json({ ok: true });
});

// Password reset. There is no email service, so on a published site resets are done by the clinic administrator
// (User Management -> Reset password). The on-screen reset token only works when the request comes from the
// same machine that runs the server (local demo), and never when NODE_ENV=production. Anyone on the internet
// who knew a Student ID could otherwise take over that account.
router.post('/forgot', U.limiter({ max: 8, windowMs: 3600e3 }), (req, res) => {
  const localDemo = !U.IS_PROD && U.isLoopback(req.ip);
  const user = findUser(req.body && req.body.identifier);
  if (!localDemo) return res.json({ ok: true, manual: true }); // same answer whether or not the account exists
  if (!user) return fail(res, 404, "We couldn't find an account with that ID or email.");
  const db = store.get(); const token = crypto.randomBytes(24).toString('hex');
  db.resetTokens = db.resetTokens.filter((t) => t.userId !== user.id && t.expires > Date.now());
  db.resetTokens.push({ token, userId: user.id, expires: Date.now() + 15 * 60 * 1000 });
  store.save();
  res.json({ ok: true, resetToken: token });
});

router.post('/reset', (req, res) => {
  const { token, password } = req.body || {};
  if (!U.validPassword(password)) return fail(res, 400, U.pwRule());
  const db = store.get(); const entry = db.resetTokens.find((t) => t.token === token && t.expires > Date.now());
  if (!entry) return fail(res, 400, 'This reset request has expired. Please start again.');
  const user = db.users.find((u) => u.id === entry.userId);
  user.passwordHash = bcrypt.hashSync(password, 10);
  db.resetTokens = db.resetTokens.filter((t) => t !== entry);
  db.sessions = db.sessions.filter((s) => s.userId !== user.id);
  store.log(user.name, 'Reset password'); store.save();
  res.json({ ok: true, identifier: user.email || user.studentId });
});

// ---- notifications (any signed-in user sees their own) ----
router.get('/notifications', U.requireAuth(), (req, res) => {
  const list = store.get().notifications.filter((n) => n.userId === req.user.id || (n.userId === 'staff' && req.user.role !== 'student')).slice(0, 30);
  res.json({ notifications: list, unread: list.filter((n) => !n.read).length });
});
router.post('/notifications/read', U.requireAuth(), (req, res) => {
  store.get().notifications.forEach((n) => { if (n.userId === req.user.id || (n.userId === 'staff' && req.user.role !== 'student')) n.read = true; });
  store.save(); res.json({ ok: true });
});

module.exports = router;
module.exports.COURSES = COURSES;
module.exports.YEARS = YEARS;
