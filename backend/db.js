// Small JSON-file database. Every collection mirrors a table in ../docs/schema.sql,
// so moving to MySQL/PostgreSQL later is a mechanical change (see README).
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'db.json');
const VERSION = 2;
let db;

const pad = (n) => String(n).padStart(2, '0');
const fmt = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const isoDay = (offset = 0) => { const d = new Date(); d.setDate(d.getDate() + offset); return fmt(d); };

const DEFAULT_SETTINGS = {
  clinic: {
    name: 'Talisay City College Clinic', systemName: 'TCC CLINIC — Student Health Record and Consultation Tracking System',
    address: 'Talisay City College, Talisay City, Cebu', email: 'tcclinic@tcc.edu.ph', phone: '(032) 494-1234',
    hours: [
      { days: 'Monday – Friday', time: '8:00 AM – 5:00 PM' },
      { days: 'Saturday', time: '8:00 AM – 12:00 PM' },
      { days: 'Sunday & Holidays', time: 'Closed' },
    ],
  },
  notifications: { appointmentUpdates: true, prescriptionIssued: true, newAnnouncements: true, followUpReminders: true },
  security: { sessionHours: 8, idleMinutes: 30, maxLoginAttempts: 5, minPasswordLength: 8 },
  general: { maxAdvanceDays: 60, slotMinutes: 30, allowRegistration: true },
  permissions: { staff: { manageStudents: true, manageConsultations: true, manageAppointments: true, managePrescriptions: true, manageAnnouncements: true, viewReports: true, deleteRecords: true } },
};

const COLLECTIONS = ['users', 'students', 'healthRecords', 'medicalHistory', 'allergies', 'immunizations', 'vitalSigns',
  'documents', 'consultations', 'appointments', 'prescriptions', 'medicines', 'alerts', 'announcements',
  'notifications', 'activity', 'messages', 'sessions', 'resetTokens'];

function emptyDb() {
  const d = { version: VERSION, nextId: 100, settings: JSON.parse(JSON.stringify(DEFAULT_SETTINGS)) };
  COLLECTIONS.forEach((c) => (d[c] = []));
  return d;
}

// ---------- demo data ----------
function rng(seed) { return () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

const COMPLAINTS = [
  ['Headache and dizziness', 'Tension headache', 'Paracetamol 500mg', '1 tablet', 'every 6 hours as needed', '3 days'],
  ['Sore throat', 'Acute pharyngitis', 'Amoxicillin 500mg', '1 capsule', '3 times a day', '7 days'],
  ['Stomach pain', 'Hyperacidity', 'Antacid (Aluminum hydroxide)', '1 tablet', 'after meals', '5 days'],
  ['Fever and body aches', 'Viral infection', 'Paracetamol 500mg', '1 tablet', 'every 6 hours', '3 days'],
  ['Cough and colds', 'Upper respiratory infection', 'Cetirizine 10mg', '1 tablet', 'once daily at night', '5 days'],
  ['Menstrual cramps', 'Primary dysmenorrhea', 'Mefenamic acid 500mg', '1 capsule', 'every 8 hours as needed', '3 days'],
  ['Minor wound on knee', 'Abrasion', 'Povidone-iodine', 'Apply thin layer', 'twice daily', '5 days'],
  ['Allergic rash', 'Allergic dermatitis', 'Loratadine 10mg', '1 tablet', 'once daily', '5 days'],
  ['Diarrhea', 'Acute gastroenteritis', 'Oral rehydration salts', '1 sachet in 1L water', 'after each loose stool', '3 days'],
  ['Annual physical exam', 'Healthy', null],
];
const STAFF = ['Nurse Maria Santos', 'Dr. Ramon Uy'];
const MEDS = [['Paracetamol 500mg', 'Tablet'], ['Amoxicillin 500mg', 'Capsule'], ['Antacid (Aluminum hydroxide)', 'Tablet'], ['Cetirizine 10mg', 'Tablet'], ['Loratadine 10mg', 'Tablet'], ['Mefenamic acid 500mg', 'Capsule'], ['Povidone-iodine', 'Solution'], ['Oral rehydration salts', 'Sachet'], ['Ibuprofen 200mg', 'Tablet'], ['Salbutamol inhaler', 'Inhaler']];
const STUDENTS = [
  ['Ana Marie Reyes', '2023-00214', 'BSIT', '2nd Year', 'Female', 'A+'], ['Mark Anthony Villanueva', '2022-00387', 'BSED', '3rd Year', 'Male', 'B+'],
  ['Kristine Joy Ramos', '2024-00456', 'BSBA', '1st Year', 'Female', 'O+'], ['John Paul Lim', '2021-00102', 'BSCS', '4th Year', 'Male', 'AB+'],
  ['Maria Cecilia Tan', '2023-00561', 'BEED', '2nd Year', 'Female', 'O-'], ['Carlo Miguel Bautista', '2022-00298', 'BSIT', '3rd Year', 'Male', 'A-'],
  ['Jasmine Mae Flores', '2024-00619', 'BSHM', '1st Year', 'Female', 'B+'], ['Rafael Gabriel Cruz', '2021-00177', 'BSCrim', '4th Year', 'Male', 'O+'],
  ['Angelica Dizon', '2023-00733', 'BSED', '2nd Year', 'Female', 'A+'], ['Nathan Dave Ocampo', '2022-00845', 'BSBA', '3rd Year', 'Male', 'B-'],
  ['Bea Louise Navarro', '2024-00912', 'BSIT', '1st Year', 'Female', 'O+'],
];

function seed() {
  const d = emptyDb();
  const now = new Date().toISOString();
  const R = rng(20260401);
  const pick = (a) => a[Math.floor(R() * a.length)];
  const id = (p) => `${p}${d.nextId++}`;
  const hash = (p) => bcrypt.hashSync(p, 10);

  d.users.push(
    { id: 'u_admin1', role: 'admin', name: 'Clinic Administrator', studentId: '', email: 'admin@tcc.edu.ph', passwordHash: hash(process.env.ADMIN_PASSWORD || 'Admin1234'), status: 'active', photo: '', createdAt: now },
    { id: 'u_staff1', role: 'staff', name: 'Nurse Maria Santos', studentId: '', email: 'nurse@tcc.edu.ph', passwordHash: hash(process.env.STAFF_PASSWORD || 'Staff1234'), status: 'active', photo: '', createdAt: now },
    { id: 'u_staff2', role: 'staff', name: 'Dr. Ramon Uy', studentId: '', email: 'doctor@tcc.edu.ph', passwordHash: hash(process.env.STAFF_PASSWORD || 'Staff1234'), status: 'active', photo: '', createdAt: now },
  );
  MEDS.forEach(([name, form]) => d.medicines.push({ id: id('m'), name, form }));

  // Juan Dela Cruz — the demo student (same login as earlier versions)
  const juan = 'u_student1';
  d.users.push({ id: juan, role: 'student', name: 'Juan Dela Cruz', studentId: '2024-00123', email: 'juan.delacruz@tcc.edu.ph', passwordHash: hash('Student123'), status: 'active', photo: '', createdAt: now });
  d.students.push({ userId: juan, course: 'BSIT', yearLevel: '3rd Year', contact: '0912-345-6789', birthdate: '2003-03-15', gender: 'Male', bloodType: 'O+', address: 'Talisay City, Cebu', emergencyContact: 'Elena Dela Cruz (Mother) — 0917-555-0101' });
  d.healthRecords.push({ userId: juan, general: 'No chronic illnesses currently recorded. Childhood asthma, no attacks in the past 5 years.', lastPhysical: isoDay(-9), notes: 'Allergic to penicillin — avoid penicillin-class antibiotics. Hepatitis B series is incomplete.' });
  d.medicalHistory.push(
    { id: id('mh'), userId: juan, condition: 'Asthma (childhood)', type: 'Condition', date: '', note: 'No attacks in the past 5 years' },
    { id: id('mh'), userId: juan, condition: 'Appendectomy', type: 'Hospitalization', date: '2018-05-12', note: 'Admitted 3 days, no complications' },
  );
  d.allergies.push(
    { id: id('al'), userId: juan, name: 'Penicillin', reaction: 'Skin rash', severity: 'Moderate' },
    { id: id('al'), userId: juan, name: 'Peanuts', reaction: 'Mild swelling', severity: 'Mild' },
  );
  d.immunizations.push(
    { id: id('im'), userId: juan, vaccine: 'COVID-19 (booster)', date: '2023-02-10', status: 'Completed' },
    { id: id('im'), userId: juan, vaccine: 'Influenza', date: isoDay(-120), status: 'Completed' },
    { id: id('im'), userId: juan, vaccine: 'Hepatitis B (dose 2 of 3)', date: '2022-06-05', status: 'Ongoing' },
  );
  d.vitalSigns.push(
    { id: id('v'), userId: juan, date: isoDay(-9), bp: '120/80', heartRate: 78, temp: 36.7, weight: 62, height: 168, recordedBy: 'Dr. Ramon Uy' },
    { id: id('v'), userId: juan, date: isoDay(-200), bp: '118/76', heartRate: 74, temp: 36.5, weight: 61, height: 168, recordedBy: 'Nurse Maria Santos' },
  );
  d.documents.push(
    { id: id('d'), userId: juan, name: 'Physical exam result', category: 'Laboratory Result', date: isoDay(-200), file: null, fileName: '', mime: '', size: 0, uploadedBy: 'Nurse Maria Santos' },
    { id: id('d'), userId: juan, name: 'Chest X-ray', category: 'Laboratory Result', date: '2025-11-14', file: null, fileName: '', mime: '', size: 0, uploadedBy: 'Nurse Maria Santos' },
  );
  [[-60, 0], [-41, 1], [-25, 2], [-9, 9]].forEach(([off, ci]) => {
    const c = COMPLAINTS[ci]; const cid = id('c'); const staff = ci % 2 ? STAFF[1] : STAFF[0];
    d.consultations.push({ id: cid, userId: juan, date: isoDay(off), complaint: c[0], diagnosis: c[1], treatment: c[2] ? `${c[2]}, rest and fluids` : 'No treatment needed', notes: 'Patient assessed by clinic staff. Vitals checked, advised rest and hydration, and to return if symptoms persist.', staffName: ci === 3 || ci === 9 ? STAFF[1] : staff, status: 'completed' });
    if (c[2]) d.prescriptions.push({ id: id('p'), userId: juan, consultationId: cid, date: isoDay(off), medicine: c[2], dosage: c[3], frequency: c[4], duration: c[5], instructions: 'Take with water. Stop and consult the clinic if rash or swelling appears.', staffName: staff, status: off > -30 ? 'active' : 'completed' });
  });
  d.appointments.push(
    { id: id('a'), userId: juan, date: isoDay(3), time: '09:30', purpose: 'Follow-up check-up', notes: '', status: 'approved', staffName: 'Nurse Maria Santos', remarks: '', createdAt: now },
    { id: id('a'), userId: juan, date: isoDay(10), time: '14:00', purpose: 'Dental screening', notes: '', status: 'pending', staffName: '', remarks: '', createdAt: now },
    { id: id('a'), userId: juan, date: isoDay(-9), time: '10:00', purpose: 'Annual physical exam', notes: '', status: 'completed', staffName: 'Dr. Ramon Uy', remarks: '', createdAt: now },
    { id: id('a'), userId: juan, date: isoDay(-30), time: '13:30', purpose: 'Medical certificate', notes: '', status: 'cancelled', staffName: '', remarks: 'Cancelled by student', createdAt: now },
  );

  // other students, with generated history so reports and charts have something to show
  const slotPool = ['08:00', '08:30', '09:00', '10:00', '10:30', '11:00', '13:00', '14:00', '15:00', '16:00'];
  STUDENTS.forEach(([name, sid, course, year, gender, blood], i) => {
    const uid = `u_s${i + 2}`;
    d.users.push({ id: uid, role: 'student', name, studentId: sid, email: `${name.split(' ')[0].toLowerCase()}.${name.split(' ').pop().toLowerCase()}@tcc.edu.ph`, passwordHash: hash('Student123'), status: i === 9 ? 'disabled' : 'active', photo: '', createdAt: now });
    d.students.push({ userId: uid, course, yearLevel: year, contact: `09${17 + (i % 3)}-${String(100 + i * 37).slice(0, 3)}-${String(1000 + i * 211).slice(0, 4)}`, birthdate: `${2000 + (i % 5)}-${pad(1 + (i * 5) % 12)}-${pad(1 + (i * 7) % 28)}`, gender, bloodType: blood, address: 'Talisay City, Cebu', emergencyContact: '' });
    d.healthRecords.push({ userId: uid, general: 'No significant medical concerns on file.', lastPhysical: isoDay(-30 - i * 12), notes: '' });
    d.vitalSigns.push({ id: id('v'), userId: uid, date: isoDay(-30 - i * 12), bp: `${108 + i * 2}/${70 + (i % 4) * 3}`, heartRate: 68 + i * 2, temp: 36.4 + (i % 4) / 10, weight: 48 + i * 3, height: 152 + i * 2, recordedBy: STAFF[i % 2] });
    d.immunizations.push({ id: id('im'), userId: uid, vaccine: 'COVID-19 (primary series)', date: '2022-01-15', status: 'Completed' }, { id: id('im'), userId: uid, vaccine: 'Influenza', date: isoDay(-100 - i * 9), status: i % 3 === 0 ? 'Due' : 'Completed' });
    if (i % 3 === 1) d.allergies.push({ id: id('al'), userId: uid, name: pick(['Shrimp', 'Dust mites', 'Aspirin', 'Pollen']), reaction: pick(['Hives', 'Sneezing', 'Itching']), severity: pick(['Mild', 'Moderate', 'Severe']) });
    const n = 2 + Math.floor(R() * 5);
    for (let k = 0; k < n; k++) {
      const off = -Math.floor(R() * 330) - 3; const c = pick(COMPLAINTS); const st = pick(STAFF); const cid = id('c');
      d.consultations.push({ id: cid, userId: uid, date: isoDay(off), complaint: c[0], diagnosis: c[1], treatment: c[2] ? `${c[2]}, rest and fluids` : 'No treatment needed', notes: '', staffName: st, status: 'completed' });
      if (c[2]) d.prescriptions.push({ id: id('p'), userId: uid, consultationId: cid, date: isoDay(off), medicine: c[2], dosage: c[3], frequency: c[4], duration: c[5], instructions: 'Take as directed.', staffName: st, status: off > -10 ? 'active' : R() > 0.1 ? 'completed' : 'cancelled' });
    }
    const aStat = ['pending', 'approved', 'completed', 'completed', 'cancelled', 'rejected'];
    for (let k = 0; k < 2; k++) {
      const status = pick(aStat); const off = status === 'completed' || status === 'cancelled' ? -Math.floor(R() * 40) - 1 : Math.floor(R() * 12) + 1;
      d.appointments.push({ id: id('a'), userId: uid, date: isoDay(off), time: pick(slotPool), purpose: pick(['Medical check-up', 'Follow-up check', 'Consultation', 'Medical certificate']), notes: '', status, staffName: status === 'pending' ? '' : pick(STAFF), remarks: status === 'rejected' ? 'Schedule not available' : '', createdAt: now });
    }
  });
  // make sure there is no accidental double booking in the generated data
  const seen = new Set();
  d.appointments = d.appointments.filter((a) => { if (!['pending', 'approved'].includes(a.status)) return true; const k = a.date + a.time; if (seen.has(k)) return false; seen.add(k); return true; });

  d.alerts.push(
    { id: id('h'), userId: juan, type: 'followup', title: 'Vaccination record incomplete', message: 'Please submit your Hepatitis B vaccination card to the clinic.', severity: 'warning', active: true, date: isoDay(-5) },
    { id: id('h'), userId: null, type: 'notice', title: 'Dengue advisory', message: 'Cases are rising in the area. Clear standing water and wear long sleeves in the afternoon.', severity: 'critical', active: true, date: isoDay(-2) },
    { id: id('h'), userId: null, type: 'health', title: 'Stay hydrated this week', message: 'Temperatures are high. Drink at least 8 glasses of water and take breaks in the shade.', severity: 'info', active: true, date: isoDay(-1) },
    { id: id('h'), userId: juan, type: 'appointment', title: 'Appointment reminder', message: 'You have a follow-up check-up in 3 days. Bring your school ID.', severity: 'info', active: true, date: isoDay(0) },
    { id: id('h'), userId: juan, type: 'prescription', title: 'Prescription reminder', message: 'Remember to finish your full course of medicine as prescribed.', severity: 'info', active: true, date: isoDay(-3) },
  );
  d.announcements.push(
    { id: id('n'), title: 'Free flu vaccination drive', body: 'The clinic is offering free flu shots to all enrolled students. Bring your school ID.', date: isoDay(-1), category: 'Vaccination Program', status: 'published' },
    { id: id('n'), title: 'Clinic hours during exam week', body: 'The clinic will stay open until 6:00 PM from Monday to Friday.', date: isoDay(-4), category: 'Clinic Schedule Update', status: 'published' },
    { id: id('n'), title: 'Mental health awareness talk', body: 'Join the guidance and clinic team for an open talk in the AVR this Friday at 2 PM.', date: isoDay(-8), category: 'Medical Campaign', status: 'published' },
    { id: id('n'), title: 'Clinic closed for city holiday', body: 'The clinic will be closed on the upcoming city holiday. For emergencies, call 911.', date: isoDay(5), category: 'Clinic Closure', status: 'draft' },
  );
  d.notifications.push({ id: id('nt'), userId: juan, title: 'Appointment approved', message: 'Your follow-up check-up was approved.', link: '#appointments', read: false, createdAt: now });
  d.activity.push({ id: id('ac'), at: now, actor: 'System', action: 'Database seeded', detail: 'Demo data created' });
  return d;
}

// A clean install: just the staff/admin logins and default settings. No students, no records.
function blank() {
  const d = seed();
  const keep = d.users.filter((u) => u.role !== 'student');
  const fresh = emptyDb();
  fresh.users = keep; fresh.nextId = d.nextId;
  fresh.activity.push({ id: `ac${fresh.nextId++}`, at: new Date().toISOString(), actor: 'System', action: 'Database created', detail: 'Blank database' });
  return fresh;
}
const initial = () => (process.env.DEMO_DATA === '1' ? seed() : blank());

// ---------- persistence ----------
function save() {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  const tmp = FILE + '.tmp';
  const fd = fs.openSync(tmp, 'w');
  try { fs.writeSync(fd, JSON.stringify(db, null, 2)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); } // force it onto the disk, not just the OS cache
  fs.renameSync(tmp, FILE); // atomic replace so a crash can't corrupt the file
}

// Save to disk. If the write fails, run undo() so memory never holds data that was not really stored.
function persist(undo) {
  try { save(); return true; } catch (e) {
    console.error('Could not write the database:', e.message);
    try { if (undo) undo(); } catch {}
    return false;
  }
}

// Version 1 files (the earlier student-only build) are converted to a fresh database;
// accounts that existed are kept so people can still log in (the old demo student is not).
function upgradeFromV1(old) {
  const fresh = initial();
  const have = new Set(fresh.users.map((u) => u.id));
  for (const u of old.users || []) {
    if (have.has(u.id) || ['u_staff1', 'u_admin1', 'u_staff2'].includes(u.id) || (u.id === 'u_student1' && u.studentId === '2024-00123')) continue;
    fresh.users.push({ status: 'active', photo: '', ...u });
    if (u.role === 'student') fresh.students.push({ userId: u.id, course: '', yearLevel: '', contact: '', birthdate: '', gender: '', bloodType: '', address: '', emergencyContact: '' });
  }
  fresh.nextId = Math.max(fresh.nextId, old.nextId || 0);
  return fresh;
}

function load() {
  if (fs.existsSync(FILE)) {
    const raw = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    if (raw.version === VERSION) {
      db = raw;
      COLLECTIONS.forEach((c) => (db[c] = db[c] || []));
      db.settings = { ...DEFAULT_SETTINGS, ...(db.settings || {}) };
    } else {
      fs.copyFileSync(FILE, FILE.replace(/\.json$/, '.v1-backup.json'));
      db = upgradeFromV1(raw);
      save();
    }
  } else {
    db = initial();
    save();
  }
  return db;
}

const get = () => db || load();
const newId = (prefix) => `${prefix}${get().nextId++}`;
const log = (actor, action, detail = '') => {
  const a = get().activity; a.unshift({ id: newId('ac'), at: new Date().toISOString(), actor: actor || 'System', action, detail });
  if (a.length > 500) a.length = 500;
};
const notify = (userId, title, message, link = '') => get().notifications.unshift({ id: newId('nt'), userId, title, message, link, read: false, createdAt: new Date().toISOString() });

module.exports = { get, save, persist, newId, isoDay, log, notify, DEFAULT_SETTINGS, FILE };
