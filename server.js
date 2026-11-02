import express from 'express';
import path from 'node:path';
import { createHash, randomBytes, createHmac, timingSafeEqual, scryptSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();
// Railway terminates HTTPS at its proxy; trust forwarded headers so invite links use https.
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(express.json({ limit: '1mb' }));
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'HR Manager' }));

// Администратор задаётся только через переменные окружения Railway.
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const SESSION_COOKIE = 'hr_manager_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
if (!ADMIN_USERNAME || !ADMIN_PASSWORD || SESSION_SECRET.length < 32) {
  console.error('Set ADMIN_USERNAME, ADMIN_PASSWORD and SESSION_SECRET (at least 32 characters) in environment variables.');
  process.exit(1);
}
const loginAttempts = new Map();
const sign = value => createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
const makeSession = (role, sub) => {
  const payload = Buffer.from(JSON.stringify({ role, sub, exp: Math.floor(Date.now()/1000) + SESSION_TTL_SECONDS, nonce: randomBytes(12).toString('hex') })).toString('base64url');
  return `${payload}.${sign(payload)}`;
};
const readSession = token => {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.'); if (parts.length !== 2) return null;
  const expected = Buffer.from(sign(parts[0])); const supplied = Buffer.from(parts[1]);
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return null;
  try { const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); return payload.exp > Math.floor(Date.now()/1000) ? payload : null; } catch { return null; }
};
const validSession = (token, role, sub) => { const payload = readSession(token); return Boolean(payload && payload.role === role && (sub === undefined || payload.sub === sub)); };
const hashPassword = password => { const salt = randomBytes(16).toString('hex'); return `scrypt$${salt}$${scryptSync(password, salt, 64).toString('hex')}`; };
const verifyPassword = (password, stored) => { try { const [kind, salt, hash] = String(stored || '').split('$'); if (kind !== 'scrypt' || !salt || !hash) return false; const expected = Buffer.from(hash, 'hex'); const actual = scryptSync(password, salt, 64); return expected.length === actual.length && timingSafeEqual(expected, actual); } catch { return false; } };
const EMPLOYEE_COOKIE = 'hr_employee_session';
const getCookie = (req, name) => (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`))?.slice(name.length + 1);
const sameOrigin = (req, res, next) => {
  const origin = req.get('origin');
  if (origin) {
    try { const parsed = new URL(origin); if (parsed.host !== req.get('host')) return res.status(403).json({ error: 'Запрос отклонён: неверный источник' }); }
    catch { return res.status(403).json({ error: 'Запрос отклонён' }); }
  }
  next();
};
app.post('/api/auth/login', sameOrigin, (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const attempt = loginAttempts.get(ip) || { count: 0, until: 0 };
  if (attempt.until > Date.now()) return res.status(429).json({ error: 'Слишком много попыток. Подождите 15 минут.' });
  const username = Buffer.from(String(req.body.username || ''));
  const password = Buffer.from(String(req.body.password || ''));
  const expectedUser = Buffer.from(ADMIN_USERNAME); const expectedPass = Buffer.from(ADMIN_PASSWORD);
  const userOk = username.length === expectedUser.length && timingSafeEqual(username, expectedUser);
  const passOk = password.length === expectedPass.length && timingSafeEqual(password, expectedPass);
  if (!userOk || !passOk) {
    attempt.count += 1;
    if (attempt.count >= 8) { attempt.count = 0; attempt.until = Date.now() + 15 * 60 * 1000; }
    loginAttempts.set(ip, attempt);
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  loginAttempts.delete(ip);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${makeSession('admin', ADMIN_USERNAME)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${req.secure || process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ ok: true, username: ADMIN_USERNAME });
});
app.get('/api/auth/me', (req, res) => {
  if (!validSession(getCookie(req, SESSION_COOKIE), 'admin', ADMIN_USERNAME)) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, username: ADMIN_USERNAME });
});
app.post('/api/auth/logout', sameOrigin, (req, res) => {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${req.secure || process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ ok: true });
});
// Авторизация сотрудника: отдельная сессия и отдельный набор API.
const employeeLoginAttempts = new Map();
app.post('/api/employee-auth/login', sameOrigin, asyncRoute(async (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const attempt = employeeLoginAttempts.get(ip) || { count: 0, until: 0 };
  if (attempt.until > Date.now()) return res.status(429).json({ error: 'Слишком много попыток. Подождите 15 минут.' });
  const login = cleanText(req.body.login).toLowerCase();
  const password = String(req.body.password || '');
  const employee = await prisma.employee.findUnique({ where: { login } });
  if (!employee || !employee.passwordHash || employee.status !== 'Работает' || !verifyPassword(password, employee.passwordHash)) {
    attempt.count += 1; if (attempt.count >= 8) { attempt.count = 0; attempt.until = Date.now() + 15 * 60 * 1000; }
    employeeLoginAttempts.set(ip, attempt);
    return res.status(401).json({ error: 'Неверный логин или пароль, либо доступ не активирован' });
  }
  employeeLoginAttempts.delete(ip);
  res.setHeader('Set-Cookie', `${EMPLOYEE_COOKIE}=${makeSession('employee', employee.id)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${req.secure || process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ ok: true });
}));
app.get('/api/employee-auth/me', asyncRoute(async (req, res) => {
  const session = readSession(getCookie(req, EMPLOYEE_COOKIE));
  if (!session || session.role !== 'employee') return res.status(401).json({ authenticated: false });
  const employee = await prisma.employee.findUnique({ where: { id: session.sub }, select: { id: true, status: true, login: true, passwordHash: true } });
  if (!employee || employee.status !== 'Работает' || !employee.login || !employee.passwordHash) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true });
}));
app.post('/api/employee-auth/logout', sameOrigin, (req, res) => {
  res.setHeader('Set-Cookie', `${EMPLOYEE_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${req.secure || process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
  res.json({ ok: true });
});

// Сотрудник самостоятельно активирует личный кабинет после одобрения анкеты.
app.post('/api/public/employee-activation/:token', sameOrigin, asyncRoute(async (req, res) => {
  const activation = await prisma.employeeActivation.findUnique({ where: { tokenHash: hashToken(req.params.token) }, include: { employee: true } });
  if (!activation || activation.expiresAt <= new Date()) return res.status(404).json({ error: 'Ссылка активации недействительна или срок её действия истёк. Обратитесь к руководителю.' });
  const login = cleanText(req.body.login).toLowerCase();
  const password = String(req.body.password || '');
  if (!/^[a-z0-9._-]{3,40}$/.test(login)) return res.status(400).json({ error: 'Логин: 3–40 символов, латинские буквы, цифры, точка, дефис или подчёркивание' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Пароль должен содержать от 8 до 128 символов' });
  const existing = await prisma.employee.findUnique({ where: { login } });
  if (existing && existing.id !== activation.employeeId) return res.status(409).json({ error: 'Этот логин уже занят' });
  await prisma.$transaction(async tx => {
    await tx.employee.update({ where: { id: activation.employeeId }, data: { login, passwordHash: hashPassword(password) } });
    await tx.employeeActivation.delete({ where: { id: activation.id } });
  });
  res.json({ ok: true, message: 'Личный кабинет активирован. Теперь вы можете войти.' });
}));

// Разделённая защита: сотрудник видит только собственные данные, остальные API доступны руководителю.
app.use('/api', (req, res, next) => {
  if (req.path === '/health' || req.path.startsWith('/auth/') || req.path.startsWith('/employee-auth/') || req.path.startsWith('/public/')) return next();
  if (req.path.startsWith('/employee/')) {
    const session = readSession(getCookie(req, EMPLOYEE_COOKIE));
    if (!session || session.role !== 'employee') return res.status(401).json({ error: 'Требуется вход сотрудника' });
    req.employeeId = session.sub;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return sameOrigin(req, res, next);
    return next();
  }
  if (!validSession(getCookie(req, SESSION_COOKIE), 'admin', ADMIN_USERNAME)) return res.status(401).json({ error: 'Требуется авторизация руководителя' });
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return sameOrigin(req, res, next);
  next();
});

app.get('/api/employee/me', asyncRoute(async (req, res) => {
  const employee = await prisma.employee.findUnique({ where: { id: req.employeeId }, include: { branch: true } });
  if (!employee || employee.status !== 'Работает' || !employee.login || !employee.passwordHash) return res.status(403).json({ error: 'Доступ к кабинету приостановлен' });
  res.json({ id: employee.id, fullName: employee.fullName, phone: employee.phone, position: employee.position, status: employee.status, hireDate: employee.hireDate, branch: employee.branch?.name, login: employee.login });
}));
app.get('/api/employee/shifts', asyncRoute(async (req, res) => {
  const activeEmployee = await prisma.employee.findUnique({ where: { id: req.employeeId }, select: { status: true, login: true, passwordHash: true } });
  if (!activeEmployee || activeEmployee.status !== 'Работает' || !activeEmployee.login || !activeEmployee.passwordHash) return res.status(403).json({ error: 'Доступ к кабинету приостановлен' });
  const shifts = await prisma.shift.findMany({ where: { employeeId: req.employeeId }, include: { shiftType: true }, orderBy: { workDate: 'desc' }, take: 250 });
  res.json(shifts.map(s => ({ id: s.id, workDate: s.workDate, startedAt: s.startedAt, endedAt: s.endedAt, amount: s.amount, comment: s.comment, status: s.status, shiftType: s.shiftType?.name })));
}));
const hashToken = token => createHash('sha256').update(token).digest('hex');
const cleanText = value => String(value || '').trim();

// Руководитель создаёт ссылку для самостоятельного заполнения анкеты.
app.post('/api/invites', asyncRoute(async (req, res) => {
  const branchId = cleanText(req.body.branchId);
  const days = Math.min(90, Math.max(1, Number(req.body.daysValid) || 30));
  if (!branchId) return res.status(400).json({ error: 'Выберите филиал' });
  const branch = await prisma.branch.findUnique({ where: { id: branchId } });
  if (!branch || !branch.active) return res.status(404).json({ error: 'Филиал не найден или отключён' });
  const token = randomBytes(32).toString('base64url');
  const invite = await prisma.employeeInvite.create({ data: {
    tokenHash: hashToken(token), branchId,
    expiresAt: new Date(Date.now() + days * 24 * 60 * 60 * 1000)
  }, include: { branch: true } });
  res.status(201).json({ id: invite.id, branch: invite.branch.name, expiresAt: invite.expiresAt, url: `${req.protocol}://${req.get('host')}/anketa/${token}` });
}));

app.get('/api/public/invites/:token', asyncRoute(async (req, res) => {
  const invite = await prisma.employeeInvite.findUnique({ where: { tokenHash: hashToken(req.params.token) }, include: { branch: true } });
  if (!invite || !invite.active || invite.expiresAt <= new Date() || !invite.branch.active) return res.status(404).json({ error: 'Ссылка недействительна или срок её действия истёк' });
  res.json({ branch: invite.branch.name, expiresAt: invite.expiresAt });
}));

app.post('/api/public/invites/:token/applications', asyncRoute(async (req, res) => {
  const invite = await prisma.employeeInvite.findUnique({ where: { tokenHash: hashToken(req.params.token) }, include: { branch: true } });
  if (!invite || !invite.active || invite.expiresAt <= new Date() || !invite.branch.active) return res.status(404).json({ error: 'Ссылка недействительна или срок её действия истёк' });
  const fullName = cleanText(req.body.fullName);
  const phone = cleanText(req.body.phone);
  if (fullName.length < 3 || phone.length < 5) return res.status(400).json({ error: 'Укажите ФИО и корректный номер телефона' });
  const application = await prisma.employeeApplication.create({ data: {
    inviteId: invite.id, branchId: invite.branchId, fullName, phone,
    birthDate: req.body.birthDate ? new Date(req.body.birthDate) : null,
    position: cleanText(req.body.position) || null,
    hireDate: req.body.hireDate ? new Date(req.body.hireDate) : null,
    notes: cleanText(req.body.notes) || null
  } });
  res.status(201).json({ ok: true, id: application.id, message: 'Анкета отправлена руководителю на проверку' });
}));

app.get('/api/applications', asyncRoute(async (req, res) => res.json(await prisma.employeeApplication.findMany({ include: { branch: true }, orderBy: { createdAt: 'desc' } }))));
app.get('/api/invites', asyncRoute(async (req, res) => res.json(await prisma.employeeInvite.findMany({ include: { branch: true, _count: { select: { applications: true } } }, orderBy: { createdAt: 'desc' } }))));
app.patch('/api/applications/:id', asyncRoute(async (req, res) => {
  const status = cleanText(req.body.status);
  if (!['Одобрена', 'Отклонена'].includes(status)) return res.status(400).json({ error: 'Неизвестное решение' });
  const application = await prisma.employeeApplication.findUnique({ where: { id: req.params.id }, include: { branch: true } });
  if (!application) return res.status(404).json({ error: 'Анкета не найдена' });
  if (application.status !== 'На проверке') return res.status(409).json({ error: 'Эта анкета уже обработана' });
  let activationUrl = null;
  if (status === 'Одобрена') {
    const token = randomBytes(32).toString('base64url');
    await prisma.$transaction(async tx => {
      const employee = await tx.employee.create({ data: { fullName: application.fullName, phone: application.phone, birthDate: application.birthDate, position: application.position, hireDate: application.hireDate, notes: application.notes, branchId: application.branchId, status: 'Работает' } });
      await tx.employeeActivation.create({ data: { employeeId: employee.id, tokenHash: hashToken(token), expiresAt: new Date(Date.now() + 72 * 60 * 60 * 1000) } });
      await tx.employeeApplication.update({ where: { id: application.id }, data: { status, reviewedAt: new Date() } });
    });
    activationUrl = `${req.protocol}://${req.get('host')}/activate/${token}`;
  } else {
    await prisma.employeeApplication.update({ where: { id: application.id }, data: { status, reviewedAt: new Date() } });
  }
  res.json({ ok: true, status, activationUrl });
}));

app.patch('/api/invites/:id', asyncRoute(async (req, res) => {
  const invite = await prisma.employeeInvite.update({ where: { id: req.params.id }, data: { active: Boolean(req.body.active) } });
  res.json(invite);
}));

app.get('/api/branches', asyncRoute(async (req,res) => res.json(await prisma.branch.findMany({ orderBy: { name: 'asc' } }))));
app.post('/api/branches', asyncRoute(async (req,res) => {
  const name = String(req.body.name || '').trim(); if (!name) return res.status(400).json({ error: 'Укажите название филиала' });
  res.status(201).json(await prisma.branch.create({ data: { name, address: req.body.address || null } }));
}));
app.get('/api/employees', asyncRoute(async (req,res) => { const rows = await prisma.employee.findMany({ include: { branch: true, rates: { include: { shiftType: true } } }, orderBy: { fullName: 'asc' } }); res.json(rows.map(({ passwordHash, ...employee }) => employee)); }));
app.post('/api/employees', asyncRoute(async (req,res) => {
  const { fullName, branchId } = req.body;
  if (!String(fullName || '').trim() || !branchId) return res.status(400).json({ error: 'ФИО и филиал обязательны' });
  const employee = await prisma.employee.create({ data: {
    fullName: String(fullName).trim(), branchId, phone: req.body.phone || null,
    position: req.body.position || null, status: req.body.status || 'Работает',
    hireDate: req.body.hireDate ? new Date(req.body.hireDate) : null, notes: req.body.notes || null
  }, include: { branch: true, rates: { include: { shiftType: true } } } });
  res.status(201).json(employee);
}));
app.patch('/api/employees/:id', asyncRoute(async (req,res) => {
  const allowed = ['fullName','phone','position','status','notes','branchId'];
  const data = Object.fromEntries(allowed.filter(k => req.body[k] !== undefined).map(k => [k, req.body[k]]));
  if (req.body.hireDate !== undefined) data.hireDate = req.body.hireDate ? new Date(req.body.hireDate) : null;
  const updated = await prisma.employee.update({ where: { id: req.params.id }, data, include: { branch: true, rates: { include: { shiftType: true } } } }); const { passwordHash, ...safeEmployee } = updated; res.json(safeEmployee);
}));
app.get('/api/shift-types', asyncRoute(async (req,res) => res.json(await prisma.shiftType.findMany({ where: { active: true }, orderBy: { name: 'asc' } }))));
app.post('/api/shift-types', asyncRoute(async (req,res) => {
  const name = String(req.body.name || '').trim(); if (!name) return res.status(400).json({ error: 'Укажите название типа смены' });
  res.status(201).json(await prisma.shiftType.create({ data: { name } }));
}));
app.put('/api/employees/:id/rates', asyncRoute(async (req,res) => {
  const { shiftTypeId, amount } = req.body;
  const n = Number(amount); if (!shiftTypeId || !Number.isFinite(n) || n < 0) return res.status(400).json({ error: 'Проверьте тип смены и сумму' });
  const rate = await prisma.employeeRate.upsert({ where: { employeeId_shiftTypeId: { employeeId: req.params.id, shiftTypeId } }, update: { amount: n }, create: { employeeId: req.params.id, shiftTypeId, amount: n } });
  res.json(rate);
}));
app.get('/api/shifts', asyncRoute(async (req,res) => {
  const where = {};
  if (req.query.from || req.query.to) where.workDate = { ...(req.query.from ? { gte: new Date(req.query.from) } : {}), ...(req.query.to ? { lte: new Date(req.query.to + 'T23:59:59.999Z') } : {}) };
  if (req.query.branchId) where.employee = { branchId: req.query.branchId };
  res.json(await prisma.shift.findMany({ where, include: { employee: { include: { branch: true } }, shiftType: true }, orderBy: { workDate: 'desc' } }));
}));
app.post('/api/shifts', asyncRoute(async (req,res) => {
  const { employeeId, shiftTypeId, workDate, startedAt, endedAt, comment } = req.body;
  if (!employeeId || !shiftTypeId || !workDate) return res.status(400).json({ error: 'Сотрудник, тип смены и дата обязательны' });
  const rate = await prisma.employeeRate.findUnique({ where: { employeeId_shiftTypeId: { employeeId, shiftTypeId } } });
  if (!rate) return res.status(400).json({ error: 'Для сотрудника не задана стоимость этого типа смены' });
  const shift = await prisma.shift.create({ data: { employeeId, shiftTypeId, workDate: new Date(workDate), startedAt: startedAt || null, endedAt: endedAt || null, amount: rate.amount, comment: comment || null }, include: { employee: true, shiftType: true } });
  res.status(201).json(shift);
}));
app.get('/api/summary', asyncRoute(async (req,res) => {
  const now = new Date(); const from = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)); const to = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth()+1, 1));
  const [employees, branches, shifts] = await Promise.all([
    prisma.employee.count({ where: { status: 'Работает' } }), prisma.branch.count({ where: { active: true } }),
    prisma.shift.findMany({ where: { workDate: { gte: from, lt: to } }, select: { amount: true } })
  ]);
  res.json({ employees, branches, shifts: shifts.length, payroll: shifts.reduce((sum,s) => sum + Number(s.amount), 0) });
}));

app.use('/api', (err, req, res, next) => { console.error(err); res.status(400).json({ error: err.message || 'Ошибка сервера' }); });
app.use(express.static(path.join(__dirname, 'dist')));
app.get(/.*/, (req,res,next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});
app.listen(PORT, '0.0.0.0', () => console.log(`HR Manager server listening on ${PORT}`));
