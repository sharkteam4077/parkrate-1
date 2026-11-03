import express from 'express';
import path from 'node:path';
import { createHash, randomBytes, randomUUID, createHmac, timingSafeEqual, scryptSync } from 'node:crypto';
import { S3Client, PutObjectCommand, HeadObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();
// Railway terminates HTTPS at its proxy; trust forwarded headers so invite links use https.
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;
const b2Configured = Boolean(process.env.B2_KEY_ID && process.env.B2_APPLICATION_KEY && process.env.B2_BUCKET_NAME && process.env.B2_ENDPOINT && process.env.B2_REGION);
let b2Client;
function getB2Client() {
  if (!b2Configured) throw new Error('Backblaze B2 не настроен. Проверьте переменные B2_KEY_ID, B2_APPLICATION_KEY, B2_BUCKET_NAME, B2_ENDPOINT и B2_REGION в Railway.');
  if (!b2Client) b2Client = new S3Client({
    region: process.env.B2_REGION,
    endpoint: process.env.B2_ENDPOINT.startsWith('http') ? process.env.B2_ENDPOINT : `https://${process.env.B2_ENDPOINT}`,
    forcePathStyle: true,
    credentials: { accessKeyId: process.env.B2_KEY_ID, secretAccessKey: process.env.B2_APPLICATION_KEY }
  });
  return b2Client;
}
const b2Bucket = () => process.env.B2_BUCKET_NAME;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Large media payloads are accepted; practical limits are imposed by Railway/browser resources.
app.use(express.json({ limit: '2mb' }));
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'ПаркРайт' }));
let locationsImport;
async function ensureLocationsImported() {
  if (!locationsImport) locationsImport = (async () => {
    const rows = JSON.parse(await readFile(path.join(__dirname, 'data', 'locations.json'), 'utf8'));
    const count = await prisma.location.count();
    if (count < rows.length) for (let i=0; i<rows.length; i+=500) {
      await prisma.location.createMany({ data: rows.slice(i,i+500), skipDuplicates: true });
    }
    return rows.length;
  })().catch(err => { locationsImport = null; throw err; });
  return locationsImport;
}

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
  res.json({ id: employee.id, fullName: employee.fullName, phone: employee.phone, birthYear: employee.birthYear, telegramUsername: employee.telegramUsername, position: employee.position, status: employee.status, hireDate: employee.hireDate, branch: employee.branch?.name, branchCity: employee.branch?.city || employee.branch?.name, login: employee.login });
}));
app.get('/api/employee/tasks', asyncRoute(async (req, res) => {
  const activeEmployee = await prisma.employee.findUnique({ where: { id: req.employeeId }, select: { status: true, login: true, passwordHash: true } });
  if (!activeEmployee || activeEmployee.status !== 'Работает' || !activeEmployee.login || !activeEmployee.passwordHash) return res.status(403).json({ error: 'Доступ к кабинету приостановлен' });
  const tasks = await prisma.task.findMany({ where: { employeeId: req.employeeId }, include: { location: true, reports: { where: { employeeId: req.employeeId }, orderBy: { createdAt: 'desc' }, take: 1 } }, orderBy: [{ dueDate: 'asc' }, { createdAt: 'desc' }] });
  res.json(tasks);
}));
app.post('/api/employee/tasks/:id/reports/upload-urls', asyncRoute(async (req, res) => {
  const task = await prisma.task.findFirst({ where: { id: req.params.id, employeeId: req.employeeId } });
  if (!task) return res.status(404).json({ error: 'Задание не найдено' });
  if (task.status === 'Выполнено') return res.status(409).json({ error: 'Задание уже принято и закрыто' });
  const files = Array.isArray(req.body.files) ? req.body.files : [];
  if (!files.length) return res.status(400).json({ error: 'Выберите фотографии или видео' });
  const s3 = getB2Client();
  const uploads = await Promise.all(files.map(async file => {
    const type = String(file?.type || '').toLowerCase();
    if (!/^(image|video)\//.test(type)) throw new Error('Разрешены только фотографии и видео');
    const name = String(file?.name || 'file').slice(0, 240);
    const key = `reports/${req.employeeId}/${task.id}/${randomUUID()}`;
    const command = new PutObjectCommand({ Bucket: b2Bucket(), Key: key, ContentType: type });
    const url = await getSignedUrl(s3, command, { expiresIn: 900 });
    return { key, url, headers: { 'Content-Type': type }, type, name, size: Number(file?.size) || 0 };
  }));
  res.json({ uploads });
}));

app.post('/api/employee/tasks/:id/reports', asyncRoute(async (req, res) => {
  const task = await prisma.task.findFirst({ where: { id: req.params.id, employeeId: req.employeeId } });
  if (!task) return res.status(404).json({ error: 'Задание не найдено' });
  if (task.status === 'Выполнено') return res.status(409).json({ error: 'Задание уже принято и закрыто' });
  const latitude = Number(req.body.latitude), longitude = Number(req.body.longitude);
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 || !Number.isFinite(longitude) || longitude < -180 || longitude > 180) return res.status(400).json({ error: 'Сначала определите местоположение на объекте' });
  const media = Array.isArray(req.body.media) ? req.body.media : [];
  if (!media.length) return res.status(400).json({ error: 'Добавьте хотя бы одну фотографию или видеозапись' });
  const s3 = getB2Client();
  const verifiedMedia = await Promise.all(media.map(async item => {
    if (!item || typeof item.key !== 'string' || !item.key.startsWith(`reports/${req.employeeId}/${task.id}/`) || typeof item.type !== 'string' || !/^(image|video)\//i.test(item.type)) throw new Error('Некорректные данные вложения. Загрузите файлы повторно.');
    const head = await s3.send(new HeadObjectCommand({ Bucket: b2Bucket(), Key: item.key }));
    if (!head.ContentLength) throw new Error('Одно из вложений не найдено в хранилище. Повторите загрузку.');
    return { key: item.key, type: item.type, name: String(item.name || 'file').slice(0, 240), size: head.ContentLength };
  }));
  const latest = await prisma.taskReport.findFirst({ where: { taskId: task.id, employeeId: req.employeeId }, orderBy: { createdAt: 'desc' } });
  if (latest?.status === 'На проверке' || latest?.status === 'Принят') return res.status(409).json({ error: 'Отчёт уже находится на проверке или принят' });
  const report = await prisma.taskReport.create({ data: { taskId: task.id, employeeId: req.employeeId, result: 'Фото- и видеоподтверждение выполнения на локации', comment: null, hoursSpent: null, latitude, longitude, mediaJson: JSON.stringify(verifiedMedia), status: 'На проверке' } });
  await prisma.task.update({ where: { id: task.id }, data: { status: 'На проверке', completedAt: null } });
  res.status(201).json(report);
}));

app.patch('/api/employee/tasks/:id', asyncRoute(async (req, res) => {
  const task = await prisma.task.findFirst({ where: { id: req.params.id, employeeId: req.employeeId } });
  if (!task) return res.status(404).json({ error: 'Задание не найдено' });
  const status = cleanText(req.body.status);
  if (status !== 'В работе') return res.status(400).json({ error: 'Завершение задания возможно только после отправки и принятия отчёта' });
  const updated = await prisma.task.update({ where: { id: task.id }, data: { status, employeeComment: cleanText(req.body.employeeComment).slice(0, 2000) || null, completedAt: null } });
  res.json(updated);
}));

app.get('/api/employee/locations', asyncRoute(async (req,res) => {
  await ensureLocationsImported();
  const rows = await prisma.location.findMany({ orderBy: [{city:'asc'},{district:'asc'}], take: 7000 });
  const busy = await prisma.locationSelection.findMany({ where:{status:{in:['На проверке','Одобрена']}}, select:{locationId:true,status:true} });
  const states = new Map(busy.map(x=>[x.locationId,x.status]));
  res.json(rows.map(x=>({...x,availability:states.get(x.id)||'Доступен'})));
}));
app.get('/api/employee/location-selections', asyncRoute(async (req,res) => {
  res.json(await prisma.locationSelection.findMany({where:{employeeId:req.employeeId},include:{location:true},orderBy:{createdAt:'desc'}}));
}));
app.post('/api/employee/location-selections', asyncRoute(async (req,res) => {
  const locationId = cleanText(req.body.locationId);
  if (!locationId) return res.status(400).json({error:'Выберите объект на карте'});
  const location = await prisma.location.findUnique({where:{id:locationId}});
  if (!location) return res.status(404).json({error:'Объект не найден'});
  const previous = await prisma.locationSelection.findFirst({where:{employeeId:req.employeeId,status:{in:['На проверке','Одобрена']}}});
  if (previous) return res.status(409).json({error:'У вас уже есть запрос на проверке или одобренный объект'});
  const occupied = await prisma.locationSelection.findFirst({where:{locationId,status:{in:['На проверке','Одобрена']}}});
  if (occupied) return res.status(409).json({error:'Этот объект уже выбран или ожидает проверки'});
  const result = await prisma.locationSelection.create({data:{employeeId:req.employeeId,locationId},include:{location:true}});
  res.status(201).json(result);
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
  if (fullName.length < 3 || phone.length < 5) return res.status(400).json({ error: 'Укажите фамилию, имя и корректный номер телефона' });
  const birthYear = req.body.birthYear ? Number.parseInt(req.body.birthYear, 10) : null;
  if (birthYear !== null && (!Number.isInteger(birthYear) || birthYear < 1900 || birthYear > new Date().getFullYear())) return res.status(400).json({ error: 'Укажите корректный год рождения' });
  const application = await prisma.employeeApplication.create({ data: {
    inviteId: invite.id, branchId: invite.branchId, fullName, phone,
    birthYear: req.body.birthYear ? Number.parseInt(req.body.birthYear, 10) : null,
    telegramUsername: cleanText(req.body.telegramUsername).replace(/^@/, '') || null
  } });
  res.status(201).json({ ok: true, id: application.id, message: 'Анкета отправлена руководителю на проверку' });
}));

app.get('/api/applications', asyncRoute(async (req, res) => res.json(await prisma.employeeApplication.findMany({ include: { branch: true }, orderBy: { createdAt: 'desc' } }))));
app.get('/api/invites', asyncRoute(async (req, res) => res.json(await prisma.employeeInvite.findMany({ include: { branch: true, _count: { select: { applications: true } } }, orderBy: { createdAt: 'desc' } }))));
app.delete('/api/applications/:id', asyncRoute(async (req, res) => {
  const row = await prisma.employeeApplication.findUnique({ where: { id: req.params.id } });
  if (!row) return res.status(404).json({ error: 'Анкета не найдена' });
  if (row.status === 'Одобрена') return res.status(409).json({ error: 'Одобренная анкета связана с созданным сотрудником. Удалите сотрудника отдельно; история анкеты сохранена.' });
  await prisma.employeeApplication.delete({ where: { id: row.id } });
  res.json({ ok: true });
}));
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
      const employee = await tx.employee.create({ data: { fullName: application.fullName, phone: application.phone, birthYear: application.birthYear, telegramUsername: application.telegramUsername, branchId: application.branchId, status: 'Работает' } });
      await tx.employeeActivation.create({ data: { employeeId: employee.id, tokenHash: hashToken(token), expiresAt: new Date(Date.now() + 72 * 60 * 60 * 1000) } });
      await tx.employeeApplication.update({ where: { id: application.id }, data: { status, reviewedAt: new Date() } });
    });
    activationUrl = `${req.protocol}://${req.get('host')}/activate/${token}`;
  } else {
    await prisma.employeeApplication.update({ where: { id: application.id }, data: { status, reviewedAt: new Date() } });
  }
  res.json({ ok: true, status, activationUrl });
}));

app.delete('/api/invites/:id', asyncRoute(async (req, res) => {
  const invite = await prisma.employeeInvite.findUnique({ where: { id: req.params.id }, include: { _count: { select: { applications: true } } } });
  if (!invite) return res.status(404).json({ error: 'Приглашение не найдено' });
  await prisma.employeeInvite.delete({ where: { id: invite.id } });
  res.json({ ok: true, deletedApplications: invite._count.applications });
}));
app.patch('/api/invites/:id', asyncRoute(async (req, res) => {
  const invite = await prisma.employeeInvite.update({ where: { id: req.params.id }, data: { active: Boolean(req.body.active) } });
  res.json(invite);
}));

app.get('/api/branches', asyncRoute(async (req,res) => res.json(await prisma.branch.findMany({ orderBy: { name: 'asc' } }))));
app.post('/api/branches', asyncRoute(async (req,res) => {
  const name = String(req.body.name || '').trim(); const city = String(req.body.city || '').trim(); if (!name) return res.status(400).json({ error: 'Укажите название филиала' });
  if (!city) return res.status(400).json({ error: 'Укажите город филиала' });
  res.status(201).json(await prisma.branch.create({ data: { name, city, address: req.body.address || null } }));
}));
app.delete('/api/branches/:id', asyncRoute(async (req,res) => {
  const branch = await prisma.branch.findUnique({ where: { id: req.params.id }, include: { _count: { select: { employees: true, invites: true, applications: true } } } });
  if (!branch) return res.status(404).json({ error: 'Филиал не найден' });
  if (branch._count.employees || branch._count.invites || branch._count.applications) return res.status(409).json({ error: `Нельзя удалить филиал: связанные записи — сотрудники: ${branch._count.employees}, приглашения: ${branch._count.invites}, анкеты: ${branch._count.applications}. Сначала удалите или перенесите их.` });
  await prisma.branch.delete({ where: { id: branch.id } });
  res.json({ ok: true });
}));
app.patch('/api/branches/:id', asyncRoute(async (req,res) => {
  const city = String(req.body.city || '').trim();
  if (!city) return res.status(400).json({ error: 'Укажите город филиала' });
  res.json(await prisma.branch.update({ where: { id: req.params.id }, data: { city } }));
}));
app.get('/api/employees', asyncRoute(async (req,res) => { const rows = await prisma.employee.findMany({ include: { branch: true }, orderBy: { fullName: 'asc' } }); res.json(rows.map(({ passwordHash, ...employee }) => employee)); }));
app.post('/api/employees', asyncRoute(async (req,res) => {
  const { fullName, branchId } = req.body;
  if (!String(fullName || '').trim() || !branchId) return res.status(400).json({ error: 'ФИО и филиал обязательны' });
  const employee = await prisma.employee.create({ data: {
    fullName: String(fullName).trim(), branchId, phone: req.body.phone || null,
    position: req.body.position || null, status: req.body.status || 'Работает',
    hireDate: req.body.hireDate ? new Date(req.body.hireDate) : null, notes: req.body.notes || null
  }, include: { branch: true } });
  res.status(201).json(employee);
}));
app.delete('/api/employees/:id', asyncRoute(async (req,res) => {
  const employee = await prisma.employee.findUnique({ where: { id: req.params.id } });
  if (!employee) return res.status(404).json({ error: 'Сотрудник не найден' });
  await prisma.$transaction(async tx => {
    await tx.shift.deleteMany({ where: { employeeId: employee.id } });
    await tx.employee.delete({ where: { id: employee.id } });
  });
  res.json({ ok: true });
}));
app.patch('/api/employees/:id', asyncRoute(async (req,res) => {
  const allowed = ['fullName','phone','position','status','notes','branchId'];
  const data = Object.fromEntries(allowed.filter(k => req.body[k] !== undefined).map(k => [k, req.body[k]]));
  if (req.body.hireDate !== undefined) data.hireDate = req.body.hireDate ? new Date(req.body.hireDate) : null;
  const updated = await prisma.employee.update({ where: { id: req.params.id }, data, include: { branch: true } }); const { passwordHash, ...safeEmployee } = updated; res.json(safeEmployee);
}));
app.get('/api/tasks', asyncRoute(async (req, res) => {
  const tasks = await prisma.task.findMany({ include: { employee: { include: { branch: true } }, location: true, locationSelection: true }, orderBy: [{ dueDate: 'asc' }, { createdAt: 'desc' }] });
  res.json(tasks);
}));
app.post('/api/tasks', asyncRoute(async (req, res) => {
  const employeeId = cleanText(req.body.employeeId);
  const title = cleanText(req.body.title);
  const description = cleanText(req.body.description);
  if (!employeeId || title.length < 3) return res.status(400).json({ error: 'Выберите сотрудника и укажите название задания (не менее 3 символов)' });
  const employee = await prisma.employee.findUnique({ where: { id: employeeId } });
  if (!employee || employee.status !== 'Работает') return res.status(404).json({ error: 'Активный сотрудник не найден' });
  const dueDate = req.body.dueDate ? new Date(req.body.dueDate) : null;
  if (dueDate && Number.isNaN(dueDate.getTime())) return res.status(400).json({ error: 'Некорректный срок выполнения' });
  const task = await prisma.task.create({ data: { employeeId, title, description: description || null, dueDate } , include: { employee: { include: { branch: true } }, location: true } });
  res.status(201).json(task);
}));
app.delete('/api/tasks/:id', asyncRoute(async (req, res) => {
  const task = await prisma.task.findUnique({ where: { id: req.params.id } });
  if (!task) return res.status(404).json({ error: 'Задание не найдено' });
  await prisma.task.delete({ where: { id: task.id } });
  res.json({ ok: true });
}));
app.patch('/api/tasks/:id', asyncRoute(async (req, res) => {
  const status = cleanText(req.body.status);
  if (!['Новое', 'В работе', 'Требует доработки'].includes(status)) return res.status(400).json({ error: 'Завершить задание можно только после принятия отчёта' });
  const task = await prisma.task.update({ where: { id: req.params.id }, data: { status, completedAt: null }, include: { employee: { include: { branch: true } } } });
  res.json(task);
}));


app.get('/api/reports', asyncRoute(async (req, res) => {
  const reports = await prisma.taskReport.findMany({ include: { task: true, employee: { include: { branch: true } } }, orderBy: [{ status: 'asc' }, { createdAt: 'desc' }] });
  const s3 = b2Configured ? getB2Client() : null;
  const result = await Promise.all(reports.map(async r => {
    let media = []; try { media = JSON.parse(r.mediaJson || '[]'); } catch {}
    media = await Promise.all(media.map(async item => {
      if (!item?.key || !s3) return item;
      const data = await getSignedUrl(s3, new GetObjectCommand({ Bucket: b2Bucket(), Key: item.key }), { expiresIn: 3600 });
      return { ...item, data };
    }));
    return { ...r, media };
  }));
  res.json(result);
}));
app.patch('/api/reports/:id', asyncRoute(async (req, res) => {
  const status = cleanText(req.body.status);
  if (!['Принят', 'Требует доработки'].includes(status)) return res.status(400).json({ error: 'Выберите решение по отчёту' });
  const report = await prisma.taskReport.findUnique({ where: { id: req.params.id } });
  if (!report) return res.status(404).json({ error: 'Отчёт не найден' });
  if (report.status !== 'На проверке') return res.status(409).json({ error: 'Этот отчёт уже проверен' });
  const adminComment = cleanText(req.body.adminComment).slice(0, 2000) || null;
  if (status === 'Требует доработки' && !adminComment) return res.status(400).json({ error: 'Укажите, что необходимо исправить' });
  const updated = await prisma.$transaction(async tx => {
    const row = await tx.taskReport.update({ where: { id: report.id }, data: { status, adminComment, reviewedAt: new Date() } });
    await tx.task.update({ where: { id: report.taskId }, data: { status: status === 'Принят' ? 'Выполнено' : 'Требует доработки', completedAt: status === 'Принят' ? new Date() : null } });
    return row;
  });
  res.json(updated);
}));

app.get('/api/location-selections', asyncRoute(async (req,res) => res.json(await prisma.locationSelection.findMany({
  include:{employee:{include:{branch:true}},location:true},orderBy:[{status:'asc'},{createdAt:'desc'}]
}))));
app.delete('/api/location-selections/:id', asyncRoute(async (req,res) => {
  const row = await prisma.locationSelection.findUnique({ where: { id: req.params.id } });
  if (!row) return res.status(404).json({ error: 'Заявка не найдена' });
  await prisma.locationSelection.delete({ where: { id: row.id } });
  res.json({ ok: true });
}));
app.patch('/api/location-selections/:id', asyncRoute(async (req,res) => {
  const status=cleanText(req.body.status);
  if(!['Одобрена','Отклонена'].includes(status)) return res.status(400).json({error:'Недопустимое решение'});
  const current=await prisma.locationSelection.findUnique({where:{id:req.params.id},include:{employee:true,location:true}});
  if(!current) return res.status(404).json({error:'Запрос не найден'});
  if(current.status!=='На проверке') return res.status(409).json({error:'Запрос уже рассмотрен'});
  if(status==='Одобрена'){
    const conflict=await prisma.locationSelection.findFirst({where:{locationId:current.locationId,status:'Одобрена',id:{not:current.id}}});
    if(conflict) return res.status(409).json({error:'Объект уже одобрен другому сотруднику'});
  }
  const result = await prisma.$transaction(async tx => {
    // The selection link is indexed but deliberately not UNIQUE: older databases may
    // contain duplicate links. Idempotency is enforced here without destructive db push.
    const existingTask = status === 'Одобрена'
      ? await tx.task.findFirst({where:{locationSelectionId:current.id},include:{employee:{include:{branch:true}},location:true}})
      : null;
    const changed = await tx.locationSelection.updateMany({
      where:{id:current.id,status:'На проверке'},
      data:{status,adminComment:cleanText(req.body.adminComment).slice(0,1000)||null,reviewedAt:new Date()}
    });
    if (changed.count !== 1) return { conflict: true };
    let task = null;
    if (status === 'Одобрена') {
      task = existingTask || await tx.task.create({data:{
        employeeId: current.employeeId,
        title: `Работа на объекте: ${current.location.district || current.location.city || 'Выбранная локация'}`,
        description: `Выполнить работу на выбранном объекте.\nОбъект: ${current.location.district || '—'}\nГород: ${current.location.city || '—'}\nРегион: ${current.location.region || '—'}\nКоординаты: ${current.location.latitude}, ${current.location.longitude}`,
        locationId: current.locationId,
        adminUsername: ADMIN_USERNAME,
        locationSelectionId: current.id,
        status: 'В работе'
      }, include:{employee:{include:{branch:true}},location:true}});
    }
    const updated = await tx.locationSelection.findUnique({where:{id:current.id}});
    return { ...updated, task };
  });
  if (result.conflict) return res.status(409).json({error:'Заявка уже была рассмотрена другим запросом'});
  res.json({...result, employee:current.employee, location:current.location});
}));

app.get('/api/summary', asyncRoute(async (req,res) => {
  const [employees, branches, tasks, completedTasks] = await Promise.all([
    prisma.employee.count({ where: { status: 'Работает' } }),
    prisma.branch.count({ where: { active: true } }),
    prisma.task.count(),
    prisma.task.count({ where: { status: 'Выполнено' } })
  ]);
  res.json({ employees, branches, tasks, completedTasks });
}));

app.use('/api', (err, req, res, next) => { console.error(err); res.status(400).json({ error: err.message || 'Ошибка сервера' }); });
app.use(express.static(path.join(__dirname, 'dist')));
app.get(/.*/, (req,res,next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});
app.listen(PORT, '0.0.0.0', () => console.log(`ПаркРайт server listening on ${PORT}`));
