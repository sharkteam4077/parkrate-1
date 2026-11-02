import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();
// Railway terminates HTTPS at its proxy; trust forwarded headers so invite links use https.
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3001;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(cors());
app.use(express.json());
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'HR Manager' }));
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
  if (status === 'Одобрена') {
    await prisma.$transaction(async tx => {
      await tx.employee.create({ data: { fullName: application.fullName, phone: application.phone, birthDate: application.birthDate, position: application.position, hireDate: application.hireDate, notes: application.notes, branchId: application.branchId, status: 'Работает' } });
      await tx.employeeApplication.update({ where: { id: application.id }, data: { status, reviewedAt: new Date() } });
    });
  } else {
    await prisma.employeeApplication.update({ where: { id: application.id }, data: { status, reviewedAt: new Date() } });
  }
  res.json({ ok: true, status });
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
app.get('/api/employees', asyncRoute(async (req,res) => res.json(await prisma.employee.findMany({ include: { branch: true, rates: { include: { shiftType: true } } }, orderBy: { fullName: 'asc' } }))));
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
  res.json(await prisma.employee.update({ where: { id: req.params.id }, data, include: { branch: true, rates: { include: { shiftType: true } } } }));
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
