import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3001;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
app.use(cors());
app.use(express.json());
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'HR Manager' }));
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
