import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
try {
  if (await prisma.branch.count() === 0) {
    const b = await prisma.branch.create({ data: { name: 'Главный филиал', address: '' } });
    const s1 = await prisma.shiftType.create({ data: { name: 'Дневная смена' } });
    const s2 = await prisma.shiftType.create({ data: { name: 'Ночная смена' } });
    const e = await prisma.employee.create({ data: { fullName: 'Демонстрационный сотрудник', position: 'Сотрудник', branchId: b.id } });
    await prisma.employeeRate.createMany({ data: [
      { employeeId: e.id, shiftTypeId: s1.id, amount: 3000 },
      { employeeId: e.id, shiftTypeId: s2.id, amount: 3500 }
    ] });
    console.log('Демо-данные созданы');
  }
} finally { await prisma.$disconnect(); }
