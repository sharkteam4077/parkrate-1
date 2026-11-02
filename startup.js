import { PrismaClient } from '@prisma/client';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const prisma = new PrismaClient();
const run = promisify(execFile);

async function runCommand(command, args) {
  console.log(`> ${command} ${args.join(' ')}`);
  try {
    const { stdout, stderr } = await run(command, args, {
      cwd: process.cwd(),
      env: process.env,
      maxBuffer: 10 * 1024 * 1024
    });
    if (stdout) process.stdout.write(stdout);
    if (stderr) process.stderr.write(stderr);
  } catch (error) {
    if (error.stdout) process.stdout.write(error.stdout);
    if (error.stderr) process.stderr.write(error.stderr);
    throw error;
  }
}

try {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');

  // The marker lives outside the Prisma-managed public schema, so db push --force-reset
  // cannot erase it. A transaction-scoped advisory lock prevents parallel first boots.
  await prisma.$executeRawUnsafe('CREATE SCHEMA IF NOT EXISTS hr_manager_meta');
  await prisma.$executeRawUnsafe(`
    CREATE TABLE IF NOT EXISTS hr_manager_meta.bootstrap (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT pg_advisory_xact_lock(731904221)`;
    const rows = await tx.$queryRaw`SELECT id FROM hr_manager_meta.bootstrap WHERE id = 1`;
    const firstInstall = rows.length === 0;

    if (firstInstall) {
      console.log('Первый запуск HR Manager: инициализируем чистую схему базы данных.');
      await runCommand('npx', ['prisma', 'db', 'push', '--force-reset', '--accept-data-loss']);
      await runCommand(process.execPath, ['prisma/seed.js']);
      await tx.$executeRaw`INSERT INTO hr_manager_meta.bootstrap (id) VALUES (1) ON CONFLICT (id) DO NOTHING`;
      console.log('Первичная настройка базы данных завершена.');
    } else {
      console.log('Повторный запуск: обновляем схему без сброса данных.');
      await runCommand('npx', ['prisma', 'db', 'push']);
      await runCommand(process.execPath, ['prisma/seed.js']);
    }
  }, { maxWait: 30000, timeout: 300000 });
} catch (error) {
  console.error('Не удалось подготовить базу данных HR Manager:', error);
  process.exitCode = 1;
} finally {
  await prisma.$disconnect();
}

if (process.exitCode === 1) process.exit(1);
await import('./server.js');
