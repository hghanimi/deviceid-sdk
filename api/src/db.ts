import { Pool } from 'pg';

export type QueryableDb = {
  query: (text: string, values?: any[]) => Promise<any>;
};

let pool: Pool | null = null;

export function getPool(connectionString: string): Pool {
  if (!pool) {
    console.log('[db] creating new pool');
    pool = new Pool({
      connectionString,
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    });
  }
  return pool;
}

export function resetPool(): void {
  pool = null;
}

export function shouldRetryDbError(err: unknown): boolean {
  const msg = String((err as any)?.message || '').toLowerCase();
  return msg.includes('timeout exceeded when trying to connect')
    || msg.includes('connection terminated unexpectedly')
    || msg.includes('server closed the connection unexpectedly')
    || msg.includes('could not connect to server');
}

export function withDbTimeout<T>(promise: Promise<T>, ms = 12000): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error(`db query timeout after ${ms}ms`)), ms);
    }),
  ]);
}

export function getDb(connectionString: string): QueryableDb {
  const activePool = getPool(connectionString);
  return {
    query(text: string, values?: any[]) {
      return withDbTimeout(activePool.query(text, values));
    },
  };
}
