export type QueryRunner = <T>(text: string, params: unknown[]) => Promise<T[]>;
export type TransactionRunner = <T>(work: (run: QueryRunner) => Promise<T>) => Promise<T>;

export interface Sql {
  <T = Record<string, unknown>>(strings: TemplateStringsArray, ...values: unknown[]): Promise<T[]>;
  query<T = Record<string, unknown>>(text: string, params?: unknown[]): Promise<T[]>;
  transaction<T>(work: (sql: Sql) => Promise<T>): Promise<T>;
}

/** Transaction callbacks get a client pinned to one connection on both backends. */
export function createSqlClient(run: QueryRunner, transact?: TransactionRunner): Sql {
  const sql = (async <T>(strings: TemplateStringsArray, ...values: unknown[]) => {
    let text = strings[0];
    for (let i = 0; i < values.length; i++) text += `$${i + 1}${strings[i + 1]}`;
    return run<T>(text, values);
  }) as Sql;
  sql.query = <T>(text: string, params: unknown[] = []) => run<T>(text, params);
  sql.transaction = <T>(work: (sql: Sql) => Promise<T>) => {
    if (!transact) throw new Error("Nested transactions are not supported");
    return transact((txRun) => work(createSqlClient(txRun)));
  };
  return sql;
}
