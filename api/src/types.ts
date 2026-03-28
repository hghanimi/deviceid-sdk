import type { QueryableDb } from './db';

export type AppEnv = {
  Bindings: {
    DATABASE_URL: string;
    OPENSANCTIONS_API_KEY?: string;
    SUPABASE_URL: string;
    SUPABASE_SERVICE_KEY: string;
    ANTHROPIC_API_KEY?: string;
  };
  Variables: {
    db: QueryableDb;
    apiKey: any;
  };
};
