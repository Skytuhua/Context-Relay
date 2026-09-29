import { readEdgeEnvironment } from "../_shared/environment.mjs";
import { createClient } from "npm:@supabase/supabase-js@2.112.0";

import { createSupabaseSyncDependencies } from "./adapter.mjs";
import { createSyncEdgeHandler } from "./core.mjs";

const dependencies = createSupabaseSyncDependencies({
  createClient,
  env: readEdgeEnvironment((name: string) => Deno.env.get(name)),
});
const handler = createSyncEdgeHandler(dependencies);

Deno.serve(handler);
