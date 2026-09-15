import { readEdgeEnvironment } from "../_shared/environment.mjs";
import { createClient } from "npm:@supabase/supabase-js@2.112.0";

import { createSupabaseAccountLifecycleDependencies } from "./adapter.mjs";
import { createAccountLifecycleEdgeHandler } from "./core.mjs";

const dependencies = createSupabaseAccountLifecycleDependencies({
  createClient,
  env: readEdgeEnvironment((name: string) => Deno.env.get(name)),
});
const handler = createAccountLifecycleEdgeHandler(dependencies);

Deno.serve(handler);
