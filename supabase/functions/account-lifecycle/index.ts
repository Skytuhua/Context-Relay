import { createClient } from "npm:@supabase/supabase-js@2.112.0";

import { createSupabaseAccountLifecycleDependencies } from "./adapter.mjs";
import { createAccountLifecycleEdgeHandler } from "./core.mjs";

const dependencies = createSupabaseAccountLifecycleDependencies({
  createClient,
  env: {
    SUPABASE_URL: Deno.env.get("SUPABASE_URL") ?? "",
    SUPABASE_PUBLISHABLE_KEY: Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? "",
    CONTEXT_RELAY_SUPABASE_SECRET_KEY:
      Deno.env.get("CONTEXT_RELAY_SUPABASE_SECRET_KEY") ?? "",
  },
});
const handler = createAccountLifecycleEdgeHandler(dependencies);

Deno.serve(handler);
