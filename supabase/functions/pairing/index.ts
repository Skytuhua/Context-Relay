import { createClient } from "npm:@supabase/supabase-js@2.112.0";
import { createSupabasePairingDependencies } from "./adapter.mjs";
import { createPairingEdgeHandler } from "./core.mjs";

const dependencies = createSupabasePairingDependencies({ createClient, env: {
  SUPABASE_URL: Deno.env.get("SUPABASE_URL") ?? "",
  SUPABASE_PUBLISHABLE_KEY: Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? "",
  CONTEXT_RELAY_SUPABASE_SECRET_KEY: Deno.env.get("CONTEXT_RELAY_SUPABASE_SECRET_KEY") ?? "",
  CONTEXT_RELAY_PAIRING_PEPPER: Deno.env.get("CONTEXT_RELAY_PAIRING_PEPPER") ?? "",
} });
Deno.serve(createPairingEdgeHandler(dependencies));
