import { readEdgeEnvironment } from "../_shared/environment.mjs";
import { createClient } from "npm:@supabase/supabase-js@2.112.0";
import { createSupabasePairingDependencies } from "./adapter.mjs";
import { createPairingEdgeHandler } from "./core.mjs";

const dependencies = createSupabasePairingDependencies({ createClient, env: readEdgeEnvironment((name: string) => Deno.env.get(name)) });
Deno.serve(createPairingEdgeHandler(dependencies));
