import { readEdgeEnvironment } from "../_shared/environment.mjs";
import { createClient } from "npm:@supabase/supabase-js@2.112.0";
import { createSupabaseEnrollmentDependencies } from "./adapter.mjs";
import { createEnrollmentEdgeHandler } from "./core.mjs";

const dependencies = createSupabaseEnrollmentDependencies({ createClient, env: readEdgeEnvironment((name: string) => Deno.env.get(name)) });
Deno.serve(createEnrollmentEdgeHandler(dependencies));
