function key(get, overrideName, mapName) {
  const override = get(overrideName);
  if (override !== undefined) return override;
  try {
    const values = JSON.parse(get(mapName));
    if (values === null || Array.isArray(values) || !Object.hasOwn(values, "default") ||
        typeof values.default !== "string" || values.default.length === 0) {
      throw new Error();
    }
    return values.default;
  } catch {
    // JSON parser errors can include the secret input.
    throw new Error("configuration_error");
  }
}

export function readEdgeEnvironment(get) {
  return {
    SUPABASE_URL: get("SUPABASE_URL") ?? "",
    SUPABASE_PUBLISHABLE_KEY: key(get, "SUPABASE_PUBLISHABLE_KEY", "SUPABASE_PUBLISHABLE_KEYS"),
    CONTEXT_RELAY_SUPABASE_SECRET_KEY: key(get, "CONTEXT_RELAY_SUPABASE_SECRET_KEY", "SUPABASE_SECRET_KEYS"),
    CONTEXT_RELAY_PAIRING_PEPPER: get("CONTEXT_RELAY_PAIRING_PEPPER") ?? "",
  };
}
