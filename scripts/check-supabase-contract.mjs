import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CONTEXT_RELAY_RELATIONS = new Set([
  'accounts', 'device_bindings', 'device_certificates', 'sync_operations',
  'sync_checkpoints', 'blob_manifests', 'pairing_requests', 'recovery_roots',
  'github_installations', 'deletion_requests', 'blob_upload_reservations',
]);
const IDENTITY_HELPERS = new Set([
  'current_session_id', 'current_read_account_id', 'current_write_account_id',
  'current_read_device_id', 'current_write_device_id',
]);
const AUTHENTICATED_READ_RELATIONS = [
  'accounts', 'device_bindings', 'device_certificates', 'sync_operations',
  'sync_checkpoints', 'blob_manifests',
];
const SERVICE_LIFECYCLE_WRAPPERS = [
  {
    name: 'service_revoke_device_binding',
    arguments: 'p_account_id uuid, p_device_id uuid, p_cutoff_sequence bigint, p_cutoff_hash bytea, p_cutoff_signature bytea',
    identityArguments: 'uuid,uuid,bigint,bytea,bytea',
    returns: 'void',
  },
  {
    name: 'service_begin_account_deletion',
    arguments: 'p_account_id uuid',
    identityArguments: 'uuid',
    returns: 'uuid',
  },
  {
    name: 'service_cancel_account_deletion',
    arguments: 'p_account_id uuid',
    identityArguments: 'uuid',
    returns: 'void',
  },
];
const BLOB_SERVICE_FUNCTION_IDENTITIES = new Map([
  ['public.service_reserve_blob_upload(uuid,uuid,uuid,bytea,bigint[],timestamptz)', 'service_role'],
  ['public.service_finalize_blob_upload(uuid)', 'service_role'],
  ['public.service_release_blob_upload(uuid,context_relay_private.upload_reservation_state)', 'service_role'],
  ['context_relay_private.can_upload_ciphertext_object(text,text,jsonb)', 'authenticated'],
  ['context_relay_private.can_read_ciphertext_object(text,text)', 'authenticated'],
]);
const BLOB_SERVICE_FUNCTION_NAMES = new Set([
  'service_reserve_blob_upload',
  'service_finalize_blob_upload',
  'service_release_blob_upload',
  'can_upload_ciphertext_object',
  'can_read_ciphertext_object',
]);
const PROTECTED_GRANT_ROLES = new Set(['public', 'anon', 'authenticated', 'service_role']);
const PROTECTED_GRANT_SCHEMAS = new Set(['public', 'context_relay_private']);
const FOUNDATION_MIGRATION = 'supabase/migrations/20260804000000_context_relay_ciphertext_boundary.sql';
const RELATIONS = [
  ['public', 'accounts'],
  ['public', 'device_bindings'],
  ['public', 'device_certificates'],
  ['public', 'sync_operations'],
  ['public', 'sync_checkpoints'],
  ['public', 'blob_manifests'],
  ['public', 'pairing_requests'],
  ['public', 'recovery_roots'],
  ['public', 'github_installations'],
  ['public', 'deletion_requests'],
  ['context_relay_private', 'blob_upload_reservations'],
];
const REQUIRED_INDEXES = [
  'accounts_deletion_state_idx',
  'device_bindings_account_owner_idx',
  'device_bindings_auth_session_idx',
  'device_bindings_one_live_per_device_idx',
  'device_bindings_state_idx',
  'device_bindings_expiry_idx',
  'device_bindings_revoked_at_idx',
  'device_certificates_issuer_device_idx',
  'sync_operations_device_certificate_idx',
  'sync_operations_account_workspace_received_idx',
  'sync_checkpoints_device_certificate_idx',
  'sync_checkpoints_account_workspace_received_idx',
  'sync_checkpoints_creator_received_idx',
  'sync_checkpoints_causal_frontier_idx',
  'blob_manifests_device_certificate_idx',
  'blob_manifests_account_storage_idx',
  'pairing_requests_decision_certificate_idx',
  'blob_upload_reservations_device_certificate_idx',
];
const SUPPORTING_UNIQUE_CONSTRAINTS = [
  ['device_bindings_account_device_binding_key', ['account_id', 'device_id', 'id']],
  ['device_certificates_account_workspace_device_key', ['account_id', 'workspace_id', 'device_id']],
  ['pairing_requests_account_workspace_request_key', ['account_id', 'workspace_id', 'id']],
  ['recovery_roots_account_root_key', ['account_id', 'id']],
  ['github_installations_account_installation_key', ['account_id', 'installation_id']],
  ['deletion_requests_account_id_key', ['account_id']],
];

export const REALTIME_HINT_CONTRACT = Object.freeze({
  topic: 'account:<account_uuid>:sync',
  event: 'sync_hint',
  payload: Object.freeze({ version: 1, kind: 'pull_now' }),
  private: true,
});

function readIfPresent(root, relativePath) {
  const target = path.join(root, relativePath);
  return existsSync(target) ? readFileSync(target, 'utf8') : null;
}

function sqlFiles(root) {
  const directory = path.join(root, 'supabase/migrations');
  if (!existsSync(directory)) return [];
  return readdirSync(directory).sort().filter((name) => name.endsWith('.sql')).map((name) => ({
    path: `supabase/migrations/${name}`,
    text: readFileSync(path.join(directory, name), 'utf8'),
  }));
}

function applicationContractFiles(root) {
  const files = [];
  const functionsDirectory = path.join(root, 'supabase/functions');
  function visit(directory, relativeDirectory) {
    if (!existsSync(directory)) return;
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      const relativePath = path.posix.join(relativeDirectory, entry.name);
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(target, relativePath);
      if (entry.isFile()) files.push({ path: relativePath, text: readFileSync(target, 'utf8') });
    }
  }
  visit(functionsDirectory, 'supabase/functions');
  const realtimeVerifier = readIfPresent(root, 'scripts/verify-supabase-realtime.mjs');
  if (realtimeVerifier !== null) files.push({ path: 'scripts/verify-supabase-realtime.mjs', text: realtimeVerifier });
  return files;
}

function violation(violations, ruleId, relativePath, message) {
  violations.push({ ruleId, path: relativePath, message });
}

function withoutSqlComments(sql) {
  return sql.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\r\n]*/g, ' ');
}

function splitTopLevelSqlStatements(sql) {
  const statements = [];
  let statement = '';

  for (let index = 0; index < sql.length;) {
    const character = sql[index];
    const next = sql[index + 1];

    if (character === '-' && next === '-') {
      const newline = sql.indexOf('\n', index + 2);
      statement += ' ';
      index = newline === -1 ? sql.length : newline;
      continue;
    }
    if (character === '/' && next === '*') {
      statement += ' ';
      let depth = 1;
      index += 2;
      while (index < sql.length && depth > 0) {
        if (sql[index] === '/' && sql[index + 1] === '*') {
          depth += 1;
          index += 2;
        } else if (sql[index] === '*' && sql[index + 1] === '/') {
          depth -= 1;
          index += 2;
        } else {
          index += 1;
        }
      }
      continue;
    }
    if (character === "'" || character === '"') {
      const quote = character;
      statement += character;
      index += 1;
      while (index < sql.length) {
        statement += sql[index];
        if (sql[index] === quote && sql[index + 1] === quote) {
          statement += sql[index + 1];
          index += 2;
        } else if (sql[index] === quote) {
          index += 1;
          break;
        } else {
          index += 1;
        }
      }
      continue;
    }
    if (character === '$') {
      const delimiter = sql.slice(index).match(/^\$(?:[a-z_][a-z0-9_]*)?\$/i)?.[0];
      if (delimiter) {
        const end = sql.indexOf(delimiter, index + delimiter.length);
        if (end !== -1) {
          statement += sql.slice(index, end + delimiter.length);
          index = end + delimiter.length;
          continue;
        }
      }
    }

    statement += character;
    index += 1;
    if (character === ';') {
      if (statement.trim()) statements.push(statement.trim());
      statement = '';
    }
  }

  if (statement.trim()) statements.push(statement.trim());
  return statements;
}

function tokenizeSqlStatement(statement) {
  const tokens = [];
  for (let index = 0; index < statement.length;) {
    const character = statement[index];
    if (/\s/.test(character)) {
      index += 1;
      continue;
    }
    if (character === '$') {
      const delimiter = statement.slice(index).match(/^\$(?:[a-z_][a-z0-9_]*)?\$/i)?.[0];
      if (delimiter) {
        const contentStart = index + delimiter.length;
        const end = statement.indexOf(delimiter, contentStart);
        if (end !== -1) {
          tokens.push({ type: 'dollar-string', value: statement.slice(contentStart, end) });
          index = end + delimiter.length;
          continue;
        }
      }
    }
    if (character === "'" || character === '"') {
      const quote = character;
      let value = '';
      index += 1;
      while (index < statement.length) {
        if (statement[index] === quote && statement[index + 1] === quote) {
          value += quote;
          index += 2;
        } else if (statement[index] === quote) {
          index += 1;
          break;
        } else {
          value += statement[index];
          index += 1;
        }
      }
      tokens.push({ type: quote === "'" ? 'string' : 'quoted-identifier', value });
      continue;
    }
    const word = statement.slice(index).match(/^[a-z_][a-z0-9_$]*/i)?.[0];
    if (word) {
      tokens.push({ type: 'word', value: word.toLowerCase() });
      index += word.length;
      continue;
    }
    const operator = statement.slice(index).match(/^(?:::|\|\|)/)?.[0];
    if (operator) {
      tokens.push({ type: 'symbol', value: operator });
      index += operator.length;
      continue;
    }
    tokens.push({ type: 'symbol', value: character });
    index += 1;
  }
  return tokens;
}

function sqlWord(token, value) {
  return token?.type === 'word' && token.value === value;
}

function sqlIdentifier(token, value) {
  return (token?.type === 'word' && token.value === value)
    || (token?.type === 'quoted-identifier' && token.value === value);
}

function sqlQualifiedIdentifier(tokens, index, schema, relation) {
  return sqlIdentifier(tokens[index], schema)
    && tokens[index + 1]?.type === 'symbol'
    && tokens[index + 1].value === '.'
    && sqlIdentifier(tokens[index + 2], relation);
}

function tokenizeJavaScript(source) {
  const tokens = [];
  let canStartRegularExpression = true;
  const push = (token) => {
    tokens.push(token);
    if (token.type === 'identifier') {
      canStartRegularExpression = new Set(['return', 'throw', 'case', 'typeof', 'instanceof', 'in', 'of', 'yield', 'await']).has(token.value);
    } else if (['string', 'template', 'number', 'regex'].includes(token.type)) {
      canStartRegularExpression = false;
    } else {
      canStartRegularExpression = ![')', ']', '}'].includes(token.value);
    }
  };

  for (let index = 0; index < source.length;) {
    const character = source[index];
    const next = source[index + 1];
    if (/\s/.test(character)) {
      index += 1;
      continue;
    }
    if (character === '/' && next === '/') {
      const newline = source.indexOf('\n', index + 2);
      index = newline === -1 ? source.length : newline;
      continue;
    }
    if (character === '/' && next === '*') {
      const end = source.indexOf('*/', index + 2);
      index = end === -1 ? source.length : end + 2;
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      const quote = character;
      let value = '';
      index += 1;
      while (index < source.length) {
        if (source[index] === '\\') {
          value += source[index] + (source[index + 1] ?? '');
          index += 2;
        } else if (source[index] === quote) {
          index += 1;
          break;
        } else {
          value += source[index];
          index += 1;
        }
      }
      push({ type: quote === '`' ? 'template' : 'string', value });
      continue;
    }
    if (character === '/' && canStartRegularExpression) {
      let value = '/';
      let inCharacterClass = false;
      index += 1;
      while (index < source.length) {
        const part = source[index];
        value += part;
        if (part === '\\') {
          value += source[index + 1] ?? '';
          index += 2;
        } else if (part === '[') {
          inCharacterClass = true;
          index += 1;
        } else if (part === ']') {
          inCharacterClass = false;
          index += 1;
        } else if (part === '/' && !inCharacterClass) {
          index += 1;
          while (/[a-z]/i.test(source[index] ?? '')) {
            value += source[index];
            index += 1;
          }
          break;
        } else {
          index += 1;
        }
      }
      push({ type: 'regex', value });
      continue;
    }
    const identifier = source.slice(index).match(/^[A-Za-z_$][A-Za-z0-9_$]*/)?.[0];
    if (identifier) {
      push({ type: 'identifier', value: identifier });
      index += identifier.length;
      continue;
    }
    const number = source.slice(index).match(/^(?:0|[1-9][0-9]*)/)?.[0];
    if (number) {
      push({ type: 'number', value: number });
      index += number.length;
      continue;
    }
    const operator = source.slice(index).match(/^(?:=>|===|!==|==|!=|<=|>=|\?\?|\?\.|&&|\|\||\+\+|--|\*\*)/)?.[0];
    push({ type: 'symbol', value: operator ?? character });
    index += operator?.length ?? 1;
  }
  return tokens;
}

function topLevelJavaScriptIndexes(tokens, first, second) {
  const indexes = [];
  let braces = 0;
  let parentheses = 0;
  let brackets = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (braces === 0 && parentheses === 0 && brackets === 0
        && token.type === 'identifier' && token.value === first
        && tokens[index + 1]?.type === 'identifier' && tokens[index + 1].value === second) {
      indexes.push(index);
    }
    if (token.type !== 'symbol') continue;
    if (token.value === '{') braces += 1;
    if (token.value === '}') braces -= 1;
    if (token.value === '(') parentheses += 1;
    if (token.value === ')') parentheses -= 1;
    if (token.value === '[') brackets += 1;
    if (token.value === ']') brackets -= 1;
  }
  return indexes;
}

function hasSql(sql, pattern) {
  return pattern.test(sql);
}

function splitSqlList(text) {
  const items = [];
  let itemStart = 0;
  let inQuotedIdentifier = false;
  let parenthesisDepth = 0;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === '"') {
      if (inQuotedIdentifier && text[index + 1] === '"') {
        index += 1;
      } else {
        inQuotedIdentifier = !inQuotedIdentifier;
      }
    } else if (!inQuotedIdentifier && character === '(') {
      parenthesisDepth += 1;
    } else if (!inQuotedIdentifier && character === ')') {
      parenthesisDepth -= 1;
    } else if (!inQuotedIdentifier && parenthesisDepth === 0 && character === ',') {
      items.push(text.slice(itemStart, index).trim());
      itemStart = index + 1;
    }
  }

  items.push(text.slice(itemStart).trim());
  return items.filter(Boolean);
}

function normalizeSqlIdentifier(identifier) {
  const trimmed = identifier.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/""/g, '"');
  }
  return trimmed.toLowerCase();
}

function normalizeQualifiedName(value) {
  const identifier = '(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_$]*)';
  const match = value.trim().match(new RegExp(`^(${identifier})\\s*\\.\\s*(${identifier})$`, 'i'));
  if (!match) return null;
  return `${normalizeSqlIdentifier(match[1])}.${normalizeSqlIdentifier(match[2])}`;
}

function normalizeFunctionIdentity(value) {
  const match = value.trim().match(/^([\s\S]*?)\s*\(([\s\S]*)\)$/);
  if (!match) return null;
  const qualifiedName = normalizeQualifiedName(match[1]);
  if (qualifiedName === null) return null;
  const argumentsText = splitSqlList(match[2]).map((argument) => argument.replace(/\s+/g, ' ').trim().toLowerCase()).join(',');
  return `${qualifiedName}(${argumentsText})`;
}

function realtimePublicationTargets(sql) {
  const targets = [];
  const identifier = '(?:"(?:[^"]|"")+"|[a-z_][a-z0-9_$]*)';
  const statements = withoutSqlComments(sql).matchAll(new RegExp(`\\balter\\s+publication\\s+(${identifier})\\s+([\\s\\S]*?);`, 'gi'));

  for (const [, publicationText, actionsText] of statements) {
    if (normalizeSqlIdentifier(publicationText) !== 'supabase_realtime') continue;
    let publicationObjectKind = null;
    for (const rawItem of splitSqlList(actionsText)) {
      let item = rawItem.trim();
      const actionMatch = item.match(/^(add|set)\s+([\s\S]*)$/i);
      if (actionMatch) {
        publicationObjectKind = null;
        item = actionMatch[2].trim();
      } else if (/^(?:drop|reset|owner|rename)\b/i.test(item)) {
        publicationObjectKind = null;
        continue;
      }

      const schemaObjectMatch = item.match(/^tables\s+in\s+schema\s+([\s\S]*)$/i);
      const tableObjectMatch = item.match(/^table\s+([\s\S]*)$/i);
      if (schemaObjectMatch) {
        publicationObjectKind = 'schema';
        item = schemaObjectMatch[1].trim();
      } else if (tableObjectMatch) {
        publicationObjectKind = 'table';
        item = tableObjectMatch[1].trim();
      }

      if (publicationObjectKind === 'schema') {
        const schemaMatch = item.match(new RegExp(`^(${identifier})`, 'i'));
        if (!schemaMatch) continue;
        const schema = normalizeSqlIdentifier(schemaMatch[1]);
        const isCurrentSchemaKeyword = !schemaMatch[1].startsWith('"') && schema === 'current_schema';
        if (schema === 'public' || schema === 'context_relay_private' || isCurrentSchemaKeyword) {
          targets.push(`${schema}.*`);
        }
      } else if (publicationObjectKind === 'table') {
        item = item.replace(/^only\s+/i, '').trim();
        const targetMatch = item.match(new RegExp(`^(${identifier})(?:\\s*\\.\\s*(${identifier}))?`, 'i'));
        if (!targetMatch) continue;
        const schema = targetMatch[2] ? normalizeSqlIdentifier(targetMatch[1]) : 'public';
        const relation = normalizeSqlIdentifier(targetMatch[2] ?? targetMatch[1]);
        if ((schema === 'public' || schema === 'context_relay_private')
            && CONTEXT_RELAY_RELATIONS.has(relation)) {
          targets.push(`${schema}.${relation}`);
        }
      }
    }
  }
  return targets;
}

function hasProtectedSchemaWideGrant(sql, objectKind) {
  const grants = [...sql.matchAll(new RegExp(`\\bgrant\\s+([^;]*?)\\s+on\\s+all\\s+${objectKind}\\s+in\\s+schema\\s+([^;]*?)\\s+to\\s+([^;]+);`, 'gi'))];
  return grants.some(([, , schemaText, roleText]) => {
    const schemas = splitSqlList(schemaText).map(normalizeSqlIdentifier);
    const roles = splitSqlList(roleText.replace(/\s+with\s+grant\s+option\s*$/i, ''))
      .map(normalizeSqlIdentifier);
    return schemas.some((schema) => PROTECTED_GRANT_SCHEMAS.has(schema))
      && roles.some((role) => PROTECTED_GRANT_ROLES.has(role));
  });
}

function functionGrantStatements(sql) {
  return [...sql.matchAll(/\bgrant\s+([^;]*?)\s+on\s+function\s+([^;]*?)\s+to\s+([^;]+);/gi)]
    .map(([, privilegeText, functionText, roleText]) => ({
      privileges: splitSqlList(privilegeText).map((privilege) => privilege.toLowerCase()),
      functions: splitSqlList(functionText).map(normalizeFunctionIdentity).filter((identity) => identity !== null),
      roles: splitSqlList(roleText.replace(/\s+with\s+grant\s+option\s*$/i, '')).map(normalizeSqlIdentifier),
      hasGrantOption: /\s+with\s+grant\s+option\s*$/i.test(roleText),
    }));
}

function functionDefinition(sql, schema, name) {
  return sql.match(new RegExp(
    `\\bcreate\\s+(?:or\\s+replace\\s+)?function\\s+${schema}\\.${name}\\s*\\([\\s\\S]*?\\$\\$\\s*;`,
    'i',
  ))?.[0] ?? '';
}

function tomlSection(config, section) {
  const escaped = section.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return config.match(new RegExp(`^\\[${escaped}\\]\\r?\\n((?:^(?!\\[).*(?:\\r?\\n|$))*)`, 'm'))?.[1] ?? '';
}

function validateConfig(config, violations) {
  if (config === null) {
    violation(violations, 'supabase-config', 'supabase/config.toml', 'missing Supabase configuration');
    return;
  }
  const apiSchemas = config.match(/\bschemas\s*=\s*\[([^\]]*)\]/s)?.[1] ?? '';
  if (/\bproject_id\s*=\s*["']context-relay["']/.test(config) === false) {
    violation(violations, 'project-id', 'supabase/config.toml', 'project_id must be context-relay');
  }
  if (/\bmajor_version\s*=\s*17\b/.test(tomlSection(config, 'db')) === false) {
    violation(violations, 'db-major-version', 'supabase/config.toml', 'PostgreSQL major version must be 17');
  }
  if (apiSchemas.replace(/\s/g, '') !== '"public","graphql_public"') {
    violation(violations, 'api-schemas', 'supabase/config.toml', 'API schemas must be exactly [public, graphql_public] in order');
  }
  if (/['"]context_relay_private['"]/.test(apiSchemas)) {
    violation(violations, 'private-schema-exposed', 'supabase/config.toml', 'context_relay_private must not be an API schema');
  }
  const expiry = Number(config.match(/\bjwt_expiry\s*=\s*(\d+)/)?.[1]);
  if (expiry !== 900) violation(violations, 'jwt-expiry', 'supabase/config.toml', 'JWT expiry must be exactly 900 seconds');
  const github = tomlSection(config, 'auth.external.github');
  if (!/\bsecret\s*=\s*["']env\(SUPABASE_AUTH_GITHUB_SECRET\)["']/.test(github)) {
    violation(violations, 'github-oauth-secret', 'supabase/config.toml', 'GitHub OAuth secret must come from SUPABASE_AUTH_GITHUB_SECRET');
  }
  const bucket = tomlSection(config, 'storage.buckets.ciphertext');
  if (!/\bpublic\s*=\s*false\b/.test(bucket) || !/\bfile_size_limit\s*=\s*["']?33554432["']?/.test(bucket)) {
    violation(violations, 'ciphertext-bucket', 'supabase/config.toml', 'ciphertext bucket must be private and limited to 33554432 bytes');
  }
}

function validateMigration(file, violations, { requireBaseline = true } = {}) {
  const sql = file.text;
  const functions = [...sql.matchAll(/\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.(\w+)\s*\(([^)]*)\)/gi)];
  const names = new Set(functions.map((match) => match[1]));
  if (requireBaseline) {
    if (!/\balter\s+table\s+(?:if\s+exists\s+)?(?:public\.)?\w+\s+enable\s+row\s+level\s+security\b/i.test(sql)) {
      violation(violations, 'migration-rls', file.path, 'migration must enable RLS');
    }
    if (!/\brevoke\b/i.test(sql) || !/\bgrant\b/i.test(sql)) {
      violation(violations, 'migration-grants', file.path, 'migration must contain explicit privilege changes');
    }
    if (![...IDENTITY_HELPERS].every((name) => names.has(name))) {
      violation(violations, 'migration-session-helpers', file.path, 'migration must define the five session identity helpers');
    }
  }
  for (const [, name, argumentsText] of functions) {
    const argumentsPresent = argumentsText.trim().length > 0;
    if (IDENTITY_HELPERS.has(name) && argumentsPresent) {
      violation(violations, 'identity-helper-arguments', file.path, `${name} must have zero arguments`);
    }
    if (/^can_(?:read|upload)_ciphertext_object$/.test(name) && /\b(?:user|account|device|session)(?:_|\b)/i.test(argumentsText)) {
      violation(violations, 'storage-predicate-identity-arguments', file.path, `${name} cannot accept caller-selected identity`);
    }
  }
  for (const match of sql.matchAll(/\bgrant\s+(?:insert|update|delete|all)\b[\s\S]*?\bon\s+(?:table\s+)?public\.(sync_operations|sync_checkpoints)\s+to\s+authenticated\b/gi)) {
    violation(violations, 'immutable-authenticated-mutation-grant', file.path, `authenticated mutation grant on immutable ${match[1]}`);
  }
  for (const match of sql.matchAll(/\bgrant\b[\s\S]*?\bon\s+(?:table\s+)?(?:public\.)?(\w+)\s+to\s+service_role\b/gi)) {
    if (CONTEXT_RELAY_RELATIONS.has(match[1])) violation(violations, 'service-role-context-relation-grant', file.path, `service_role grant on Context Relay relation ${match[1]}`);
  }
  for (const target of realtimePublicationTargets(sql)) {
    violation(violations, 'realtime-context-relation', file.path, `Context Relay relation ${target} cannot join supabase_realtime`);
  }
  if (/signed[ _-]?url/i.test(sql)) violation(violations, 'signed-url-contract', file.path, 'signed URLs are not part of the ciphertext boundary');
}

function validateFoundationMigration(file, violations, allMigrationText = file.text) {
  const sql = withoutSqlComments(file.text);
  const allSql = withoutSqlComments(allMigrationText);

  const tableDefinitions = [...sql.matchAll(/\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?((?:public|context_relay_private)\.\w+)\s*\(([\s\S]*?)\n\);/gi)];
  const duplicateConstraint = tableDefinitions.find(([, , body]) => {
    const names = [...body.matchAll(/\bconstraint\s+(\w+)\b/gi)].map((match) => match[1].toLowerCase());
    return new Set(names).size !== names.length;
  });
  if (duplicateConstraint) {
    violation(violations, 'migration-duplicate-constraint', file.path, `${duplicateConstraint[1]} declares a duplicate constraint name`);
  }

  const createdRelations = [...sql.matchAll(/\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:public|context_relay_private)\.\w+\b/gi)];
  if (createdRelations.length !== RELATIONS.length
      || !RELATIONS.every(([schema, relation]) => hasSql(sql, new RegExp(`\\bcreate\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?${schema}\\.${relation}\\b`, 'i')))) {
    violation(violations, 'migration-relations', file.path, 'foundation migration must create the exact eleven Context Relay relations');
  }

  if (!/\bcreate\s+schema\s+(?:if\s+not\s+exists\s+)?context_relay_private\b/i.test(sql)
      || !/\brevoke\s+all\s+on\s+schema\s+context_relay_private\s+from\s+public\b/i.test(sql)) {
    violation(violations, 'migration-private-schema', file.path, 'private schema must exist and be denied to PUBLIC by default');
  }

  const ownerCreated = /\bcreate\s+role\s+context_relay_rls_owner\s+(?=[^;]*\bnologin\b)(?=[^;]*\bnoinherit\b)[^;]*;/i.test(sql);
  const ownerOwnsRelations = RELATIONS.every(([schema, relation]) => hasSql(sql, new RegExp(`\\balter\\s+table\\s+${schema}\\.${relation}\\s+owner\\s+to\\s+context_relay_rls_owner\\b`, 'i')));
  const ownerOwnsHelpers = [...IDENTITY_HELPERS].every((helper) => hasSql(sql, new RegExp(`\\balter\\s+function\\s+context_relay_private\\.${helper}\\s*\\(\\s*\\)\\s+owner\\s+to\\s+context_relay_rls_owner\\b`, 'i')));
  if (!ownerCreated || !ownerOwnsRelations || !ownerOwnsHelpers) {
    violation(violations, 'migration-owner', file.path, 'NOLOGIN NOINHERIT role must own all relations and identity helpers');
  }

  const enumPatterns = [
    /create\s+type\s+context_relay_private\.device_binding_state\s+as\s+enum\s*\(\s*'pending'\s*,\s*'active'\s*,\s*'revoked'\s*\)/i,
    /create\s+type\s+context_relay_private\.account_deletion_state\s+as\s+enum\s*\(\s*'active'\s*,\s*'pending_delete'\s*,\s*'purged'\s*\)/i,
    /create\s+type\s+context_relay_private\.pairing_request_state\s+as\s+enum\s*\(\s*'pending'\s*,\s*'approved'\s*,\s*'rejected'\s*,\s*'expired'\s*,\s*'cancelled'\s*\)/i,
    /create\s+type\s+context_relay_private\.upload_reservation_state\s+as\s+enum\s*\(\s*'reserved'\s*,\s*'finalized'\s*,\s*'expired'\s*,\s*'cancelled'\s*\)/i,
  ];
  if (!enumPatterns.every((pattern) => pattern.test(sql))) {
    violation(violations, 'migration-enums', file.path, 'foundation enums and labels must match the frozen state machines');
  }

  const compoundForeignKeys = [
    'device_bindings_account_owner_fkey',
    'device_certificates_account_fkey',
    'sync_operations_device_certificate_fkey',
    'sync_checkpoints_device_certificate_fkey',
    'blob_manifests_device_certificate_fkey',
    'pairing_requests_account_fkey',
    'recovery_roots_account_fkey',
    'github_installations_account_fkey',
    'deletion_requests_account_fkey',
    'blob_upload_reservations_device_certificate_fkey',
  ];
  if (!compoundForeignKeys.every((name) => hasSql(sql, new RegExp(`\\bconstraint\\s+${name}\\s+foreign\\s+key\\s*\\(\\s*account_id\\b`, 'i')))
      || !/(?:sync_operations|sync_checkpoints|blob_manifests)[\s\S]*?foreign\s+key\s*\(\s*account_id\s*,\s*workspace_id\s*,\s*(?:creator_)?device_id\s*,\s*device_certificate_id\s*\)\s*references\s+public\.device_certificates\s*\(\s*account_id\s*,\s*workspace_id\s*,\s*device_id\s*,\s*id\s*\)/i.test(sql)
      || !/blob_upload_reservations[\s\S]*?foreign\s+key\s*\(\s*account_id\s*,\s*workspace_id\s*,\s*creator_device_id\s*,\s*device_certificate_id\s*\)\s*references\s+public\.device_certificates\s*\(\s*account_id\s*,\s*workspace_id\s*,\s*device_id\s*,\s*id\s*\)/i.test(sql)) {
    violation(violations, 'migration-account-scoping', file.path, 'account-scoped relationships must use compound account and certificate keys');
  }

  const constantsPresent = /quota_limit_bytes\s+bigint\s+not\s+null\s+default\s+524288000/i.test(sql)
    && /quota_limit_bytes\s*=\s*524288000/i.test(sql)
    && /octet_length\s*\(\s*ciphertext\s*\)\s*<=\s*4194304/i.test(sql)
    && /33554432/.test(sql)
    && /interval\s+'7 days'/i.test(sql)
    && /cutoff_device_sequence[\s\S]*cutoff_hash[\s\S]*cutoff_signature/i.test(sql)
    && /octet_length\s*\([^)]*\)\s*=\s*24/i.test(sql)
    && /octet_length\s*\([^)]*\)\s*=\s*32/i.test(sql)
    && /octet_length\s*\([^)]*\)\s*=\s*64/i.test(sql);
  if (!constantsPresent) {
    violation(violations, 'migration-constants', file.path, 'quota, ciphertext, blob-part, deadline, revocation, and crypto-width constants must be explicit');
  }

  const operationDefinition = tableDefinitions.find(([, qualifiedName]) => qualifiedName.toLowerCase() === 'public.sync_operations')?.[2] ?? '';
  const checkpointDefinition = tableDefinitions.find(([, qualifiedName]) => qualifiedName.toLowerCase() === 'public.sync_checkpoints')?.[2] ?? '';
  const syncEnvelopeShapeIsExact = /\bproject_id\s+uuid\b/i.test(operationDefinition)
    && !/\bmutation_id\b/i.test(operationDefinition)
    && /\bdevice_sequence\s+numeric\s+not\s+null\b/i.test(operationDefinition)
    && /\bprevious_device_hash\s+bytea\s+not\s+null\b/i.test(operationDefinition)
    && /\bblob_refs\s+jsonb\s+not\s+null\b/i.test(operationDefinition)
    && /\bcreated_hlc\s+jsonb\s+not\s+null\b/i.test(operationDefinition)
    && /schema_version\s*=\s*1/i.test(operationDefinition)
    && /record_kind\s+in\s*\(\s*'memory'\s*,\s*'memory_candidate'\s*,\s*'task'\s*,\s*'secret_ref'\s*,\s*'instruction'\s*,\s*'component'\s*,\s*'project'\s*\)/i.test(operationDefinition)
    && /mutation_kind\s+in\s*\(\s*'upsert'\s*,\s*'tombstone'\s*\)/i.test(operationDefinition)
    && /device_sequence\s+between\s+0\s+and\s+18446744073709551615/i.test(operationDefinition)
    && /device_sequence\s*=\s*pg_catalog\.trunc\s*\(\s*device_sequence\s*\)/i.test(operationDefinition)
    && /control_epoch\s+between\s+0\s+and\s+4294967295/i.test(operationDefinition)
    && /key_epoch\s+between\s+0\s+and\s+4294967295/i.test(operationDefinition)
    && /valid_sync_causal_frontier\s*\(\s*causal_frontier\s*\)/i.test(operationDefinition)
    && /valid_sync_blob_refs\s*\(\s*blob_refs\s*\)/i.test(operationDefinition)
    && /valid_hybrid_logical_clock\s*\(\s*created_hlc\s*\)/i.test(operationDefinition)
    && /\bprevious_checkpoint_hash\s+bytea\s+not\s+null\b/i.test(checkpointDefinition)
    && /schema_version\s*=\s*1/i.test(checkpointDefinition)
    && /key_epoch\s+between\s+0\s+and\s+4294967295/i.test(checkpointDefinition)
    && /valid_sync_causal_frontier\s*\(\s*causal_frontier\s*\)/i.test(checkpointDefinition)
    && /valid_hybrid_logical_clock\s*\(\s*created_hlc\s*\)/i.test(checkpointDefinition);
  const syncValidatorsAreHardened = ['valid_sync_causal_frontier', 'valid_sync_blob_refs', 'valid_hybrid_logical_clock'].every((name) => {
    const definition = sql.match(new RegExp(`\\bcreate\\s+(?:or\\s+replace\\s+)?function\\s+context_relay_private\\.${name}\\s*\\(\\s*\\w+\\s+jsonb\\s*\\)[\\s\\S]*?\\$\\$\\s*;`, 'i'))?.[0] ?? '';
    return /\breturns\s+boolean\b/i.test(definition)
      && /\blanguage\s+plpgsql\b/i.test(definition)
      && /\bimmutable\b/i.test(definition)
      && /\bstrict\b/i.test(definition)
      && /\bsecurity\s+invoker\b/i.test(definition)
      && /\bset\s+search_path\s*=\s*''/i.test(definition)
      && hasSql(sql, new RegExp(`\\balter\\s+function\\s+context_relay_private\\.${name}\\s*\\(\\s*jsonb\\s*\\)\\s+owner\\s+to\\s+context_relay_rls_owner\\b`, 'i'));
  });
  const causalValidatorDefinition = sql.match(/\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.valid_sync_causal_frontier\s*\([\s\S]*?\$\$\s*;/i)?.[0] ?? '';
  const blobRefsValidatorDefinition = sql.match(/\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.valid_sync_blob_refs\s*\([\s\S]*?\$\$\s*;/i)?.[0] ?? '';
  const hlcValidatorDefinition = sql.match(/\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.valid_hybrid_logical_clock\s*\([\s\S]*?\$\$\s*;/i)?.[0] ?? '';
  const syncValidatorsPreserveWireSemantics = /previous_device_id[\s\S]*device_id_text::pg_catalog\.uuid\s*<=\s*previous_device_id::pg_catalog\.uuid[\s\S]*previous_device_id\s*:=\s*device_id_text/i.test(causalValidatorDefinition)
    && blobRefsValidatorDefinition.includes(String.raw`U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000'`)
    && /logical_text\s*!~\s*'\^\(0\|\[1-9\]\[0-9\]\*\)\$'/i.test(hlcValidatorDefinition)
    && /logical_text::numeric\s*<=\s*4294967295/i.test(hlcValidatorDefinition);
  if (!syncEnvelopeShapeIsExact || !syncValidatorsAreHardened || !syncValidatorsPreserveWireSemantics) {
    violation(violations, 'migration-sync-envelopes', file.path, 'sync operation and checkpoint storage must match the exact frozen V1 wire shapes and unsigned bounds');
  }

  const quotaTriggerDefinition = sql.match(/\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.charge_sync_operation_bytes\s*\(\s*\)[\s\S]*?\$\$\s*;/i)?.[0] ?? '';
  const accountLockIndex = quotaTriggerDefinition.search(/\bfrom\s+public\.accounts\s+as\s+account[\s\S]*?\bwhere\s+account\.id\s*=\s*new\.account_id\s+for\s+update\s*;/i);
  const counterUpdateIndex = quotaTriggerDefinition.search(/\bupdate\s+public\.accounts\s+as\s+account\b/i);
  const quotaTriggerIsExact = /\breturns\s+trigger\b/i.test(quotaTriggerDefinition)
    && /\blanguage\s+plpgsql\b/i.test(quotaTriggerDefinition)
    && /\bvolatile\b/i.test(quotaTriggerDefinition)
    && /\bsecurity\s+definer\b/i.test(quotaTriggerDefinition)
    && /\bset\s+search_path\s*=\s*''/i.test(quotaTriggerDefinition)
    && accountLockIndex >= 0
    && counterUpdateIndex > accountLockIndex
    && /account_state\s*<>\s*'active'/i.test(quotaTriggerDefinition)
    && /account_used_bytes\s*\+\s*account_reserved_bytes\s*\+\s*operation_ciphertext_bytes\s*>\s*account_quota_limit_bytes/i.test(quotaTriggerDefinition)
    && /used_bytes\s*=\s*account\.used_bytes\s*\+\s*operation_ciphertext_bytes/i.test(quotaTriggerDefinition)
    && /\balter\s+function\s+context_relay_private\.charge_sync_operation_bytes\s*\(\s*\)\s+owner\s+to\s+context_relay_rls_owner\b/i.test(sql)
    && /\brevoke\s+all\s+on\s+function\s+context_relay_private\.charge_sync_operation_bytes\s*\(\s*\)\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role\b/i.test(sql)
    && /\bcreate\s+trigger\s+sync_operations_charge_quota_before_insert\s+before\s+insert\s+on\s+public\.sync_operations\s+for\s+each\s+row\s+execute\s+function\s+context_relay_private\.charge_sync_operation_bytes\s*\(\s*\)\s*;/i.test(sql);
  if (!quotaTriggerIsExact) {
    violation(violations, 'migration-operation-quota-trigger', file.path, 'operation quota trigger must lock the account, require active state, enforce used plus reserved quota, and atomically charge ciphertext bytes');
  }

  const rlsEnablements = [...sql.matchAll(/\balter\s+table\s+((?:public|context_relay_private)\.\w+)\s+enable\s+row\s+level\s+security\b/gi)]
    .map((match) => match[1].toLowerCase());
  if (rlsEnablements.length !== RELATIONS.length
      || !RELATIONS.every(([schema, relation]) => rlsEnablements.filter((name) => name === `${schema}.${relation}`).length === 1)) {
    violation(violations, 'migration-rls-relations', file.path, 'RLS must be enabled exactly once on each of the eleven relations');
  }

  const explicitIndexesPresent = REQUIRED_INDEXES.every((index) => hasSql(sql, new RegExp(`\\bcreate\\s+(?:unique\\s+)?index\\s+${index}\\b`, 'i')));
  const supportingUniqueIndexesPresent = SUPPORTING_UNIQUE_CONSTRAINTS.every(([constraint, columns]) => {
    const columnPattern = columns.join('\\s*,\\s*');
    return hasSql(sql, new RegExp(`\\bconstraint\\s+${constraint}\\s+unique\\s*\\(\\s*${columnPattern}\\s*\\)`, 'i'));
  });
  if (!explicitIndexesPresent || !supportingUniqueIndexesPresent) {
    violation(violations, 'migration-indexes', file.path, 'every foreign key and identity policy hot path must have an explicit index');
  }

  const defaultTableReset = /alter\s+default\s+privileges\s+for\s+role\s+context_relay_rls_owner[\s\S]*?revoke\s+all\s+on\s+tables\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role/i.test(sql);
  const defaultFunctionReset = /alter\s+default\s+privileges\s+for\s+role\s+context_relay_rls_owner[\s\S]*?revoke\s+(?:all|execute)\s+on\s+functions\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role/i.test(sql);
  const relationReset = /revoke\s+all\s+on\s+table[\s\S]*?public\.accounts[\s\S]*?context_relay_private\.blob_upload_reservations[\s\S]*?from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role/i.test(sql);
  if (!defaultTableReset || !defaultFunctionReset || !relationReset) {
    violation(violations, 'migration-privilege-reset', file.path, 'default and object privileges must be revoked deny-first');
  }

  const functionDefinitions = [...sql.matchAll(/\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.(current_(?:session|read_account|write_account|read_device|write_device)_id)\s*\(\s*\)[\s\S]*?\$\$\s*;/gi)];
  const allCurrentIdentityDefinitions = [...sql.matchAll(/\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.(current_\w+_id)\s*\(/gi)];
  const hardened = functionDefinitions.length === 5
    && allCurrentIdentityDefinitions.length === 5
    && allCurrentIdentityDefinitions.every((match) => IDENTITY_HELPERS.has(match[1]))
    && functionDefinitions.every((match) => /\bstable\b/i.test(match[0])
    && /\bsecurity\s+definer\b/i.test(match[0])
    && /\bset\s+search_path\s*=\s*''/i.test(match[0])
    && !/\bexecute\b/i.test(match[0]));
  if (!hardened) {
    violation(violations, 'migration-helper-hardening', file.path, 'all five identity helpers must be stable hardened definers with empty search paths and no dynamic SQL');
  }

  const authContextBridge = sql.match(/\bcreate\s+function\s+context_relay_private\.request_auth_context\s*\(\s*\)[\s\S]*?\$auth_context\$\s*;/i)?.[0] ?? '';
  const authContextBridgeIsExact = /\breturns\s+table\s*\(\s*auth_user_id\s+uuid\s*,\s*session_id\s+text\s*\)/i.test(authContextBridge)
    && /\blanguage\s+sql\b/i.test(authContextBridge)
    && /\bstable\b/i.test(authContextBridge)
    && /\bsecurity\s+definer\b/i.test(authContextBridge)
    && /\bset\s+search_path\s*=\s*''/i.test(authContextBridge)
    && /\bselect\s+auth\.uid\s*\(\s*\)\s*,\s*auth\.jwt\s*\(\s*\)\s*->>\s*'session_id'/i.test(authContextBridge)
    && !/\balter\s+function\s+context_relay_private\.request_auth_context\s*\(\s*\)\s+owner\s+to\s+context_relay_rls_owner\b/i.test(sql)
    && /\brevoke\s+all\s+on\s+function\s+context_relay_private\.request_auth_context\s*\(\s*\)\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role\s*,\s*context_relay_rls_owner\b/i.test(sql)
    && /\bgrant\s+execute\s+on\s+function\s+context_relay_private\.request_auth_context\s*\(\s*\)\s+to\s+context_relay_rls_owner\b/i.test(sql)
    && !/\bgrant\s+(?:usage|all)\s+on\s+schema\s+auth\s+to\s+context_relay_rls_owner\b/i.test(sql)
    && functionDefinitions.every((match) => /context_relay_private\.request_auth_context\s*\(\s*\)/i.test(match[0])
      && !/auth\.(?:uid|jwt)\s*\(\s*\)/i.test(match[0]));
  if (!authContextBridgeIsExact) {
    violation(violations, 'migration-auth-context-bridge', file.path, 'hosted Auth claims must cross one exact non-client security-definer bridge into the five dedicated-owner identity helpers');
  }

  const helperGrant = /grant\s+execute\s+on\s+function\s+context_relay_private\.current_read_account_id\s*\(\s*\)\s*,\s*context_relay_private\.current_write_account_id\s*\(\s*\)\s*,\s*context_relay_private\.current_read_device_id\s*\(\s*\)\s*,\s*context_relay_private\.current_write_device_id\s*\(\s*\)\s+to\s+authenticated/i.test(sql);
  const currentSessionGranted = /grant\s+execute\s+on\s+function\s+context_relay_private\.current_session_id\s*\(\s*\)[\s\S]*?\bto\s+authenticated\b/i.test(sql);
  if (!helperGrant || currentSessionGranted) {
    violation(violations, 'migration-helper-grants', file.path, 'authenticated must execute only the four account/device policy helpers');
  }

  const validatorDefinition = sql.match(/\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.valid_ciphertext_part_sizes\s*\(\s*\w+\s+jsonb\s*\)[\s\S]*?\$\$\s*;/i)?.[0] ?? '';
  const validatorHardened = /\breturns\s+boolean\b/i.test(validatorDefinition)
    && /\blanguage\s+plpgsql\b/i.test(validatorDefinition)
    && /\bimmutable\b/i.test(validatorDefinition)
    && /\bstrict\b/i.test(validatorDefinition)
    && /\bsecurity\s+invoker\b/i.test(validatorDefinition)
    && /\bset\s+search_path\s*=\s*''/i.test(validatorDefinition)
    && /jsonb_typeof/i.test(validatorDefinition)
    && /jsonb_array_length/i.test(validatorDefinition)
    && /jsonb_array_elements/i.test(validatorDefinition)
    && /'number'/i.test(validatorDefinition)
    && /\btrunc\s*\(/i.test(validatorDefinition)
    && />\s*0\b/i.test(validatorDefinition)
    && /<=\s*33554432\b/i.test(validatorDefinition);
  const validatorUsedByBothRelations = /blob_manifests[\s\S]*?valid_ciphertext_part_sizes\s*\(\s*ciphertext_part_sizes\s*\)/i.test(sql)
    && /blob_upload_reservations[\s\S]*?valid_ciphertext_part_sizes\s*\(\s*expected_part_sizes\s*\)/i.test(sql);
  const validatorOwned = /alter\s+function\s+context_relay_private\.valid_ciphertext_part_sizes\s*\(\s*jsonb\s*\)\s+owner\s+to\s+context_relay_rls_owner/i.test(sql);
  if (!validatorHardened || !validatorUsedByBothRelations || !validatorOwned) {
    violation(violations, 'migration-part-size-validator', file.path, 'both blob relations must use the hardened integral bounded part-size validator');
  }

  const internalFunctions = [
    'valid_ciphertext_part_sizes\\s*\\(\\s*jsonb\\s*\\)',
    'ciphertext_part_sizes_total\\s*\\(\\s*jsonb\\s*\\)',
    'valid_sync_causal_frontier\\s*\\(\\s*jsonb\\s*\\)',
    'valid_sync_blob_refs\\s*\\(\\s*jsonb\\s*\\)',
    'valid_hybrid_logical_clock\\s*\\(\\s*jsonb\\s*\\)',
    'charge_sync_operation_bytes\\s*\\(\\s*\\)',
  ];
  const ownerRoleBlocks = [...allSql.matchAll(/\bset\s+local\s+role\s+context_relay_rls_owner\s*;([\s\S]*?)\breset\s+role\s*;/gi)]
    .map((match) => match[1]);
  const internalExecutionRevokedAsOwner = ownerRoleBlocks.some((block) => (
    /\brevoke\s+all\s+on\s+function\b/i.test(block)
    && /\bfrom\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role\s*;/i.test(block)
    && internalFunctions.every((signature) => new RegExp(`context_relay_private\\.${signature}`, 'i').test(block))
  ));
  let ownerMembershipOpen = false;
  let ownerMembershipLifecycleValid = true;
  let ownerMembershipGrantCount = 0;
  for (const statement of splitTopLevelSqlStatements(allSql)) {
    if (/^grant\s+context_relay_rls_owner\s+to\s+current_user\s+with\s+inherit\s+false\s*,\s*set\s+true\s*;?$/i.test(statement)) {
      if (ownerMembershipOpen) ownerMembershipLifecycleValid = false;
      ownerMembershipOpen = true;
      ownerMembershipGrantCount += 1;
    } else if (/^revoke\s+context_relay_rls_owner\s+from\s+current_user(?:\s+granted\s+by\s+current_user)?\s*;?$/i.test(statement)) {
      if (!ownerMembershipOpen) ownerMembershipLifecycleValid = false;
      ownerMembershipOpen = false;
    } else if (/^set\s+local\s+role\s+context_relay_rls_owner\s*;?$/i.test(statement) && !ownerMembershipOpen) {
      ownerMembershipLifecycleValid = false;
    }
  }
  const temporaryOwnerMembershipClosed = ownerMembershipLifecycleValid
    && ownerMembershipGrantCount > 0
    && !ownerMembershipOpen;
  if (!internalExecutionRevokedAsOwner || !temporaryOwnerMembershipClosed
      || /\bgrant\s+execute\s+on\s+function\s+context_relay_private\.(?:valid_ciphertext_part_sizes|ciphertext_part_sizes_total|valid_sync_causal_frontier|valid_sync_blob_refs|valid_hybrid_logical_clock|charge_sync_operation_bytes)\b/i.test(allSql)) {
    violation(violations, 'migration-internal-function-execute', file.path, 'the dedicated owner must revoke public, client, and service execution from all six internal validators and trigger helpers while acting as their owner');
  }

  const relationGrants = [...sql.matchAll(/\bgrant\s+([^;]*?)\s+on\s+(?:table\s+)?([^;]*?)\s+to\s+([^;]+);/gi)];
  const authenticatedSelectRelations = [];
  let disallowedClientRelationGrant = false;
  for (const [, privilegeText, objectText, roleText] of relationGrants) {
    const privileges = splitSqlList(privilegeText).map((privilege) => privilege.toLowerCase());
    const hasGrantOption = /\s+with\s+grant\s+option\s*$/i.test(roleText);
    const roles = splitSqlList(roleText.replace(/\s+with\s+grant\s+option\s*$/i, ''))
      .map(normalizeSqlIdentifier);
    const grantedRelations = splitSqlList(objectText)
      .map(normalizeQualifiedName)
      .filter((name) => name !== null)
      .filter((name) => CONTEXT_RELAY_RELATIONS.has(name.split('.')[1]))
      .map((name) => name.split('.')[1]);
    if (grantedRelations.length === 0) continue;
    if (roles.includes('authenticated') && privileges.length === 1 && privileges[0] === 'select') {
      authenticatedSelectRelations.push(...grantedRelations);
    }
    if (hasGrantOption
        || roles.some((role) => ['public', 'anon', 'service_role'].includes(role))
        || (roles.includes('authenticated') && !(privileges.length === 1 && privileges[0] === 'select'))) {
      disallowedClientRelationGrant = true;
    }
  }
  const expectedReadRelations = [...AUTHENTICATED_READ_RELATIONS].sort();
  const actualReadRelations = [...authenticatedSelectRelations].sort();
  if (disallowedClientRelationGrant
      || hasProtectedSchemaWideGrant(sql, 'tables')
      || actualReadRelations.length !== expectedReadRelations.length
      || actualReadRelations.some((name, index) => name !== expectedReadRelations[index])) {
    violation(violations, 'migration-read-grants', file.path, 'authenticated must receive SELECT only on the exact six read relations and no client/service role may receive other direct relation grants');
  }

  const policyStatements = [...sql.matchAll(/\bcreate\s+policy\s+\w+\s+on\s+(?:public|context_relay_private)\.\w+[\s\S]*?;/gi)]
    .map((match) => match[0].replace(/\s+/g, ' ').replace(/\(\s+/g, '(').replace(/\s+\)/g, ')').trim().toLowerCase());
  const expectedPolicyExpressions = new Map([
    ['accounts', 'id = (select context_relay_private.current_read_account_id())'],
    ['device_bindings', 'account_id = (select context_relay_private.current_read_account_id())'],
    ['device_certificates', 'account_id = (select context_relay_private.current_read_account_id())'],
    ['sync_operations', 'account_id = (select context_relay_private.current_read_account_id())'],
    ['sync_checkpoints', 'account_id = (select context_relay_private.current_read_account_id())'],
    ['blob_manifests', 'account_id = (select context_relay_private.current_read_account_id()) and finalized_at is not null'],
  ]);
  const policiesAreExact = policyStatements.length === expectedPolicyExpressions.size
    && [...expectedPolicyExpressions].every(([relation, expression]) => {
      const matching = policyStatements.filter((statement) => new RegExp(`^create policy \\w+ on public\\.${relation} for select to authenticated using \\(.*\\);$`).test(statement));
      return matching.length === 1 && matching[0].endsWith(`using (${expression});`);
    });
  if (!policiesAreExact) {
    violation(violations, 'migration-read-policies', file.path, 'foundation migration must define exactly one scalar-helper authenticated SELECT policy on each read relation and no other policies');
  }

  const lifecycleWrapperNames = new Set(SERVICE_LIFECYCLE_WRAPPERS.map((wrapper) => wrapper.name));
  const lifecycleServiceDefinitions = [...sql.matchAll(/\bcreate\s+(?:or\s+replace\s+)?function\s+public\.(service_\w+)\s*\(/gi)]
    .filter(([, name]) => lifecycleWrapperNames.has(name.toLowerCase()));
  let wrappersAreExact = lifecycleServiceDefinitions.length === SERVICE_LIFECYCLE_WRAPPERS.length;
  for (const wrapper of SERVICE_LIFECYCLE_WRAPPERS) {
    const escapedArguments = wrapper.arguments.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
    const definition = sql.match(new RegExp(`\\bcreate\\s+(?:or\\s+replace\\s+)?function\\s+public\\.${wrapper.name}\\s*\\(\\s*${escapedArguments}\\s*\\)[\\s\\S]*?\\$\\$\\s*;`, 'i'))?.[0] ?? '';
    const hardened = definition.length > 0
      && new RegExp(`\\breturns\\s+${wrapper.returns}\\b`, 'i').test(definition)
      && /\blanguage\s+plpgsql\b/i.test(definition)
      && /\bsecurity\s+definer\b/i.test(definition)
      && /\bset\s+search_path\s*=\s*''/i.test(definition)
      && !/\bexecute\b/i.test(definition)
      && !/\b(?:from|join|update|insert\s+into)\s+(?:accounts|device_bindings|deletion_requests)\b/i.test(definition)
      && hasSql(sql, new RegExp(`\\balter\\s+function\\s+public\\.${wrapper.name}\\s*\\(\\s*${wrapper.identityArguments.replaceAll(',', '\\s*,\\s*')}\\s*\\)\\s+owner\\s+to\\s+context_relay_rls_owner\\b`, 'i'));
    const accountLockIndex = definition.search(/\bfrom\s+public\.accounts\b[^;]*\bfor\s+update\s*;/i);
    const bindingOrRequestLockIndex = wrapper.name === 'service_revoke_device_binding'
      ? definition.search(/\bfrom\s+public\.device_bindings\b[^;]*\bfor\s+update\s*;/i)
      : definition.search(/\bfrom\s+public\.deletion_requests\b[^;]*\bfor\s+update\s*;/i);
    const stableLockOrder = accountLockIndex >= 0 && bindingOrRequestLockIndex > accountLockIndex;
    let lifecycleSemantics = false;
    if (wrapper.name === 'service_revoke_device_binding') {
      const historyLockIndex = definition.search(/\bfrom\s+public\.device_bindings\b[^;]*binding\.state\s*=\s*'revoked'[^;]*\bfor\s+update\s*;/i);
      const activeLockIndex = definition.search(/\bfrom\s+public\.device_bindings\b[^;]*binding\.state\s*=\s*'active'[^;]*binding\.revoked_at\s+is\s+null[^;]*binding\.expires_at[^;]*\bfor\s+update\s*;/i);
      lifecycleSemantics = /p_cutoff_sequence\s*<\s*0/i.test(definition)
        && /octet_length\s*\(\s*p_cutoff_hash\s*\)\s*<>\s*32/i.test(definition)
        && /octet_length\s*\(\s*p_cutoff_signature\s*\)\s*<>\s*64/i.test(definition)
        && /account_state\s+not\s+in\s*\([^)]*'active'[^)]*'pending_delete'/i.test(definition)
        && historyLockIndex >= 0
        && activeLockIndex > historyLockIndex
        && /binding\.cutoff_device_sequence\s*=\s*p_cutoff_sequence/i.test(definition)
        && /binding\.cutoff_hash\s*=\s*p_cutoff_hash/i.test(definition)
        && /binding\.cutoff_signature\s*=\s*p_cutoff_signature/i.test(definition)
        && /p_cutoff_sequence\s*<=\s*max_prior_cutoff_sequence/i.test(definition)
        && /binding\.state\s*=\s*'active'/i.test(definition)
        && /binding\.revoked_at\s+is\s+null/i.test(definition)
        && /binding\.expires_at\s+is\s+null\s+or\s+binding\.expires_at\s*>\s*transition_time/i.test(definition)
        && /cutoff_device_sequence\s*=\s*p_cutoff_sequence/i.test(definition)
        && /cutoff_hash\s*=\s*p_cutoff_hash/i.test(definition)
        && /cutoff_signature\s*=\s*p_cutoff_signature/i.test(definition)
        && /control_epoch\s*=\s*account\.control_epoch\s*\+\s*1/i.test(definition)
        && /key_epoch\s*=\s*account\.key_epoch\s*\+\s*1/i.test(definition);
    } else if (wrapper.name === 'service_begin_account_deletion') {
      lifecycleSemantics = /statement_timestamp\s*\(\s*\)/i.test(definition)
        && (definition.match(/transition_time\s*\+\s*interval\s*'7 days'/gi)?.length ?? 0) === 3
        && /account_state\s*=\s*'pending_delete'/i.test(definition)
        && /return\s+request_row\.id/i.test(definition)
        && /insert\s+into\s+public\.deletion_requests/i.test(definition)
        && /update\s+public\.accounts/i.test(definition);
    } else {
      lifecycleSemantics = /statement_timestamp\s*\(\s*\)/i.test(definition)
        && /request_row\.grace_deadline\s*<=\s*transition_time/i.test(definition)
        && /update\s+public\.deletion_requests/i.test(definition)
        && /update\s+public\.accounts/i.test(definition)
        && /deletion_requested_at\s*=\s*null/i.test(definition)
        && /deletion_scheduled_for\s*=\s*null/i.test(definition)
        && /request_row\.cancelled_at\s+is\s+not\s+null/i.test(definition);
    }
    wrappersAreExact &&= hardened && stableLockOrder && lifecycleSemantics;
  }
  const functionGrants = [...sql.matchAll(/\bgrant\s+([^;]*?)\s+on\s+function\s+([^;]*?)\s+to\s+([^;]+);/gi)]
    .map(([, privilegeText, functionText, roleText]) => ({
      privileges: splitSqlList(privilegeText).map((privilege) => privilege.toLowerCase()),
      functions: splitSqlList(functionText).map(normalizeFunctionIdentity).filter((identity) => identity !== null),
      roles: splitSqlList(roleText.replace(/\s+with\s+grant\s+option\s*$/i, '')).map(normalizeSqlIdentifier),
      hasGrantOption: /\s+with\s+grant\s+option\s*$/i.test(roleText),
    }));
  const revokeAndGrantAreExact = SERVICE_LIFECYCLE_WRAPPERS.every((wrapper) => {
    const argumentsPattern = wrapper.identityArguments.replaceAll(',', '\\s*,\\s*');
    const identity = `public.${wrapper.name}(${wrapper.identityArguments})`;
    const matchingGrants = functionGrants.filter((grant) => grant.functions.includes(identity));
    return hasSql(sql, new RegExp(`\\brevoke\\s+all\\s+on\\s+function\\s+public\\.${wrapper.name}\\s*\\(\\s*${argumentsPattern}\\s*\\)\\s+from\\s+public\\s*,\\s*anon\\s*,\\s*authenticated\\s*,\\s*service_role\\b`, 'i'))
      && matchingGrants.length === 1
      && matchingGrants[0].privileges.length === 1
      && matchingGrants[0].privileges[0] === 'execute'
      && matchingGrants[0].roles.length === 1
      && matchingGrants[0].roles[0] === 'service_role'
      && !matchingGrants[0].hasGrantOption;
  });
  if (!wrappersAreExact) {
    violation(violations, 'migration-service-wrappers', file.path, 'foundation migration must define exactly the three fully-qualified hardened service lifecycle wrappers with exact signatures and non-login ownership');
  }
  if (!revokeAndGrantAreExact || hasProtectedSchemaWideGrant(sql, 'functions')) {
    violation(violations, 'migration-service-wrapper-grants', file.path, 'service lifecycle wrappers must revoke all caller execution and grant execution only to service_role');
  }
}

function validateBlobStorageBoundary(file, violations) {
  const sql = withoutSqlComments(file.text);
  const reserveDefinition = functionDefinition(sql, 'public', 'service_reserve_blob_upload');
  const finalizeDefinition = functionDefinition(sql, 'public', 'service_finalize_blob_upload');
  const releaseDefinition = functionDefinition(sql, 'public', 'service_release_blob_upload');
  const uploadPredicateDefinition = functionDefinition(sql, 'context_relay_private', 'can_upload_ciphertext_object');
  const readPredicateDefinition = functionDefinition(sql, 'context_relay_private', 'can_read_ciphertext_object');

  const hardenedDefinition = (definition) => definition.length > 0
    && /\bsecurity\s+definer\b/i.test(definition)
    && /\bset\s+search_path\s*=\s*''/i.test(definition)
    && !/\bexecute\b/i.test(definition);
  const ownerStatement = (schema, name, argumentsPattern) => hasSql(
    sql,
    new RegExp(`\\balter\\s+function\\s+${schema}\\.${name}\\s*\\(\\s*${argumentsPattern}\\s*\\)\\s+owner\\s+to\\s+context_relay_rls_owner\\b`, 'i'),
  );
  const accountLockBeforeReservation = (definition) => {
    const accountLock = definition.search(/\bfrom\s+public\.accounts\s+as\s+account[^;]*\bfor\s+update\s*;/i);
    const reservationLock = definition.search(/\bfrom\s+context_relay_private\.blob_upload_reservations\s+as\s+reservation[^;]*\bfor\s+update\s*;/i);
    return accountLock >= 0 && reservationLock > accountLock;
  };

  const exactSignatures = /\bcreate\s+(?:or\s+replace\s+)?function\s+public\.service_reserve_blob_upload\s*\(\s*p_account_id\s+uuid\s*,\s*p_device_id\s+uuid\s*,\s*p_storage_id\s+uuid\s*,\s*p_ciphertext_sha256\s+bytea\s*,\s*p_part_sizes\s+bigint\[\]\s*,\s*p_expires_at\s+timestamptz\s*\)/i.test(sql)
    && /\bcreate\s+(?:or\s+replace\s+)?function\s+public\.service_finalize_blob_upload\s*\(\s*p_storage_id\s+uuid\s*\)/i.test(sql)
    && /\bcreate\s+(?:or\s+replace\s+)?function\s+public\.service_release_blob_upload\s*\(\s*p_storage_id\s+uuid\s*,\s*p_terminal_state\s+context_relay_private\.upload_reservation_state\s*\)/i.test(sql)
    && /\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.can_upload_ciphertext_object\s*\(\s*p_bucket_id\s+text\s*,\s*p_name\s+text\s*,\s*p_metadata\s+jsonb\s*\)/i.test(sql)
    && /\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.can_read_ciphertext_object\s*\(\s*p_bucket_id\s+text\s*,\s*p_name\s+text\s*\)/i.test(sql);

  const relationsAreExact = /\bcreate\s+table\s+context_relay_private\.blob_upload_reservations\s*\([\s\S]*?\bciphertext_digest\s+bytea\s+not\s+null[\s\S]*?\bconstraint\s+blob_upload_reservations_storage_id_key\s+unique\s*\(\s*storage_id\s*\)[\s\S]*?\bconstraint\s+blob_upload_reservations_digest_width_check\s+check\s*\(\s*pg_catalog\.octet_length\s*\(\s*ciphertext_digest\s*\)\s*=\s*32\s*\)[\s\S]*?\bpart_count\s+between\s+1\s+and\s+16/i.test(sql)
    && /\bcreate\s+table\s+public\.blob_manifests\s*\([\s\S]*?\bconstraint\s+blob_manifests_storage_id_key\s+unique\s*\(\s*storage_id\s*\)[\s\S]*?\bpart_count\s+between\s+1\s+and\s+16/i.test(sql)
    && /\bcreate\s+(?:or\s+replace\s+)?function\s+context_relay_private\.ciphertext_part_sizes_total\s*\(/i.test(sql)
    && /\bexpected_total_bytes\s*=\s*context_relay_private\.ciphertext_part_sizes_total\s*\(\s*expected_part_sizes\s*\)/i.test(sql)
    && /\btotal_ciphertext_bytes\s*=\s*context_relay_private\.ciphertext_part_sizes_total\s*\(\s*ciphertext_part_sizes\s*\)/i.test(sql)
    && /jsonb_array_length\s*\(\s*part_sizes\s*\)\s*>\s*16/i.test(sql);

  const finalizedReplayCheck = finalizeDefinition.search(/reservation_row\.state\s*=\s*'finalized'[\s\S]*?return\s*;/i);
  const reservedStateCheck = finalizeDefinition.search(/reservation_row\.state\s*<>\s*'reserved'/i);
  const expiryCheck = finalizeDefinition.search(/reservation_row\.expires_at\s*<=\s*transition_time/i);
  const accountLifecycleCheck = finalizeDefinition.search(/account_row\.deletion_state\s*<>\s*'active'/i);
  const bindingLifecycleCheck = finalizeDefinition.search(/if\s+not\s+exists\s*\(\s*select\s+1\s+from\s+public\.device_bindings\s+as\s+binding/i);
  const manifestMutation = finalizeDefinition.search(/insert\s+into\s+public\.blob_manifests/i);
  const finalizeLifecycleOrderIsExact = finalizedReplayCheck >= 0
    && reservedStateCheck > finalizedReplayCheck
    && expiryCheck > reservedStateCheck
    && accountLifecycleCheck > expiryCheck
    && bindingLifecycleCheck > accountLifecycleCheck
    && manifestMutation > bindingLifecycleCheck;

  const reserveIsExact = hardenedDefinition(reserveDefinition)
    && /\bvolatile\b/i.test(reserveDefinition)
    && /pg_catalog\.cardinality\s*\(\s*p_part_sizes\s*\)\s+not\s+between\s+1\s+and\s+16/i.test(reserveDefinition)
    && /part_size\s*>\s*33554432/i.test(reserveDefinition)
    && /requested_total_bytes\s*>\s*524288000/i.test(reserveDefinition)
    && /octet_length\s*\(\s*p_ciphertext_sha256\s*\)\s*<>\s*32/i.test(reserveDefinition)
    && /p_expires_at\s*<=\s*transition_time/i.test(reserveDefinition)
    && /from\s+public\.accounts\s+as\s+account[\s\S]*?for\s+update\s*;/i.test(reserveDefinition)
    && /account_row\.deletion_state\s*<>\s*'active'/i.test(reserveDefinition)
    && /binding\.state\s*=\s*'active'/i.test(reserveDefinition)
    && /binding\.revoked_at\s+is\s+null/i.test(reserveDefinition)
    && /binding\.expires_at\s+is\s+null\s+or\s+binding\.expires_at\s*>\s*transition_time/i.test(reserveDefinition)
    && /ambiguous\s+device\s+certificate/i.test(reserveDefinition)
    && /requested_total_bytes\s*>\s*account_row\.quota_limit_bytes\s*-\s*account_row\.used_bytes\s*-\s*account_row\.reserved_bytes/i.test(reserveDefinition)
    && /reserved_bytes\s*=\s*account\.reserved_bytes\s*\+\s*requested_total_bytes/i.test(reserveDefinition)
    && !/\b(?:insert\s+into|update|delete\s+from)\s+storage\./i.test(reserveDefinition)
    && ownerStatement('public', 'service_reserve_blob_upload', 'uuid\\s*,\\s*uuid\\s*,\\s*uuid\\s*,\\s*bytea\\s*,\\s*bigint\\[\\]\\s*,\\s*timestamptz');

  const finalizeIsExact = hardenedDefinition(finalizeDefinition)
    && /\bvolatile\b/i.test(finalizeDefinition)
    && accountLockBeforeReservation(finalizeDefinition)
    && finalizeLifecycleOrderIsExact
    && /account_row\.deletion_state\s*<>\s*'active'/i.test(finalizeDefinition)
    && /from\s+public\.device_bindings\s+as\s+binding[^;]*binding\.account_id\s*=\s*reservation_row\.account_id[^;]*binding\.device_id\s*=\s*reservation_row\.creator_device_id[^;]*binding\.state\s*=\s*'active'[^;]*binding\.revoked_at\s+is\s+null[^;]*binding\.expires_at\s+is\s+null\s+or\s+binding\.expires_at\s*>\s*transition_time/i.test(finalizeDefinition)
    && /reservation_row\.state\s*=\s*'finalized'[\s\S]*?return\s*;/i.test(finalizeDefinition)
    && /reservation_row\.expires_at\s*<=\s*transition_time/i.test(finalizeDefinition)
    && /from\s+storage\.objects\s+as\s+object/i.test(finalizeDefinition)
    && /jsonb_typeof\s*\(\s*object\.metadata\s*->\s*'size'\s*\)\s*=\s*'number'/i.test(finalizeDefinition)
    && /full\s+join\s+actual\s+using\s*\(\s*object_name\s*\)/i.test(finalizeDefinition)
    && /lpad\s*\([\s\S]*?8\s*,\s*'0'\s*\)[\s\S]*?'\.bin'/i.test(finalizeDefinition)
    && /actual_object_count\s*<>\s*reservation_row\.part_count/i.test(finalizeDefinition)
    && /reserved_bytes\s*=\s*account\.reserved_bytes\s*-\s*reservation_row\.expected_total_bytes/i.test(finalizeDefinition)
    && /used_bytes\s*=\s*account\.used_bytes\s*\+\s*reservation_row\.expected_total_bytes/i.test(finalizeDefinition)
    && ownerStatement('public', 'service_finalize_blob_upload', 'uuid');

  const releaseIsExact = hardenedDefinition(releaseDefinition)
    && /\bvolatile\b/i.test(releaseDefinition)
    && accountLockBeforeReservation(releaseDefinition)
    && /p_terminal_state\s+not\s+in\s*\([\s\S]*?'expired'[\s\S]*?'cancelled'/i.test(releaseDefinition)
    && /reservation_row\.state\s*=\s*p_terminal_state[\s\S]*?return\s*;/i.test(releaseDefinition)
    && /reservation_row\.state\s*<>\s*'reserved'/i.test(releaseDefinition)
    && /reservation_row\.expires_at\s*>\s*transition_time/i.test(releaseDefinition)
    && /reserved_bytes\s*=\s*account\.reserved_bytes\s*-\s*reservation_row\.expected_total_bytes/i.test(releaseDefinition)
    && !/used_bytes\s*=/i.test(releaseDefinition)
    && ownerStatement('public', 'service_release_blob_upload', 'uuid\\s*,\\s*context_relay_private\\.upload_reservation_state');

  const predicateIsExact = hardenedDefinition(uploadPredicateDefinition)
    && hardenedDefinition(readPredicateDefinition)
    && /\bstable\b/i.test(uploadPredicateDefinition)
    && /\bstable\b/i.test(readPredicateDefinition)
    && /jsonb_typeof\s*\(\s*p_metadata\s*->\s*'size'\s*\)\s*<>\s*'number'/i.test(uploadPredicateDefinition)
    && /\[0-9\]\{8\}\\\.bin\$/i.test(uploadPredicateDefinition)
    && /\[0-9\]\{8\}\\\.bin\$/i.test(readPredicateDefinition)
    && /current_write_account_id\s*\(\s*\)/i.test(uploadPredicateDefinition)
    && /current_write_device_id\s*\(\s*\)/i.test(uploadPredicateDefinition)
    && /from\s+context_relay_private\.blob_upload_reservations/i.test(uploadPredicateDefinition)
    && /current_read_account_id\s*\(\s*\)/i.test(readPredicateDefinition)
    && /from\s+public\.blob_manifests/i.test(readPredicateDefinition)
    && !/from\s+storage\.objects/i.test(uploadPredicateDefinition)
    && !/from\s+storage\.objects/i.test(readPredicateDefinition)
    && ownerStatement('context_relay_private', 'can_upload_ciphertext_object', 'text\\s*,\\s*text\\s*,\\s*jsonb')
    && ownerStatement('context_relay_private', 'can_read_ciphertext_object', 'text\\s*,\\s*text');

  const bucketIsExact = /\binsert\s+into\s+storage\.buckets\s*\(\s*id\s*,\s*name\s*,\s*public\s*,\s*file_size_limit\s*,\s*allowed_mime_types\s*\)[\s\S]*?values\s*\(\s*'ciphertext'\s*,\s*'ciphertext'\s*,\s*false\s*,\s*33554432\b/i.test(sql);

  if (!exactSignatures || !relationsAreExact || !reserveIsExact || !finalizeIsExact
      || !releaseIsExact || !predicateIsExact || !bucketIsExact) {
    violation(violations, 'migration-blob-storage', file.path, 'Task 5 must define exact quota-safe blob services, predicates, invariants, and private bucket configuration');
  }

  const grants = functionGrantStatements(sql);
  const targetedGrantPresent = grants.some((grant) => grant.functions.some((identity) => BLOB_SERVICE_FUNCTION_IDENTITIES.has(identity)));
  const blobFunctionPresent = [...BLOB_SERVICE_FUNCTION_NAMES].some((name) => new RegExp(`\\bfunction\\s+(?:public|context_relay_private)\\.${name}\\s*\\(`, 'i').test(sql));
  if (targetedGrantPresent || blobFunctionPresent) {
    const functionGrantsAreExact = [...BLOB_SERVICE_FUNCTION_IDENTITIES].every(([identity, expectedRole]) => {
      const matching = grants.filter((grant) => grant.functions.includes(identity));
      return matching.length === 1
        && matching[0].privileges.length === 1
        && matching[0].privileges[0] === 'execute'
        && matching[0].roles.length === 1
        && matching[0].roles[0] === expectedRole
        && !matching[0].hasGrantOption;
    });
    const revokesAreExact = /revoke\s+all\s+on\s+function\s+public\.service_reserve_blob_upload\s*\(\s*uuid\s*,\s*uuid\s*,\s*uuid\s*,\s*bytea\s*,\s*bigint\[\]\s*,\s*timestamptz\s*\)\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role/i.test(sql)
      && /revoke\s+all\s+on\s+function\s+public\.service_finalize_blob_upload\s*\(\s*uuid\s*\)\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role/i.test(sql)
      && /revoke\s+all\s+on\s+function\s+public\.service_release_blob_upload\s*\(\s*uuid\s*,\s*context_relay_private\.upload_reservation_state\s*\)\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role/i.test(sql)
      && /revoke\s+all\s+on\s+function\s+context_relay_private\.can_upload_ciphertext_object\s*\(\s*text\s*,\s*text\s*,\s*jsonb\s*\)\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role/i.test(sql)
      && /revoke\s+all\s+on\s+function\s+context_relay_private\.can_read_ciphertext_object\s*\(\s*text\s*,\s*text\s*\)\s+from\s+public\s*,\s*anon\s*,\s*authenticated\s*,\s*service_role/i.test(sql);
    const ownerMetadataReadIsNarrow = /grant\s+usage\s+on\s+schema\s+storage\s+to\s+context_relay_rls_owner/i.test(sql)
      && /grant\s+select\s+on\s+(?:table\s+)?storage\.objects\s+to\s+context_relay_rls_owner/i.test(sql)
      && !/revoke\s+[^;]*\s+on\s+(?:table\s+)?storage\.objects\b/i.test(sql)
      && !/revoke\s+[^;]*\s+on\s+schema\s+storage\b/i.test(sql);
    if (!functionGrantsAreExact || !revokesAreExact || !ownerMetadataReadIsNarrow) {
      violation(violations, 'migration-blob-storage-grants', file.path, 'blob wrappers, predicates, and owner metadata read must have only their exact narrow grants');
    }
  }

  const storagePolicies = [...sql.matchAll(/\bcreate\s+policy\s+(\w+)\s+on\s+storage\.objects[\s\S]*?;/gi)]
    .map((match) => match[0].replace(/\s+/g, ' ').trim().toLowerCase());
  const blobPolicySurfacePresent = storagePolicies.some((statement) => /\bciphertext_objects_|\bto authenticated\b/.test(statement));
  if (blobPolicySurfacePresent) {
    const exactPolicy = (name, command, role, predicate) => {
      const matching = storagePolicies.filter((statement) => statement.startsWith(`create policy ${name} on storage.objects `));
      return matching.length === 1
        && new RegExp(`\\bfor ${command}\\b`).test(matching[0])
        && new RegExp(`\\bto ${role}\\b`).test(matching[0])
        && predicate.test(matching[0]);
    };
    const policiesAreExact = storagePolicies.length === 3
      && exactPolicy('ciphertext_objects_authenticated_insert', 'insert', 'authenticated', /can_upload_ciphertext_object\s*\(\s*bucket_id\s*,\s*name\s*,\s*metadata\s*\)/)
      && exactPolicy(
        'ciphertext_objects_authenticated_select',
        'select',
        'authenticated',
        /can_read_ciphertext_object\s*\(\s*bucket_id\s*,\s*name\s*\)\s+or\s+\(\s*storage\.allow_only_operation\s*\(\s*'storage\.object\.upload'\s*\)\s+and\s+context_relay_private\.can_upload_ciphertext_object\s*\(\s*bucket_id\s*,\s*name\s*,\s*metadata\s*\)\s*\)/,
      )
      && exactPolicy('ciphertext_objects_rls_owner_select', 'select', 'context_relay_rls_owner', /bucket_id\s*=\s*'ciphertext'/)
      && !storagePolicies.some((statement) => /\bfor (?:update|delete)\b[\s\S]*?\bto authenticated\b/.test(statement));
    if (!policiesAreExact) {
      violation(violations, 'migration-blob-storage-policies', file.path, 'Storage must have exact authenticated INSERT and operation-scoped SELECT policies plus owner metadata SELECT');
    }
  }
}

function realtimePolicyTarget(tokens, command) {
  if (!sqlWord(tokens[0], command) || !sqlWord(tokens[1], 'policy')) return false;
  let index = 2;
  if (command === 'drop' && sqlWord(tokens[index], 'if') && sqlWord(tokens[index + 1], 'exists')) index += 2;
  if (!['word', 'quoted-identifier'].includes(tokens[index]?.type)) return false;
  index += 1;
  return sqlWord(tokens[index], 'on')
    && sqlQualifiedIdentifier(tokens, index + 1, 'realtime', 'messages');
}

function containsRealtimeMessages(tokens, start = 0, end = tokens.length) {
  for (let index = start; index < end; index += 1) {
    if (sqlQualifiedIdentifier(tokens, index, 'realtime', 'messages')) return true;
  }
  return false;
}

function realtimeProviderTableMutation(tokens, allowSeparatedProviderNames = false) {
  const mentionsProviderRelation = containsRealtimeMessages(tokens)
    || (allowSeparatedProviderNames
      && tokens.some((token) => sqlIdentifier(token, 'realtime'))
      && tokens.some((token) => sqlIdentifier(token, 'messages')));
  if (!mentionsProviderRelation) return false;
  for (let index = 0; index < tokens.length; index += 1) {
    const isTableDdl = (sqlWord(tokens[index], 'create')
        || sqlWord(tokens[index], 'alter')
        || sqlWord(tokens[index], 'drop'))
      && sqlWord(tokens[index + 1], 'table');
    const isTruncate = sqlWord(tokens[index], 'truncate');
    const isInsert = sqlWord(tokens[index], 'insert') && sqlWord(tokens[index + 1], 'into');
    const isUpdate = sqlWord(tokens[index], 'update');
    const isDelete = sqlWord(tokens[index], 'delete') && sqlWord(tokens[index + 1], 'from');
    const isMerge = sqlWord(tokens[index], 'merge') && sqlWord(tokens[index + 1], 'into');
    const isIndexDdl = (sqlWord(tokens[index], 'create') || sqlWord(tokens[index], 'drop'))
      && (sqlWord(tokens[index + 1], 'index')
        || (sqlWord(tokens[index + 1], 'unique') && sqlWord(tokens[index + 2], 'index')));
    if (isTableDdl || isTruncate || isInsert || isUpdate || isDelete || isMerge || isIndexDdl) return true;
  }
  return false;
}

function realtimePolicyMutation(tokens) {
  const mentionsProviderRelation = containsRealtimeMessages(tokens)
    || (tokens.some((token) => sqlIdentifier(token, 'realtime'))
      && tokens.some((token) => sqlIdentifier(token, 'messages')));
  if (!mentionsProviderRelation) return false;
  for (let index = 0; index < tokens.length; index += 1) {
    if ((sqlWord(tokens[index], 'create')
        || sqlWord(tokens[index], 'alter')
        || sqlWord(tokens[index], 'drop'))
      && sqlWord(tokens[index + 1], 'policy')) return true;
  }
  return false;
}

function exactRealtimePolicy(tokens) {
  const candidate = tokens.filter((token, index) => !(token.type === 'symbol'
    && token.value === ','
    && tokens[index + 1]?.type === 'symbol'
    && tokens[index + 1].value === '}'));
  if (sqlWord(candidate[7], 'as') && sqlWord(candidate[8], 'permissive')) candidate.splice(7, 2);
  const expected = [
    ['word', 'create'], ['word', 'policy'], ['identifier', 'context_relay_authenticated_sync_hint_read'],
    ['word', 'on'], ['identifier', 'realtime'], ['symbol', '.'], ['identifier', 'messages'],
    ['word', 'for'], ['word', 'select'], ['word', 'to'], ['identifier', 'authenticated'], ['word', 'using'],
    ['symbol', '('], ['identifier', 'extension'], ['symbol', '='], ['string', 'broadcast'], ['word', 'and'],
    ['symbol', '('], ['word', 'select'], ['identifier', 'realtime'], ['symbol', '.'], ['identifier', 'topic'],
    ['symbol', '('], ['symbol', ')'], ['symbol', ')'], ['symbol', '='], ['string', 'account:'], ['symbol', '||'],
    ['symbol', '('], ['word', 'select'], ['identifier', 'context_relay_private'], ['symbol', '.'],
    ['identifier', 'current_read_account_id'], ['symbol', '('], ['symbol', ')'], ['symbol', ')'],
    ['symbol', '::'], ['word', 'text'], ['symbol', '||'], ['string', ':sync'], ['symbol', ')'], ['symbol', ';'],
  ];
  if (candidate.length !== expected.length) return false;
  return expected.every(([type, value], index) => {
    if (type === 'identifier') return sqlIdentifier(candidate[index], value);
    return candidate[index]?.type === type && candidate[index].value === value;
  });
}

function changesRealtimeMessagePrivileges(tokens) {
  if (!sqlWord(tokens[0], 'grant') && !sqlWord(tokens[0], 'revoke')) return false;
  const onIndex = tokens.findIndex((token) => sqlWord(token, 'on'));
  if (onIndex < 0) return false;
  const boundary = tokens.findIndex((token, index) => index > onIndex
    && (sqlWord(token, 'to') || sqlWord(token, 'from')));
  const end = boundary < 0 ? tokens.length : boundary;
  for (let index = onIndex + 1; index < end; index += 1) {
    if (sqlQualifiedIdentifier(tokens, index, 'realtime', 'messages')) return true;
    if (sqlWord(tokens[index], 'all')
        && sqlWord(tokens[index + 1], 'tables')
        && sqlWord(tokens[index + 2], 'in')
        && sqlWord(tokens[index + 3], 'schema')) {
      for (let schemaIndex = index + 4; schemaIndex < end; schemaIndex += 1) {
        if (sqlIdentifier(tokens[schemaIndex], 'realtime')) return true;
      }
    }
  }
  return false;
}

function changesRealtimeMessagePrivilegesAnywhere(tokens) {
  for (let index = 0; index < tokens.length; index += 1) {
    if (changesRealtimeMessagePrivileges(tokens.slice(index))) return true;
  }
  return false;
}

function executableSqlTargetsRealtime(text, depth = 0) {
  if (depth > 4) return true;
  const statements = splitTopLevelSqlStatements(text).map(tokenizeSqlStatement);
  if (statements.some((tokens) => realtimeProviderTableMutation(tokens, true)
      || realtimePolicyMutation(tokens)
      || changesRealtimeMessagePrivilegesAnywhere(tokens))) return true;

  const executableFragments = statements.flatMap((tokens) => tokens)
    .filter((token) => token.type === 'string' || token.type === 'dollar-string')
    .map((token) => token.value);
  if (executableFragments.some((fragment) => executableSqlTargetsRealtime(fragment, depth + 1))) return true;
  return executableFragments.length > 1
    && executableSqlTargetsRealtime(executableFragments.join(' '), depth + 1);
}

function dynamicRealtimeMutation(tokens) {
  if (!sqlWord(tokens[0], 'do')) return false;
  return tokens
    .filter((token) => token.type === 'dollar-string')
    .some((token) => executableSqlTargetsRealtime(token.value));
}

function validateRealtimeHintPolicy(file, violations) {
  const statements = splitTopLevelSqlStatements(file.text).map(tokenizeSqlStatement);
  const createdPolicies = statements.filter((tokens) => realtimePolicyTarget(tokens, 'create'));
  const changedPolicies = statements.filter((tokens) => realtimePolicyTarget(tokens, 'alter') || realtimePolicyTarget(tokens, 'drop'));
  const providerMutations = statements.filter((tokens) => realtimeProviderTableMutation(tokens) || dynamicRealtimeMutation(tokens));
  const policyIsExact = createdPolicies.length === 1
    && changedPolicies.length === 0
    && providerMutations.length === 0
    && exactRealtimePolicy(createdPolicies[0]);

  if (!policyIsExact) {
    violation(
      violations,
      'migration-realtime-hint-policy',
      file.path,
      'Realtime must have exactly one authenticated Broadcast SELECT policy for the scalar exact account sync topic',
    );
  }

  if (statements.some(changesRealtimeMessagePrivileges)) {
    violation(
      violations,
      'migration-realtime-hint-grants',
      file.path,
      'Context Relay must not change provider privileges on realtime.messages',
    );
  }
}

function exactJavaScriptTokens(actual, expected) {
  const candidate = actual.filter((token, index) => !(token.type === 'symbol'
    && token.value === ','
    && actual[index + 1]?.type === 'symbol'
    && actual[index + 1].value === '}'));
  return candidate.length === expected.length
    && expected.every(([type, value], index) => candidate[index]?.type === type && candidate[index].value === value);
}

function javaScriptStatement(tokens, start) {
  const end = tokens.findIndex((token, index) => index >= start
    && token.type === 'symbol'
    && token.value === ';');
  return end < 0 ? [] : tokens.slice(start, end + 1);
}

function namedConstDeclarations(tokens, name) {
  return tokens
    .map((token, index) => ({ token, index }))
    .filter(({ token, index }) => token.type === 'identifier'
      && token.value === 'const'
      && tokens[index + 1]?.type === 'identifier'
      && tokens[index + 1].value === name
      && tokens[index + 2]?.type === 'symbol'
      && tokens[index + 2].value === '=')
    .map(({ index }) => index);
}

function exactNamedConst(tokens, name, expected) {
  const declarations = namedConstDeclarations(tokens, name);
  return declarations.length === 1
    && exactJavaScriptTokens(javaScriptStatement(tokens, declarations[0]), expected);
}

function ownChannelAssignments(tokens) {
  return tokens
    .map((token, index) => ({ token, index }))
    .filter(({ token, index }) => token.type === 'identifier'
      && token.value === 'ownChannels'
      && tokens[index + 1]?.type === 'symbol'
      && tokens[index + 1].value === '['
      && tokens[index + 2]?.type === 'identifier'
      && tokens[index + 2].value === 'label'
      && tokens[index + 3]?.type === 'symbol'
      && tokens[index + 3].value === ']'
      && tokens[index + 4]?.type === 'symbol'
      && tokens[index + 4].value === '=')
    .map(({ index }) => index);
}

function namedFunctionBodies(tokens, name) {
  const bodies = [];
  for (let index = 1; index < tokens.length; index += 1) {
    if (tokens[index]?.type !== 'identifier'
        || tokens[index].value !== name
        || tokens[index - 1]?.type !== 'identifier'
        || tokens[index - 1].value !== 'function'
        || tokens[index + 1]?.type !== 'symbol'
        || tokens[index + 1].value !== '(') continue;
    let parentheses = 1;
    let cursor = index + 2;
    while (cursor < tokens.length && parentheses > 0) {
      if (tokens[cursor]?.type === 'symbol' && tokens[cursor].value === '(') parentheses += 1;
      if (tokens[cursor]?.type === 'symbol' && tokens[cursor].value === ')') parentheses -= 1;
      cursor += 1;
    }
    if (parentheses !== 0 || tokens[cursor]?.type !== 'symbol' || tokens[cursor].value !== '{') continue;
    const bodyStart = cursor + 1;
    let braces = 1;
    cursor = bodyStart;
    while (cursor < tokens.length && braces > 0) {
      if (tokens[cursor]?.type === 'symbol' && tokens[cursor].value === '{') braces += 1;
      if (tokens[cursor]?.type === 'symbol' && tokens[cursor].value === '}') braces -= 1;
      cursor += 1;
    }
    if (braces === 0) bodies.push(tokens.slice(bodyStart, cursor - 1));
  }
  return bodies;
}

function validateRealtimeHintContract(file, violations) {
  if (file.path !== 'scripts/verify-supabase-realtime.mjs') return;
  const tokens = tokenizeJavaScript(file.text);
  const declarations = topLevelJavaScriptIndexes(tokens, 'export', 'const')
    .filter((index) => tokens[index + 2]?.type === 'identifier' && tokens[index + 2].value === 'REALTIME_HINT');
  const declarationEnd = declarations.length === 1
    ? tokens.findIndex((token, index) => index > declarations[0] && token.type === 'symbol' && token.value === ';')
    : -1;
  const declaration = declarationEnd < 0 ? [] : tokens.slice(declarations[0], declarationEnd + 1);
  const payload = REALTIME_HINT_CONTRACT.payload;
  const expectedDeclaration = [
    ['identifier', 'export'], ['identifier', 'const'], ['identifier', 'REALTIME_HINT'], ['symbol', '='],
    ['identifier', 'Object'], ['symbol', '.'], ['identifier', 'freeze'], ['symbol', '('], ['symbol', '{'],
    ['identifier', 'event'], ['symbol', ':'], ['string', REALTIME_HINT_CONTRACT.event], ['symbol', ','],
    ['identifier', 'payload'], ['symbol', ':'], ['identifier', 'Object'], ['symbol', '.'], ['identifier', 'freeze'],
    ['symbol', '('], ['symbol', '{'], ['identifier', 'version'], ['symbol', ':'], ['number', String(payload.version)],
    ['symbol', ','], ['identifier', 'kind'], ['symbol', ':'], ['string', payload.kind], ['symbol', '}'], ['symbol', ')'],
    ['symbol', ','], ['identifier', 'private'], ['symbol', ':'], ['identifier', String(REALTIME_HINT_CONTRACT.private)],
    ['symbol', '}'], ['symbol', ')'], ['symbol', ';'],
  ];

  const topicFunctions = topLevelJavaScriptIndexes(tokens, 'function', 'topicFor');
  const expectedTopicFunction = [
    ['identifier', 'function'], ['identifier', 'topicFor'], ['symbol', '('], ['identifier', 'accountId'], ['symbol', ')'],
    ['symbol', '{'], ['identifier', 'return'], ['template', 'account:${accountId}:sync'], ['symbol', ';'], ['symbol', '}'],
  ];
  const topicFunction = topicFunctions.length === 1
    ? tokens.slice(topicFunctions[0], topicFunctions[0] + expectedTopicFunction.length)
    : [];
  const verificationBodies = namedFunctionBodies(tokens, 'verifyRealtimeVerifier');
  const verificationTokens = verificationBodies.length === 1 ? verificationBodies[0] : [];
  const topicCalls = verificationTokens
    .map((token, index) => ({ token, index }))
    .filter(({ token, index }) => token.type === 'identifier'
      && token.value === 'topicFor'
      && verificationTokens[index + 1]?.type === 'symbol'
      && verificationTokens[index + 1].value === '(')
    .map(({ index }) => verificationTokens.slice(index, index + 10));
  const expectedTopicCall = (label) => [
    ['identifier', 'topicFor'], ['symbol', '('], ['identifier', 'state'], ['symbol', '.'], ['identifier', 'users'],
    ['symbol', '.'], ['identifier', label], ['symbol', '.'], ['identifier', 'accountId'], ['symbol', ')'],
  ];
  const expectedTopics = [
    ['identifier', 'const'], ['identifier', 'topics'], ['symbol', '='], ['symbol', '{'],
    ['identifier', 'a'], ['symbol', ':'], ...expectedTopicCall('a'), ['symbol', ','],
    ['identifier', 'b'], ['symbol', ':'], ...expectedTopicCall('b'), ['symbol', '}'], ['symbol', ';'],
  ];
  const expectedOwnChannel = [
    ['identifier', 'ownChannels'], ['symbol', '['], ['identifier', 'label'], ['symbol', ']'], ['symbol', '='],
    ['identifier', 'privateChannel'], ['symbol', '('], ['identifier', 'userClients'], ['symbol', '['],
    ['identifier', 'label'], ['symbol', ']'], ['symbol', ','], ['identifier', 'topics'], ['symbol', '['],
    ['identifier', 'label'], ['symbol', ']'], ['symbol', ')'], ['symbol', ';'],
  ];
  const expectedCrossChannels = [
    ['identifier', 'const'], ['identifier', 'crossChannels'], ['symbol', '='], ['symbol', '{'],
    ['identifier', 'a'], ['symbol', ':'], ['identifier', 'privateChannel'], ['symbol', '('],
    ['identifier', 'userClients'], ['symbol', '.'], ['identifier', 'a'], ['symbol', ','],
    ['identifier', 'topics'], ['symbol', '.'], ['identifier', 'b'], ['symbol', ')'], ['symbol', ','],
    ['identifier', 'b'], ['symbol', ':'], ['identifier', 'privateChannel'], ['symbol', '('],
    ['identifier', 'userClients'], ['symbol', '.'], ['identifier', 'b'], ['symbol', ','],
    ['identifier', 'topics'], ['symbol', '.'], ['identifier', 'a'], ['symbol', ')'], ['symbol', '}'], ['symbol', ';'],
  ];
  const expectedServiceChannels = [
    ['identifier', 'const'], ['identifier', 'serviceChannels'], ['symbol', '='], ['symbol', '{'],
    ['identifier', 'a'], ['symbol', ':'], ['identifier', 'privateChannel'], ['symbol', '('],
    ['identifier', 'serviceClient'], ['symbol', ','], ['identifier', 'topics'], ['symbol', '.'],
    ['identifier', 'a'], ['symbol', ')'], ['symbol', ','],
    ['identifier', 'b'], ['symbol', ':'], ['identifier', 'privateChannel'], ['symbol', '('],
    ['identifier', 'serviceClient'], ['symbol', ','], ['identifier', 'topics'], ['symbol', '.'],
    ['identifier', 'b'], ['symbol', ')'], ['symbol', '}'], ['symbol', ';'],
  ];
  const expectedFreshChannel = [
    ['identifier', 'const'], ['identifier', 'freshAChannel'], ['symbol', '='],
    ['identifier', 'privateChannel'], ['symbol', '('], ['identifier', 'freshAClient'], ['symbol', ','],
    ['identifier', 'topics'], ['symbol', '.'], ['identifier', 'a'], ['symbol', ')'], ['symbol', ';'],
  ];
  const expectedSend = [
    ['identifier', 'const'], ['identifier', 'sendResult'], ['symbol', '='], ['identifier', 'await'],
    ['identifier', 'serviceChannels'], ['symbol', '['], ['identifier', 'label'], ['symbol', ']'], ['symbol', '.'],
    ['identifier', 'send'], ['symbol', '('], ['symbol', '{'],
    ['identifier', 'type'], ['symbol', ':'], ['string', 'broadcast'], ['symbol', ','],
    ['identifier', 'event'], ['symbol', ':'], ['identifier', 'REALTIME_HINT'], ['symbol', '.'],
    ['identifier', 'event'], ['symbol', ','],
    ['identifier', 'payload'], ['symbol', ':'], ['identifier', 'REALTIME_HINT'], ['symbol', '.'],
    ['identifier', 'payload'], ['symbol', '}'], ['symbol', ')'], ['symbol', ';'],
  ];
  const ownAssignments = ownChannelAssignments(verificationTokens);
  const dataflowIsExact = verificationBodies.length === 1
    && exactNamedConst(verificationTokens, 'topics', expectedTopics)
    && ownAssignments.length === 1
    && exactJavaScriptTokens(javaScriptStatement(verificationTokens, ownAssignments[0]), expectedOwnChannel)
    && exactNamedConst(verificationTokens, 'crossChannels', expectedCrossChannels)
    && exactNamedConst(verificationTokens, 'serviceChannels', expectedServiceChannels)
    && exactNamedConst(verificationTokens, 'freshAChannel', expectedFreshChannel)
    && exactNamedConst(verificationTokens, 'sendResult', expectedSend);
  const contractIsExact = declarations.length === 1
    && exactJavaScriptTokens(declaration, expectedDeclaration)
    && topicFunctions.length === 1
    && exactJavaScriptTokens(topicFunction, expectedTopicFunction)
    && topicCalls.length === 2
    && ['a', 'b'].every((label) => topicCalls.some((call) => exactJavaScriptTokens(call, expectedTopicCall(label))))
    && dataflowIsExact;

  if (!contractIsExact) {
    violation(
      violations,
      'realtime-hint-contract',
      file.path,
      'Realtime hints must use the frozen private account sync topic, event, and pull-only payload allowlist',
    );
  }
}

function validateWorkflow(workflow, violations) {
  if (workflow === null) return;
  const requiredCommands = [
    'pnpm check:supabase',
    'node --test scripts/tests/check-supabase-contract.test.mjs',
    'node --test scripts/tests/verify-supabase-realtime.test.mjs',
    'pnpm supabase:start:ci',
    'pnpm supabase:reset',
    'pnpm supabase:test',
    'pnpm supabase:lint',
    'pnpm supabase:stop',
  ];
  const requiredPaths = [
    "'scripts/verify-supabase-realtime.mjs'",
    "'scripts/tests/verify-supabase-realtime.test.mjs'",
  ];
  if (!requiredCommands.every((command) => workflow.includes(command))
      || !requiredPaths.every((pathFilter) => workflow.split(pathFilter).length - 1 === 2)
      || !/if:\s*always\(\)/.test(workflow)) {
    violation(violations, 'ci-supabase-commands', '.github/workflows/supabase.yml', 'workflow must run both contract suites, reset, pgTAP test, lint, always clean up, and trigger for live-verifier changes');
  }
}

export function validateSupabaseContract(root, { requireMigration = false } = {}) {
  const violations = [];
  validateConfig(readIfPresent(root, 'supabase/config.toml'), violations);
  const migrations = sqlFiles(root);
  const foundation = migrations.find((file) => file.path === FOUNDATION_MIGRATION);
  for (const file of migrations) {
    validateMigration(file, violations, {
      requireBaseline: file.path === FOUNDATION_MIGRATION || (migrations.length === 1 && foundation === undefined),
    });
  }
  if (foundation) {
    validateFoundationMigration(
      foundation,
      violations,
      migrations.map((migration) => migration.text).join('\n'),
    );
    validateBlobStorageBoundary(foundation, violations);
    validateRealtimeHintPolicy({
      path: foundation.path,
      text: migrations.map((migration) => migration.text).join('\n'),
    }, violations);
  }
  if (requireMigration && !foundation) {
    violation(violations, 'migration-required', FOUNDATION_MIGRATION, 'canonical Context Relay foundation migration is missing');
  }
  for (const file of applicationContractFiles(root)) {
    if (/signed[ _-]?url/i.test(file.text)) violation(violations, 'signed-url-contract', file.path, 'signed URLs are not part of the ciphertext boundary');
    validateRealtimeHintContract(file, violations);
  }
  validateWorkflow(readIfPresent(root, '.github/workflows/supabase.yml'), violations);
  return violations;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const violations = validateSupabaseContract(process.cwd(), { requireMigration: true });
  for (const item of violations) console.error(`${item.path}: ${item.ruleId}: ${item.message}`);
  process.exitCode = violations.length === 0 ? 0 : 1;
}
