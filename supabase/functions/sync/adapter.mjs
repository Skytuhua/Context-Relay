const MAX_SYNC_OPERATIONS = 256;
const SAFE_PROVIDER_CODES = new Set([
  "auth_required",
  "revoked",
  "quota_blocked",
  "integrity_quarantined",
  "conflict",
  "configuration_error",
]);
const PROVIDER_MESSAGE_CODES = new Map([
  ["invalid_envelope", "integrity_quarantined"],
  ["certificate_chain_invalid", "integrity_quarantined"],
  ["duplicate_operation_mismatch", "integrity_quarantined"],
  ["duplicate_checkpoint_mismatch", "integrity_quarantined"],
  ["device_sequence_gap", "integrity_quarantined"],
  ["device_hash_mismatch", "integrity_quarantined"],
  ["checkpoint_chain_mismatch", "integrity_quarantined"],
  ["blob_storage_conflict", "conflict"],
]);
const CLIENT_OPTIONS = Object.freeze({
  auth: Object.freeze({
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false,
  }),
});

function providerError(error, fallback = "transient") {
  const message = typeof error?.message === "string" ? error.message : "";
  const code = SAFE_PROVIDER_CODES.has(message)
    ? message
    : (PROVIDER_MESSAGE_CODES.get(message) ?? fallback);
  return Object.assign(new Error(code), { code });
}

function requiredEnvironment(env, name) {
  const value = env?.[name];
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw providerError(null, "configuration_error");
  }
  return value;
}

function projectUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw providerError(null, "configuration_error");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.pathname !== "" && url.pathname !== "/")
  ) {
    throw providerError(null, "configuration_error");
  }
  return url.origin;
}

function uuid(value) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
  ) {
    throw providerError(null, "integrity_quarantined");
  }
  return value;
}

function integer(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw providerError(null, "integrity_quarantined");
  }
  return value;
}

function hexToBytes(value, length) {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) {
    throw providerError(null, "integrity_quarantined");
  }
  const output = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function bytesToHex(value, length) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw providerError(null, "integrity_quarantined");
  }
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(value) {
  if (!(value instanceof Uint8Array)) throw providerError(null, "integrity_quarantined");
  let binary = "";
  for (let offset = 0; offset < value.length; offset += 0x8000) {
    binary += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function exactReceipt(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    !Array.isArray(value.accepted) ||
    !Array.isArray(value.duplicates) ||
    Object.keys(value).length !== 2
  ) {
    throw providerError(null);
  }
  return { accepted: [...value.accepted], duplicates: [...value.duplicates] };
}

function exactCheckpointReceipt(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.canonicalHash !== "string" ||
    typeof value.duplicate !== "boolean" ||
    Object.keys(value).length !== 2
  ) {
    throw providerError(null);
  }
  return {
    canonicalHash: hexToBytes(value.canonicalHash, 32),
    duplicate: value.duplicate,
  };
}

function serializeOperation(operation) {
  return {
    operationId: operation.operationId,
    accountId: operation.accountId,
    workspaceId: operation.workspaceId,
    projectId: operation.projectId,
    recordId: operation.recordId,
    recordKind: operation.recordKind,
    mutationKind: operation.mutationKind,
    deviceId: operation.deviceId,
    schemaVersion: operation.schemaVersion,
    deviceSequence: operation.deviceSequence,
    causalFrontier: operation.causalFrontier,
    controlEpoch: operation.controlEpoch,
    keyEpoch: operation.keyEpoch,
    previousDeviceHash: bytesToHex(operation.previousDeviceHash, 32),
    nonce: bytesToHex(operation.nonce, 24),
    ciphertextBase64: bytesToBase64(operation.ciphertext),
    ciphertextHash: bytesToHex(operation.ciphertextHash, 32),
    blobRefs: operation.blobRefs.map((blob) => ({
      digest: bytesToHex(blob.digest, 32),
      ciphertextBytes: blob.ciphertextBytes,
      storageId: blob.storageId,
    })),
    createdHlc: operation.createdHlc,
    signature: bytesToHex(operation.signature, 64),
    canonicalSha256: bytesToHex(operation.canonicalSha256, 32),
  };
}

function serializeCheckpoint(checkpoint) {
  return {
    schemaVersion: checkpoint.schemaVersion,
    accountId: checkpoint.accountId,
    workspaceId: checkpoint.workspaceId,
    previousCheckpointHash: bytesToHex(checkpoint.previousCheckpointHash, 32),
    causalFrontier: checkpoint.causalFrontier,
    stateHash: bytesToHex(checkpoint.stateHash, 32),
    keyEpoch: checkpoint.keyEpoch,
    creatorDeviceId: checkpoint.creatorDeviceId,
    createdHlc: checkpoint.createdHlc,
    signature: bytesToHex(checkpoint.signature, 64),
    canonicalSha256: bytesToHex(checkpoint.canonicalSha256, 32),
  };
}

function decodeIdentityContext(data, identity) {
  if (data === null || typeof data !== "object") throw providerError(null);
  return {
    accountId: uuid(data.accountId),
    workspaceId: uuid(data.workspaceId),
    deviceId: uuid(data.deviceId),
    certificateId: uuid(data.certificateId),
    controlEpoch: integer(data.controlEpoch),
    keyEpoch: integer(data.keyEpoch),
    signingPublicKey: hexToBytes(data.signingPublicKey, 32),
    certificateChain: Array.isArray(data.certificateChain) ? data.certificateChain : [],
    recoverySigningPublicKey: data.recoverySigningPublicKey,
    authenticatedUserId: uuid(identity.userId),
    authenticatedSessionId: uuid(identity.sessionId),
  };
}

function exactBlobTicket(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.storageId !== "string" ||
    !Array.isArray(value.paths) ||
    typeof value.expiresAt !== "string" ||
    Object.keys(value).length !== 3 ||
    value.paths.some((path) => typeof path !== "string")
  ) {
    throw providerError(null);
  }
  return {
    storageId: uuid(value.storageId),
    paths: [...value.paths],
    expiresAt: value.expiresAt,
  };
}

function exactBlobTransition(value, expectedState) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.storageId !== "string" ||
    value.state !== expectedState ||
    Object.keys(value).length !== 2
  ) {
    throw providerError(null);
  }
  return { storageId: uuid(value.storageId), state: expectedState };
}

export function createSupabaseSyncDependencies({ createClient, env }) {
  if (typeof createClient !== "function") throw providerError(null, "configuration_error");
  const url = projectUrl(requiredEnvironment(env, "SUPABASE_URL"));
  const publishableKey = requiredEnvironment(env, "SUPABASE_PUBLISHABLE_KEY");
  const secretKey = requiredEnvironment(env, "CONTEXT_RELAY_SUPABASE_SECRET_KEY");
  const authClient = createClient(url, publishableKey, CLIENT_OPTIONS);
  const serviceClient = createClient(url, secretKey, CLIENT_OPTIONS);

  return {
    async authenticate(token) {
      let result;
      try {
        result = await authClient.auth.getClaims(token);
      } catch (error) {
        throw providerError(error, "auth_required");
      }
      if (result?.error !== null || result?.data?.claims === undefined) {
        throw providerError(result?.error, "auth_required");
      }
      const claims = result.data.claims;
      return {
        userId: uuid(claims.sub),
        sessionId: uuid(claims.session_id),
      };
    },

    async loadIdentityContext(identity, route) {
      let result;
      try {
        result = await serviceClient.rpc("service_sync_identity_context", {
          p_auth_user_id: uuid(identity.userId),
          p_session_id: uuid(identity.sessionId),
          p_workspace_id: uuid(route.workspaceId),
          p_device_id: uuid(route.deviceId),
        });
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null || result?.data === null || typeof result?.data !== "object") {
        throw providerError(result?.error);
      }
      return decodeIdentityContext(result.data, identity);
    },

    async loadSessionContext(identity, route) {
      let result;
      try {
        result = await serviceClient.rpc("service_sync_session_context", {
          p_auth_user_id: uuid(identity.userId),
          p_session_id: uuid(identity.sessionId),
          p_workspace_id: uuid(route.workspaceId),
        });
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null || result?.data === null || typeof result?.data !== "object") {
        throw providerError(result?.error);
      }
      return decodeIdentityContext(result.data, identity);
    },

    async appendOperations(context, operations) {
      if (
        !Array.isArray(operations) ||
        operations.length === 0 ||
        operations.length > MAX_SYNC_OPERATIONS
      ) {
        throw providerError(null, "integrity_quarantined");
      }
      let result;
      try {
        result = await serviceClient.rpc("service_append_sync_operations", {
          p_auth_user_id: uuid(context.authenticatedUserId),
          p_session_id: uuid(context.authenticatedSessionId),
          p_operations: operations.map(serializeOperation),
        });
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null) throw providerError(result?.error);
      return exactReceipt(result?.data);
    },

    async appendCheckpoint(context, checkpoint) {
      let result;
      try {
        result = await serviceClient.rpc("service_append_sync_checkpoint", {
          p_auth_user_id: uuid(context.authenticatedUserId),
          p_session_id: uuid(context.authenticatedSessionId),
          p_checkpoint: serializeCheckpoint(checkpoint),
        });
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null) throw providerError(result?.error);
      return exactCheckpointReceipt(result?.data);
    },

    async reserveBlob(context, reservation) {
      let result;
      try {
        result = await serviceClient.rpc("service_reserve_blob_upload_for_session", {
          p_auth_user_id: uuid(context.authenticatedUserId),
          p_session_id: uuid(context.authenticatedSessionId),
          p_workspace_id: uuid(context.workspaceId),
          p_storage_id: uuid(reservation.storageId),
          p_ciphertext_sha256: `\\x${bytesToHex(reservation.ciphertextSha256, 32)}`,
          p_part_sizes: reservation.partSizes,
          p_expires_at: reservation.expiresAt,
        });
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null) throw providerError(result?.error);
      return exactBlobTicket(result?.data);
    },

    async finalizeBlob(identity, storageId) {
      let result;
      try {
        result = await serviceClient.rpc("service_finalize_blob_upload_for_session", {
          p_auth_user_id: uuid(identity.userId),
          p_session_id: uuid(identity.sessionId),
          p_storage_id: uuid(storageId),
        });
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null) throw providerError(result?.error);
      return exactBlobTransition(result?.data, "finalized");
    },

    async releaseBlob(identity, storageId) {
      let result;
      try {
        result = await serviceClient.rpc("service_release_blob_upload_for_session", {
          p_auth_user_id: uuid(identity.userId),
          p_session_id: uuid(identity.sessionId),
          p_storage_id: uuid(storageId),
        });
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null) throw providerError(result?.error);
      return exactBlobTransition(result?.data, "cancelled");
    },

    async broadcastPullNow(accountId) {
      let result;
      try {
        result = await serviceClient.rpc("service_send_sync_hint", {
          p_account_id: uuid(accountId),
        });
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null || result?.data?.sent !== true) {
        throw providerError(result?.error);
      }
    },
  };
}
