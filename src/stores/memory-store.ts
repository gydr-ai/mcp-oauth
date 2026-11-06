import {
  DEFAULT_DYNAMIC_CLIENT_IDLE_SECONDS,
  DEFAULT_MEMORY_STORE_ENTRIES,
} from "../constants/defaults.js"
import type { MemoryStoreOptions } from "../interfaces/memory-store.js"
import type {
  AccessTokenRecord,
  AuthorizationCodeRecord,
  ClientRecord,
  ConsentRequest,
  ConsumedAuthorizationCode,
  GrantRecord,
  GrantUpstreamUpdate,
  PendingAuthorization,
  RefreshTokenRecord,
  UsedRefreshToken,
} from "../interfaces/records.js"
import type { OAuthStore } from "../interfaces/store.js"
import { ClientCollection } from "./client-collection.js"
import { Collection } from "./collection.js"
import { checkedClock } from "../helpers/time.js"

const expiry = (value: { readonly expiresAt: number }) => value.expiresAt

/**
 * Run synchronous store logic and report its outcome as a promise.
 *
 * @param work - Synchronous store operation; anything it throws becomes the rejection.
 * @returns Resolves with `work`'s result, or rejects with what it threw.
 */
function settle<T>(work: () => T): Promise<T> {
  try {
    return Promise.resolve(work())
  } catch (error) {
    return Promise.reject(
      error instanceof Error ? error : new Error("Memory store failure"),
    )
  }
}

/**
 * An in-memory {@link OAuthStore}.
 *
 * **Single process, development and tests only.** Everything is lost on
 * restart (every client must register again and every person must
 * reconnect), and two processes never see each other's state. Its atomic
 * operations are correct only because Node.js runs them on one thread with no
 * `await` between the read and the write.
 *
 * @param options - Capacity, dynamic-client idle lifetime and clock.
 * @returns An `OAuthStore` held in this process's memory.
 * @example
 * ```ts
 * import { createMemoryStore } from "@gydr-ai/mcp-oauth"
 *
 * // Development and tests only: state is lost on restart.
 * export const store = createMemoryStore({ maxEntriesPerCollection: 10_000 })
 * ```
 */
export function createMemoryStore(
  options: MemoryStoreOptions = {},
): OAuthStore {
  const max = options.maxEntriesPerCollection ?? DEFAULT_MEMORY_STORE_ENTRIES
  const now = checkedClock(options.now ?? Date.now)
  const clients = new ClientCollection(
    max,
    (options.dynamicClientIdleSeconds ?? DEFAULT_DYNAMIC_CLIENT_IDLE_SECONDS) *
      1000,
    now,
  )
  const metadata = new Collection<{
    client: ClientRecord
    expiresAt: number
  }>(max, now, expiry)
  const pending = new Collection<PendingAuthorization>(max, now, expiry)
  const consents = new Collection<ConsentRequest>(max, now, expiry)
  const outcomes = new Collection<{
    sealedLocation: string
    expiresAt: number
  }>(max, now, expiry)
  const codes = new Collection<{
    record: AuthorizationCodeRecord
    consumed: boolean
    expiresAt: number
  }>(max, now, expiry)
  const grants = new Collection<GrantRecord>(max, now, expiry, (grant) => {
    clients.grantRemoved(grant.clientId)
  })
  const access = new Collection<AccessTokenRecord>(max, now, expiry)
  const refresh = new Collection<RefreshTokenRecord>(max, now, expiry)

  return {
    getClient(clientId) {
      return settle(() => {
        return clients.get(clientId)
      })
    },
    putClient(client) {
      return settle(() => {
        clients.put(client)
      })
    },
    getCachedClientMetadata(url) {
      return settle(() => {
        return metadata.get(url)?.client
      })
    },
    putCachedClientMetadata(url, client, expiresAt) {
      return settle(() => {
        metadata.set(url, { client, expiresAt })
      })
    },
    putPendingAuthorization(record) {
      return settle(() => {
        pending.set(record.id, record)
      })
    },
    getPendingAuthorization(id) {
      return settle(() => {
        return pending.get(id)
      })
    },
    consumePendingAuthorization(id) {
      return settle(() => {
        return pending.take(id)
      })
    },
    putConsentRequest(record) {
      return settle(() => {
        consents.set(record.id, record)
      })
    },
    getConsentRequest(id) {
      return settle(() => consents.peek(id))
    },
    putConsentOutcome(key, sealedLocation, expiresAt) {
      return settle(() => {
        outcomes.set(key, { sealedLocation, expiresAt })
      })
    },
    getConsentOutcome(key) {
      return settle(() => outcomes.get(key)?.sealedLocation)
    },
    listGrantsBySubject(subject) {
      return settle(() => grants.values().filter((g) => g.subject === subject))
    },
    consumeConsentRequest(id) {
      return settle(() => {
        // Returned even when expired, so its upstream token can be revoked.
        return consents.take(id, true)
      })
    },
    putAuthorizationCode(record) {
      return settle(() => {
        codes.set(record.codeHash, {
          record,
          consumed: false,
          expiresAt: record.expiresAt,
        })
      })
    },
    getAuthorizationCode(codeHash) {
      return settle(() => {
        const entry = codes.get(codeHash)

        return entry === undefined
          ? undefined
          : { record: entry.record, consumed: entry.consumed }
      })
    },
    consumeAuthorizationCode(codeHash) {
      return settle(() => {
        // The consumed record stays until it expires, so a replay is seen.
        const entry = codes.get(codeHash)

        if (entry === undefined) return undefined

        const result: ConsumedAuthorizationCode = {
          record: entry.record,
          firstUse: !entry.consumed,
        }

        codes.set(codeHash, { ...entry, consumed: true })

        return result
      })
    },
    putGrant(grant) {
      return settle(() => {
        // Count first: replacing or evicting a grant reports its removal
        // through the collection callback.
        clients.grantAdded(grant.clientId)
        grants.set(grant.grantId, grant)
      })
    },
    getGrant(grantId) {
      return settle(() => {
        return grants.get(grantId)
      })
    },
    updateGrant(grantId, update: GrantUpstreamUpdate) {
      return settle(() => {
        const grant = grants.get(grantId)

        if (grant === undefined) return false

        clients.grantAdded(grant.clientId)
        grants.set(grantId, { ...grant, ...update })

        return true
      })
    },
    deleteGrant(grantId) {
      return settle(() => {
        const removed = grants.take(grantId, true)

        access.deleteWhere((token) => token.grantId === grantId)
        refresh.deleteWhere((token) => token.grantId === grantId)
        codes.deleteWhere((code) => code.record.grantId === grantId)

        return removed
      })
    },
    putAccessToken(token) {
      return settle(() => {
        access.set(token.tokenHash, token)
      })
    },
    getAccessToken(tokenHash) {
      return settle(() => {
        return access.get(tokenHash)
      })
    },
    deleteAccessToken(tokenHash) {
      return settle(() => {
        access.delete(tokenHash)
      })
    },
    putRefreshToken(token) {
      return settle(() => {
        refresh.set(token.tokenHash, token)
      })
    },
    getRefreshToken(tokenHash) {
      return settle(() => {
        return refresh.get(tokenHash)
      })
    },
    useRefreshToken(tokenHash, usedAt): Promise<UsedRefreshToken | undefined> {
      return settle(() => {
        const token = refresh.get(tokenHash)

        if (token === undefined) return undefined

        if (token.usedAt !== undefined) {
          return { record: token, previousUsedAt: token.usedAt }
        }

        const marked = { ...token, usedAt }

        refresh.set(tokenHash, marked)

        return { record: marked }
      })
    },
    putRefreshTokenReplacement(tokenHash, sealedReplacement) {
      return settle(() => {
        const token = refresh.get(tokenHash)

        if (token !== undefined) {
          refresh.set(tokenHash, { ...token, sealedReplacement })
        }
      })
    },
  }
}
