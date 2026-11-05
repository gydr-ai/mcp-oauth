import type { ClientRecord } from "../interfaces/records.js"
import { hasExpired } from "../helpers/time.js"

/**
 * Clients, split so a registration flood can never push out a client people
 * are connected through:
 *
 * - `#held`: clients with at least one grant in the store, and static
 *   clients. Never evicted; bounded indirectly by the grant collection.
 * - `#idle`: dynamic clients with no grant, in least-recently-used order.
 *   Bounded by `max` (the least recently used is evicted, O(1)) and by the
 *   idle lifetime.
 *
 * @internal
 */
export class ClientCollection {
  readonly #held = new Map<string, ClientRecord>()
  readonly #idle = new Map<string, { client: ClientRecord; usedAt: number }>()
  readonly #grantCounts = new Map<string, number>()
  readonly #max: number
  readonly #idleMs: number
  readonly #now: () => number

  /**
   *
   * @param max - Most grant-less dynamic clients held; the least recently used is evicted beyond it.
   * @param idleMs - Milliseconds a grant-less dynamic client may go unused before it is dropped.
   * @param now - Clock in milliseconds since the epoch.
   */
  constructor(max: number, idleMs: number, now: () => number) {
    this.#max = max
    this.#idleMs = idleMs
    this.#now = now
  }

  #toIdle(client: ClientRecord): void {
    this.#idle.delete(client.clientId)

    while (this.#idle.size >= this.#max) {
      const oldest = this.#idle.keys().next()

      if (oldest.done === true) break

      this.#idle.delete(oldest.value)
    }

    this.#idle.set(client.clientId, { client, usedAt: this.#now() })
  }

  /**
   *
   * @param client - Client to store; static clients and clients with grants are never evicted.
   */
  put(client: ClientRecord): void {
    this.#held.delete(client.clientId)
    this.#idle.delete(client.clientId)

    if (
      client.kind === "static" ||
      (this.#grantCounts.get(client.clientId) ?? 0) > 0
    ) {
      this.#held.set(client.clientId, client)
    } else {
      this.#toIdle(client)
    }
  }

  /**
   *
   * @param clientId - The `client_id` to look up; a hit counts as use of a grant-less client.
   * @returns The client, or `undefined` when unknown or idle for longer than the idle lifetime.
   */
  get(clientId: string): ClientRecord | undefined {
    const held = this.#held.get(clientId)

    if (held !== undefined) return held

    const idle = this.#idle.get(clientId)

    if (idle === undefined) return undefined

    this.#idle.delete(clientId)

    if (hasExpired(idle.usedAt + this.#idleMs, this.#now())) return undefined

    // A lookup is a use: re-insert at the most-recently-used end.
    this.#idle.set(clientId, { client: idle.client, usedAt: this.#now() })

    return idle.client
  }

  /**
   *
   * @param clientId - Client whose grant count increases; it becomes non-evictable.
   */
  grantAdded(clientId: string): void {
    this.#grantCounts.set(clientId, (this.#grantCounts.get(clientId) ?? 0) + 1)

    const idle = this.#idle.get(clientId)

    if (idle !== undefined) {
      this.#idle.delete(clientId)
      this.#held.set(clientId, idle.client)
    }
  }

  /**
   *
   * @param clientId - Client whose grant count decreases; at zero a dynamic client becomes evictable again.
   */
  grantRemoved(clientId: string): void {
    const count = (this.#grantCounts.get(clientId) ?? 0) - 1

    if (count > 0) {
      this.#grantCounts.set(clientId, count)

      return
    }

    this.#grantCounts.delete(clientId)

    const held = this.#held.get(clientId)

    if (held !== undefined && held.kind !== "static") {
      this.#held.delete(clientId)
      this.#toIdle(held)
    }
  }
}
