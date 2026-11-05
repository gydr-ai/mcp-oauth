import { hasExpired } from "../helpers/time.js"

/**
 * A Map with expiry-on-read and oldest-first eviction. Eviction pops from
 * the head of the Map's insertion order: O(1) amortised.
 *
 * @internal
 */
export class Collection<V> {
  readonly #items = new Map<string, V>()
  readonly #max: number
  readonly #expiresAt: (value: V) => number
  readonly #now: () => number
  readonly #onRemove: (value: V) => void

  /**
   *
   * @param max - Most entries held; inserting beyond it evicts the oldest.
   * @param now - Clock in milliseconds since the epoch, compared with each entry's expiry.
   * @param expiresAt - Returns an entry's expiry in milliseconds since the epoch.
   * @param onRemove - Called for every entry that leaves the collection (replaced, expired, evicted or deleted).
   */
  constructor(
    max: number,
    now: () => number,
    expiresAt: (value: V) => number,
    onRemove: (value: V) => void = () => {},
  ) {
    this.#max = max
    this.#now = now
    this.#expiresAt = expiresAt
    this.#onRemove = onRemove
  }

  #remove(key: string, value: V): void {
    this.#items.delete(key)
    this.#onRemove(value)
  }

  /**
   *
   * @param key - Entry key, such as a token hash or record id.
   * @returns The entry, or `undefined` when absent or expired (an expired entry is removed).
   */
  get(key: string): V | undefined {
    const value = this.#items.get(key)

    if (value === undefined) return undefined

    if (hasExpired(this.#expiresAt(value), this.#now())) {
      this.#remove(key, value)

      return undefined
    }

    return value
  }

  /**
   *
   * @param key - Entry key; an existing entry under it is replaced.
   * @param value - The record to store.
   */
  set(key: string, value: V): void {
    const previous = this.#items.get(key)

    if (previous !== undefined) this.#remove(key, previous)

    while (this.#items.size >= this.#max) {
      const oldest = this.#items.entries().next()

      if (oldest.done === true) break

      this.#remove(oldest.value[0], oldest.value[1])
    }

    this.#items.set(key, value)
  }

  /**
   * Read an entry even if it has expired, without removing it.
   *
   * @param key - Entry key.
   * @returns The entry, or `undefined` when absent.
   */
  peek(key: string): V | undefined {
    return this.#items.get(key)
  }

  /**
   * Get and delete in one synchronous step.
   *
   * @param key - Entry key.
   * @param includeExpired - When `true`, an entry past its expiry is still returned and removed.
   * @returns The removed entry, or `undefined` when there was none to take.
   */
  take(key: string, includeExpired = false): V | undefined {
    const value = includeExpired ? this.#items.get(key) : this.get(key)

    if (value !== undefined) this.#remove(key, value)

    return value
  }

  /**
   *
   * @param key - Entry key; a missing key is ignored.
   */
  delete(key: string): void {
    const value = this.#items.get(key)

    if (value !== undefined) this.#remove(key, value)
  }

  /**
   * Every live (unexpired) entry.
   *
   * @returns The entries in insertion order.
   */
  values(): V[] {
    const now = this.#now()

    return [...this.#items.values()].filter(
      (value) => !hasExpired(this.#expiresAt(value), now),
    )
  }

  /**
   * Remove every entry that matches.
   *
   * @param test - Returns `true` for entries to remove.
   */
  deleteWhere(test: (value: V) => boolean): void {
    for (const [key, value] of this.#items) {
      if (test(value)) this.#remove(key, value)
    }
  }
}
