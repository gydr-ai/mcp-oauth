/**
 * Options for `createMemoryStore`.
 *
 * @example
 * ```ts
 * import { createMemoryStore, type MemoryStoreOptions } from "@gydr-ai/mcp-oauth"
 *
 * const options: MemoryStoreOptions = { maxEntriesPerCollection: 5000, dynamicClientIdleSeconds: 7 * 86_400 }
 * export const store = createMemoryStore(options)
 * ```
 */
export interface MemoryStoreOptions {
  /**
   * Most entries per collection. When full, the oldest entry is evicted
   * (bounding memory against a registration or authorization flood). A
   * client that holds a live grant is never evicted. Default: 100,000.
   */
  readonly maxEntriesPerCollection?: number
  /**
   * A dynamically registered client with no live grant is deleted after
   * this many seconds without use (registration, a lookup, or its last
   * grant ending). Default: 2,419,200 (28 days).
   */
  readonly dynamicClientIdleSeconds?: number
  /** Clock, for tests. Default: `Date.now`. */
  readonly now?: () => number
}
