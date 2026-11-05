import {
  UPSTREAM_CACHE_GRANTS,
  UPSTREAM_EXPIRY_SKEW_MS,
  UPSTREAM_LIFETIME_CEILING_SECONDS,
} from "../constants/defaults.js"
import { GrantInactiveError } from "../errors/grant-inactive-error.js"
import { UpstreamTokenError } from "../errors/upstream-token-error.js"
import type { HandlerContext } from "../interfaces/context.js"
import type { GrantRecord } from "../interfaces/records.js"
import { hasExpired } from "../helpers/time.js"

/** A load of the upstream token for one grant that is under way. */
interface Flight {
  readonly promise: Promise<string>
  /** Whether it renews at the identity provider whatever is cached. */
  readonly forced: boolean
}

/** An upstream access token held in memory. */
interface CachedToken {
  readonly token: string
  readonly expiresAt: number
}

/**
 * Supplies an upstream access token per grant, trying in turn: this
 * process's memory, the sealed copy kept on the grant, and finally a renewal
 * at the identity provider. While a renewal for a grant is under way, other
 * callers for that grant wait for it instead of starting their own, so an
 * identity provider that rotates refresh tokens never sees one used twice
 * from here.
 *
 * @internal
 */
export class UpstreamTokenCache {
  readonly #context: HandlerContext
  readonly #cache = new Map<string, CachedToken>()
  readonly #inflight = new Map<string, Flight>()
  /** Grants being revoked in this process, oldest first (bounded). */
  readonly #revoking = new Set<string>()

  /**
   *
   * @param context - Context of the owning `createMcpAuth` instance; supplies the store, sealer, identity provider and clock.
   */
  constructor(context: HandlerContext) {
    this.#context = context
  }

  /**
   * Forget a grant that is being revoked. Its cached upstream access token
   * is dropped, and a renewal for it that is under way revokes the token
   * it obtains instead of storing it.
   *
   * @param grantId - Id of the grant being revoked; unknown ids are ignored.
   */
  forget(grantId: string): void {
    this.#cache.delete(grantId)

    if (this.#revoking.size >= UPSTREAM_CACHE_GRANTS) {
      const oldest = this.#revoking.values().next()

      if (oldest.done !== true) this.#revoking.delete(oldest.value)
    }

    this.#revoking.add(grantId)
  }

  /**
   * A valid upstream access token for the grant.
   *
   * @param grantId - Id of a grant already confirmed live by `authenticate`; it is looked up again before any renewal.
   * @param forceRefresh - Skip the memory and stored copies and renew at the identity provider. Joins a renewal already under way rather than starting a second.
   * @returns The upstream access token, valid for at least another minute.
   */
  get(grantId: string, forceRefresh = false): Promise<string> {
    const running = this.#inflight.get(grantId)

    if (!forceRefresh) {
      const now = this.#context.options.now()
      const cached = this.#cache.get(grantId)

      if (
        cached !== undefined &&
        !hasExpired(cached.expiresAt - UPSTREAM_EXPIRY_SKEW_MS, now)
      ) {
        return Promise.resolve(cached.token)
      }

      if (running !== undefined) return running.promise

      return this.#start(grantId, false, this.#load(grantId))
    }

    if (running?.forced === true) return running.promise

    // A plain load under way may hand back the very token the caller wants
    // replaced: let it settle (so one refresh token is never used twice at
    // once), then renew.
    const after =
      running === undefined
        ? this.#renew(grantId)
        : running.promise.then(
            () => this.#renew(grantId),
            () => this.#renew(grantId),
          )

    return this.#start(grantId, true, after)
  }

  #start(
    grantId: string,
    forced: boolean,
    work: Promise<string>,
  ): Promise<string> {
    const promise = work.finally(() => {
      if (this.#inflight.get(grantId)?.promise === promise) {
        this.#inflight.delete(grantId)
      }
    })

    this.#inflight.set(grantId, { promise, forced })

    return promise
  }

  /**
   * Drop every cached copy of the grant's upstream access token, then renew
   * it at the identity provider.
   *
   * @param grantId - The grant.
   * @returns The new upstream access token.
   */
  async #renew(grantId: string): Promise<string> {
    const { options } = this.#context

    this.#cache.delete(grantId)

    const grant = await options.store.getGrant(grantId)

    if (grant === undefined || hasExpired(grant.expiresAt, options.now())) {
      throw new GrantInactiveError()
    }

    // An expiry of 0 makes the stored copy unusable even if the renewal
    // below fails.
    if (grant.sealedUpstreamAccessToken !== undefined) {
      await options.store.updateGrant(grantId, {
        upstreamAccessTokenExpiresAt: 0,
      })
    }

    return this.#refresh(grant)
  }

  #remember(grantId: string, token: CachedToken): void {
    if (
      this.#cache.size >= UPSTREAM_CACHE_GRANTS &&
      !this.#cache.has(grantId)
    ) {
      const oldest = this.#cache.keys().next()

      if (oldest.done !== true) this.#cache.delete(oldest.value)
    }

    this.#cache.delete(grantId)
    this.#cache.set(grantId, token)
  }

  async #load(grantId: string): Promise<string> {
    const { options } = this.#context
    const grant = await options.store.getGrant(grantId)

    if (grant === undefined || hasExpired(grant.expiresAt, options.now())) {
      throw new GrantInactiveError()
    }

    const stored = await this.#fromGrant(grant)

    if (stored !== undefined) return stored

    return this.#refresh(grant)
  }

  async #fromGrant(grant: GrantRecord): Promise<string | undefined> {
    const { options } = this.#context

    if (
      grant.sealedUpstreamAccessToken === undefined ||
      grant.upstreamAccessTokenExpiresAt === undefined ||
      hasExpired(
        grant.upstreamAccessTokenExpiresAt - UPSTREAM_EXPIRY_SKEW_MS,
        options.now(),
      )
    ) {
      return undefined
    }

    try {
      const token = await options.sealer.open(
        grant.sealedUpstreamAccessToken,
        `${grant.grantId}#access`,
      )

      this.#remember(grant.grantId, {
        token,
        expiresAt: grant.upstreamAccessTokenExpiresAt,
      })

      return token
    } catch {
      // Cannot be opened (say, its key was retired): renew instead.
      return undefined
    }
  }

  async #refresh(grant: GrantRecord): Promise<string> {
    const { options } = this.#context
    const grantId = grant.grantId

    if (grant.sealedUpstreamRefreshToken === undefined) {
      throw new UpstreamTokenError(
        "This grant has no upstream refresh token to renew with",
      )
    }

    let refreshed: Awaited<ReturnType<typeof options.identityProvider.refresh>>

    try {
      const refreshToken = await options.sealer.open(
        grant.sealedUpstreamRefreshToken,
        grantId,
      )

      refreshed = await options.identityProvider.refresh(
        refreshToken,
        Object.freeze({ grantId, subject: grant.subject }),
      )
    } catch (error) {
      await this.#context.emit({
        type: "upstream_token_refresh_failed",
        grantId,
        reason: error instanceof Error ? error.name : "unknown",
      })

      throw new UpstreamTokenError(
        "The identity provider would not renew the upstream token",
        {
          cause: error,
        },
      )
    }

    const now = options.now()
    const expiresIn = Math.max(
      0,
      Math.min(
        Number.isFinite(refreshed.expiresIn) ? refreshed.expiresIn : 0,
        UPSTREAM_LIFETIME_CEILING_SECONDS,
      ),
    )
    const expiresAt = now + expiresIn * 1000
    const updated = await options.store.updateGrant(grantId, {
      sealedUpstreamAccessToken: await options.sealer.seal(
        refreshed.accessToken,
        `${grantId}#access`,
      ),
      upstreamAccessTokenExpiresAt: expiresAt,
      ...(refreshed.refreshToken !== undefined
        ? {
            sealedUpstreamRefreshToken: await options.sealer.seal(
              refreshed.refreshToken,
              grantId,
            ),
          }
        : {}),
    })

    // The grant ended while the identity provider answered: whoever ended
    // it could only revoke the refresh token stored at that moment, so the
    // one just handed out is revoked here.
    if (!updated || this.#revoking.has(grantId)) {
      this.#cache.delete(grantId)

      if (
        refreshed.refreshToken !== undefined &&
        options.identityProvider.revoke !== undefined
      ) {
        try {
          await options.identityProvider.revoke(refreshed.refreshToken)
        } catch {
          // Best effort.
        }
      }

      throw new GrantInactiveError()
    }

    this.#remember(grantId, { token: refreshed.accessToken, expiresAt })

    return refreshed.accessToken
  }
}
