use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use async_lock::{RwLock, RwLockUpgradableReadGuard};
use headers::{CacheControl, Header};
use jwt::PKeyWithDigest;
use openssl::pkey::Public;
use reqwest::header::CACHE_CONTROL;

use crate::key::Key;

mod key;

#[cfg(test)]
mod tests;

/// A cache for storing the response of an endpoint that returns a [JSON Web Key Set][jwks].
///
/// This has a [const fn constructor][Self::new_const] so it can be placed in a `static` for ease of
/// access.
///
/// Pre-defined statics are provided for the following organizations known to use JWKs:
/// * [Google][GOOGLE]
/// * [Apple][APPLE]
///
/// [jwks]: https://datatracker.ietf.org/doc/html/rfc7517#section-5
pub struct JwkCache {
    url: Cow<'static, str>,
    cached: RwLock<CachedJwkSetHolder>,
    // if set to `true`, do not wait for a write lock to fetch
    // this will be set if the last response indicated it should not be cached:
    // * `Cache-Control: no-store` (explicit do-not-cache)
    // * `Cache-Control: max-age=0` (invalidate the cached value and do not store)
    // * no `Cache-Control` header (assume we shouldn't cache the value)
    fetch_racy: AtomicBool,
}

/// A JSON Web Key Set.
///
/// Can be [fetched directly][Self::fetch] or [retrieved from a cache][JwkCache::fetch].
pub struct JwkSet {
    keys: HashMap<String, PKeyWithDigest<Public>>,
    cache_control: CacheControl,
    fetched_at: Instant
}

struct CachedJwkSetHolder(Option<Arc<JwkSet>>);

/// A [`JwkCache`] for the Google JSON Web Key Set endpoint.
///
/// Useful for verifying JWTs returned by the [Sign In with Google][siwg] feature.
///
/// [siwg]: https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
pub static GOOGLE: JwkCache = JwkCache::new_const("https://www.googleapis.com/oauth2/v3/certs");

/// A [`JwkCache`] for the Apple JSON Web Key Set endpoint.
///
/// Useful for verifying JWTs returned by the [Sign In with Apple][siwa] feature.
///
/// ### Note
/// As of this writing (Sept 2, 2021), the Apple JWKS endpoint appears to always return
/// `Cache-Control: no-store` which means that clients should fetch the keys fresh every time they
/// wish to verify a token.
///
/// `JwkCache` will comply with this setting and not store the response. This effectively
/// makes this just a convenient wrapper around [`JwkStore::fetch()`] with a preset URL,
/// with the exception that if Apple _does_ decide to allow caching in the future, the cache will
/// automatically begin storing the response again.
///
/// [siwa]: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
pub static APPLE: JwkCache = JwkCache::new_const("https://appleid.apple.com/auth/keys")
    .default_racy();

impl JwkCache {

    /// A constructor which accepts a dynamically allocated string.
    ///
    /// No HTTP request will be made until the first time [`.fetch()`][Self::fetch] is called.
    pub fn new(url: String) -> Self {
        JwkCache {
            url: url.into(),
            cached: RwLock::new(CachedJwkSetHolder::new()),
            fetch_racy: AtomicBool::new(false),
        }
    }

    /// A `const` constructor that allows `JwkCache` to be stored in a `static` for a JWKS
    /// endpoint that is known ahead of time.
    ///
    /// Pre-defined statics are provided for the following organizations known to use JWKs:
    /// * [Google][GOOGLE]
    /// * [Apple][APPLE]
    pub const fn new_const(url: &'static str) -> Self {
        JwkCache {
            url: Cow::Borrowed(url),
            cached: RwLock::new(CachedJwkSetHolder::new()),
            fetch_racy: AtomicBool::new(false),
        }
    }

    const fn default_racy(mut self) -> Self {
        self.fetch_racy = AtomicBool::new(true);
        self
    }

    /// Get the currently configured URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Return the cached JSON Web Key set, if it's still valid,
    /// or fetch a new one fresh from the configured URL.
    ///
    /// A `reqwest::Client` is required so as to encourage reuse instead of implicitly
    /// creating a new client every time. This saves some connection overhead when the server
    /// supports HTTP/2 (especially if you go on to make other API requests to the same server,
    /// which is likely when implementing Sign in With Apple/Google).
    ///
    /// ### Caching Behavior
    /// `JwkCache` obeys the `CacheControl` header in the response from the given URL.
    ///
    /// The expiration of the returned key set is determined by `Cache-Control: max-age=<seconds>`.
    ///
    /// In general, a given `JwkCache` instance will avoid making more than one concurrent network
    /// request at a time; instead, concurrent calls to this method when the cached value is stale
    /// will wait until the first call resolves and then use its value.
    ///
    /// However, if the endpoint returns `Cache-Control: no-store`, this implementation will
    /// obey that and not cache the returned response. In the assumption that the server
    /// will return a similar response on the next call, an internal flag is set which
    /// will cause subsequent calls to this method to immediately request a fresh key set
    /// instead of waiting for an exclusive lock and making requests one-at-a-time.
    ///
    /// If the server subsequently returns something _other_ than `Cache-Control: no-store`,
    /// this instance will automatically revert to the default behavior
    /// of preferring the cached value.
    ///
    /// If the server did not return a `Cache-Control` header, the implementation
    /// assumes `Cache-Control: no-store`. The `Expires` header is ignored.
    pub async fn fetch(&self, client: &reqwest::Client) -> reqwest::Result<Arc<JwkSet>> {
        if let Some(existing) = self.cached.read().await.get_non_stale() {
            return Ok(existing);
        }

        // if the last response indicated that it should not be cached,
        // don't wait for an exclusive lock to fetch a new one
        let prefetched_store = if self.fetch_racy.load(Ordering::Relaxed) {
            let jwk_store = Arc::new(JwkSet::fetch(client, &self.url).await?);

            // the response is already "stale" if it was missing a `Cache-Control` header
            // or was set to `Cache-Control: no-store` or `Cache-Control: max-age=0`
            self.fetch_racy.store(jwk_store.is_stale(), Ordering::Relaxed);

            if jwk_store.is_stale() {
                if jwk_store.is_expired() {
                    // `Cache-Control: max-age=0` (or otherwise already expired)
                    // indicates that we need to clear our existing cache
                    self.cached.write().await.0 = None;
                }

                // obey the `no-store` and skip saving the response
                // this allows us to avoid waiting for an exclusive lock
                return Ok(jwk_store);
            }

            // server changed their mind, we can cache this response!
            Some(jwk_store)
        } else {
            None
        };

        // attempt to acquire an upgradeable read lock first
        let upgradeable_read = self.cached.upgradable_read().await;

        // check again because another thread might have refreshed while we waited for the lock
        // though this will be serialized with other tasks that also called `.upgradeable_read()`,
        // this should return quickly and new calls should immediately return the cached value
        if let Some(existing) = upgradeable_read.get_non_stale() {
            return Ok(existing);
        }

        let new_store = if let Some(prefetched) = prefetched_store {
            prefetched
        } else {
            Arc::new(JwkSet::fetch(client, &self.url).await?)
        };

        // if the server returned `no-store`, we set this flag so that we don't force
        // subsequent fetches to be serialized as otherwise each call will acquire an exclusive lock
        self.fetch_racy.store(new_store.is_stale(), Ordering::Relaxed);

        if !new_store.is_stale() {
            // wait for readers to go away
            let mut write = RwLockUpgradableReadGuard::upgrade(upgradeable_read).await;
            write.0 = Some(new_store.clone());
        } else if new_store.is_expired() {
            // a response that's already expired means clear the existing cached value
            let mut write = RwLockUpgradableReadGuard::upgrade(upgradeable_read).await;
            write.0 = None;
        }

        Ok(new_store)
    }
}

impl JwkSet {
    /// Fetch a fresh JSON Web Key Set from the given URL.
    pub async fn fetch(client: &reqwest::Client, url: &str) -> reqwest::Result<Self> {
        #[derive(serde::Deserialize)]
        struct KeyResponse {
            keys: Vec<Key>,
        }

        let fetched_at = Instant::now();

        let response = client.get(url)
            .send()
            .await?;

        let cache_control = CacheControl::decode(&mut response.headers().get_all(CACHE_CONTROL).iter())
            .ok()
            .unwrap_or_else(CacheControl::new);

        let KeyResponse { keys } = response.json().await?;

        let keys = keys.into_iter().filter_map(|mut key| {
            let key_id = key.key_id.take()?;
            Some((key_id, key.into_jwt_key().ok()?))
        })
            .collect();

        Ok(JwkSet {
            keys,
            cache_control,
            fetched_at
        })
    }

    /// Returns `true` if the key set is stale.
    ///
    /// This is based off the `Cache-Control: max-age` header. If the server returned
    /// `Cache-Control: no-store` or did not set a `Cache-Control` header, the set is
    /// assumed to be stale.
    pub fn is_stale(&self) -> bool {
        self.cache_control.no_store() ||
            self.is_expired()
    }

    /// Returns `true` if the JWK Set is beyond the `max-age` set by the `Cache-Control` header
    /// in the response, or if no `Cache-Control` header was returned.
    pub fn is_expired(&self) -> bool {
        // if a `max-age` isn't set, it's safest to assume the response is automatically expired
        self.cache_control.max_age().map_or(true, |max_age| {
            let age = self.fetched_at.elapsed();
            age < max_age
        })
    }
}

impl CachedJwkSetHolder {
    const fn new() -> Self {
        CachedJwkSetHolder(None)
    }

    /// Get the currently cached value if present and valid. If stale or missing, return `None`.
    fn get_non_stale(&self) -> Option<Arc<JwkSet>> {
        self.0.as_ref().filter(|existing| !existing.is_stale()).cloned()
    }
}

impl jwt::algorithm::store::Store for JwkSet {
    type Algorithm = PKeyWithDigest<Public>;

    fn get(&self, key_id: &str) -> Option<&Self::Algorithm> {
        self.keys.get(key_id)
    }
}