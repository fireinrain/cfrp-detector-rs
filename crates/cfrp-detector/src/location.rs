//! Cloudflare colo (edge POP) code → geographic location lookup.
//!
//! The [`LocationStore`] loads a community-maintained JSON map of IATA-style
//! three-letter Cloudflare POP codes (`LAX`, `NRT`, `SIN`, `HKG`, …) to
//! human-readable city / region / country names and coordinates, caching the
//! file locally for three days at a time.

use crate::{FileCache, Result};
use parking_lot::RwLock;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc, time::Duration};

const LOCATIONS_URL: &str =
    "https://raw.githubusercontent.com/Netrvin/cloudflare-colo-list/main/locations.json";

/// A single Cloudflare colo entry: geographic details keyed by its 3-letter code.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CfLocation {
    /// Three-letter IATA-style colo code (e.g. `LAX`).
    pub iata: String,
    /// Approximate latitude in decimal degrees.
    pub lat: f64,
    /// Approximate longitude in decimal degrees.
    pub lon: f64,
    /// Human-readable city name (English).
    pub city: String,
    /// Region / state / province name if known.
    pub region: String,
    /// ISO 3166-1 alpha-2 two-letter country code.
    pub cca2: String,
}

/// Pluggable colo lookup trait. Swap in a mock implementation for tests.
pub trait LocationSource: Send + Sync {
    /// Looks up the given colo code (case-insensitive).
    fn lookup(&self, colo: &str) -> Option<CfLocation>;
}

/// Default [`LocationSource`] backed by an in-memory `HashMap` loaded from the
/// community-maintained colo JSON file.
#[derive(Debug, Clone)]
pub struct LocationStore {
    map: Arc<RwLock<HashMap<String, CfLocation>>>,
}

impl LocationStore {
    /// Creates an empty store (useful for tests / offline fallbacks).
    pub fn empty() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Builds a store directly from an iterator of [`CfLocation`] entries.
    pub fn from_locations(locations: impl IntoIterator<Item = CfLocation>) -> Self {
        let map = locations
            .into_iter()
            .map(|x| (x.iata.to_ascii_uppercase(), x))
            .collect();
        Self {
            map: Arc::new(RwLock::new(map)),
        }
    }

    /// Fetches and caches the authoritative colo JSON, building a new store.
    pub async fn load(client: &reqwest::Client, cache: &FileCache) -> Result<Self> {
        let bytes = cache
            .load_or_fetch(
                "locations",
                ".json",
                LOCATIONS_URL,
                Duration::from_secs(3 * 24 * 3600),
                client,
            )
            .await?;
        let locations: Vec<CfLocation> = serde_json::from_slice(&bytes)?;
        let map = locations
            .into_iter()
            .map(|x| (x.iata.to_ascii_uppercase(), x))
            .collect();
        Ok(Self {
            map: Arc::new(RwLock::new(map)),
        })
    }
}

impl LocationSource for LocationStore {
    fn lookup(&self, colo: &str) -> Option<CfLocation> {
        self.map.read().get(&colo.to_ascii_uppercase()).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cf_location_fields() {
        let loc = CfLocation {
            iata: "LAX".into(),
            lat: 33.9425,
            lon: -118.4081,
            city: "Los Angeles".into(),
            region: "CA".into(),
            cca2: "US".into(),
        };
        assert_eq!(loc.iata, "LAX");
        assert_eq!(loc.city, "Los Angeles");
        assert_eq!(loc.cca2, "US");
    }

    #[test]
    fn location_store_empty_lookup_returns_none() {
        let store = LocationStore::empty();
        assert!(store.lookup("LAX").is_none());
    }

    #[test]
    fn location_store_lookup_case_insensitive() {
        let store = LocationStore::from_locations(vec![CfLocation {
            iata: "LAX".into(),
            lat: 33.9425,
            lon: -118.4081,
            city: "Los Angeles".into(),
            region: "CA".into(),
            cca2: "US".into(),
        }]);
        assert!(store.lookup("lax").is_some());
        assert!(store.lookup("Lax").is_some());
        assert!(store.lookup("LAX").is_some());
        assert_eq!(store.lookup("LAX").unwrap().city, "Los Angeles");
    }

    #[test]
    fn cf_location_serde_roundtrip() {
        let loc = CfLocation {
            iata: "SFO".into(),
            lat: 37.6213,
            lon: -122.3790,
            city: "San Francisco".into(),
            region: "CA".into(),
            cca2: "US".into(),
        };
        let json = serde_json::to_string(&loc).unwrap();
        let loc2: CfLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(loc.iata, loc2.iata);
        assert_eq!(loc.city, loc2.city);
        assert_eq!(loc.cca2, loc2.cca2);
        assert!((loc.lat - loc2.lat).abs() < 1e-9);
    }
}
