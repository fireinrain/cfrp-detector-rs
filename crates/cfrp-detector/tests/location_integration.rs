use cfrp_detector::{CfLocation, LocationSource, LocationStore};

fn sample_locations() -> Vec<CfLocation> {
    vec![
        CfLocation {
            iata: "LAX".into(),
            lat: 33.9425,
            lon: -118.4081,
            city: "Los Angeles".into(),
            region: "CA".into(),
            cca2: "US".into(),
        },
        CfLocation {
            iata: "LHR".into(),
            lat: 51.4700,
            lon: -0.4543,
            city: "London".into(),
            region: "ENG".into(),
            cca2: "GB".into(),
        },
        CfLocation {
            iata: "NRT".into(),
            lat: 35.7647,
            lon: 140.3864,
            city: "Tokyo".into(),
            region: "KT".into(),
            cca2: "JP".into(),
        },
    ]
}

#[test]
fn cf_location_serialization_keeps_keys() {
    let loc = CfLocation {
        iata: "LAX".into(),
        lat: 33.9425,
        lon: -118.4081,
        city: "Los Angeles".into(),
        region: "CA".into(),
        cca2: "US".into(),
    };
    let v = serde_json::to_value(&loc).unwrap();
    assert_eq!(v["iata"], "LAX");
    assert_eq!(v["city"], "Los Angeles");
    assert_eq!(v["region"], "CA");
    assert_eq!(v["cca2"], "US");
    assert!(v["lat"].is_f64());
    assert!(v["lon"].is_f64());
}

#[test]
fn location_store_lookup_returns_full_struct() {
    let store = LocationStore::from_locations(sample_locations());
    let hit = store.lookup("lhr").unwrap();
    assert_eq!(hit.iata, "LHR");
    assert_eq!(hit.city, "London");
    assert_eq!(hit.cca2, "GB");
}

#[test]
fn location_store_lookup_missing_returns_none() {
    let store = LocationStore::from_locations(vec![CfLocation {
        iata: "LAX".into(),
        lat: 0.0,
        lon: 0.0,
        city: String::new(),
        region: String::new(),
        cca2: String::new(),
    }]);
    assert!(store.lookup("not-there").is_none());
    assert!(store.lookup("").is_none());
}

#[test]
fn location_store_empty_lookup_always_none() {
    let store = LocationStore::empty();
    assert!(store.lookup("lax").is_none());
    assert!(store.lookup("LAX").is_none());
    assert!(store.lookup("").is_none());
}

#[test]
fn cf_location_clone_is_independent() {
    let loc = sample_locations().remove(0);
    let mut loc2 = loc.clone();
    loc2.city = "Changed".into();
    assert_ne!(loc.city, loc2.city);
    assert_eq!(loc.iata, "LAX");
}

#[test]
fn location_store_implements_location_source_trait() {
    fn use_as_source<S: LocationSource>(s: &S, key: &str) -> bool {
        s.lookup(key).is_none()
    }
    let store = LocationStore::empty();
    assert!(use_as_source(&store, "LAX"));
}

#[test]
fn cf_location_vector_serde_roundtrip() {
    let list = sample_locations();
    let json = serde_json::to_string(&list).unwrap();
    let back: Vec<CfLocation> = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), list.len());
    for (orig, restored) in list.iter().zip(back.iter()) {
        assert_eq!(orig.iata, restored.iata);
        assert_eq!(orig.city, restored.city);
        assert_eq!(orig.cca2, restored.cca2);
    }
}

#[test]
fn lookup_on_populated_store_via_from_locations() {
    let store = LocationStore::from_locations(sample_locations());
    assert_eq!(store.lookup("nrt").unwrap().city, "Tokyo");
    assert_eq!(store.lookup("lax").unwrap().cca2, "US");
    assert_eq!(store.lookup("LHR").unwrap().region, "ENG");
}

#[test]
fn from_locations_with_empty_iter_stays_empty() {
    let store = LocationStore::from_locations(vec![]);
    assert!(store.lookup("LAX").is_none());
}

#[test]
fn from_locations_iata_key_is_uppercased() {
    let store = LocationStore::from_locations(vec![CfLocation {
        iata: "lax".into(),
        lat: 0.0,
        lon: 0.0,
        city: "lowercase".into(),
        region: String::new(),
        cca2: String::new(),
    }]);
    assert!(store.lookup("LAX").is_some());
    assert_eq!(store.lookup("LAX").unwrap().city, "lowercase");
}