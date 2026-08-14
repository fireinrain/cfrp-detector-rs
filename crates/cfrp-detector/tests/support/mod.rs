pub mod mock_server;

pub use mock_server::{
    MockCfServer, MockCfServerConfig, StaticLocations, StaticRanges, make_detector_with_mocks,
};
