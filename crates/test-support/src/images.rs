//! Container fixtures use the same image defaults as Compose and Helm.
use std::sync::LazyLock;

const DEFAULTS: &str = include_str!("../../../deploy/images.env");

pub struct TestImage {
    pub name: &'static str,
    pub tag: &'static str,
}

fn image(key: &str) -> TestImage {
    let value = DEFAULTS
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(name, value)| (name == key).then_some(value))
        .expect("shared image default must exist");
    let (name, tag) = value
        .rsplit_once(':')
        .expect("image must have an explicit tag");
    TestImage { name, tag }
}

pub static POSTGRES: LazyLock<TestImage> = LazyLock::new(|| image("POSTGRES_IMAGE"));
pub static HTTPBIN: LazyLock<TestImage> = LazyLock::new(|| image("HTTPBIN_IMAGE"));
pub static PETSTORE: LazyLock<TestImage> = LazyLock::new(|| image("PETSTORE_IMAGE"));
