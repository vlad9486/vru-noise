use alloc::vec::Vec;

use serde::{Serialize, Deserialize};

const DATA: &'static str = include_str!("cacophony.json");

#[derive(Serialize, Deserialize)]
pub struct TestVector<'a> {
    #[serde(rename = "protocol_name")]
    pub name: &'a str,
    #[serde(rename = "init_prologue")]
    pub prologue: &'a [u8],

    #[serde(rename = "init_psks", default)]
    pub psks: Vec<&'a str>,

    init_remote_static: Option<&'a str>,
    pub init_static: Option<&'a str>,
    pub init_ephemeral: &'a str,
    resp_remote_static: Option<&'a str>,
    pub resp_static: Option<&'a str>,
    pub resp_ephemeral: Option<&'a str>,

    pub handshake_hash: &'a str,

    #[serde(borrow)]
    pub messages: [Pair<'a>; 6],
}

impl TestVector<'static> {
    pub fn try_load(name: &str) -> Option<Self> {
        let pos = DATA.find(name)? - 18;
        let mut de = serde_json::Deserializer::from_str(&DATA[pos..]);
        Some(Deserialize::deserialize(&mut de).unwrap())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Pair<'a> {
    pub payload: &'a str,
    pub ciphertext: &'a str,
}
