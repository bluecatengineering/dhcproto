#![no_main]
#[warn(unused_variables)]

use libfuzzer_sys::fuzz_target;
use dhcproto::v4::{Message, Decoder, Decodable};

fuzz_target!(|data: &[u8]| {
    let msg = Message::decode(&mut Decoder::new(data));
});
