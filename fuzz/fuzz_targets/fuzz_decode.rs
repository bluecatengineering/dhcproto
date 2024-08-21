#![no_main]

use libfuzzer_sys::fuzz_target;
use dhcproto::v4::{Message, Encoder, Decoder, Decodable, Encodable};

fuzz_target!(|data: &[u8]| {
    let msg = Message::decode(&mut Decoder::new(data));
});
