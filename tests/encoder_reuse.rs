use dhcproto::{Decodable, Decoder, Encodable, Encoder, v4, v6};

#[test]
fn writes_overwrite_existing_bytes_when_growing() {
    for initial_len in 0..=8 {
        for use_slice in [false, true] {
            let mut buffer = vec![255; initial_len];
            let mut encoder = Encoder::new(&mut buffer);
            encoder.write_u16(0x0102).unwrap();
            if use_slice {
                encoder.write_slice(&[3, 4, 5, 6]).unwrap();
            } else {
                encoder.write([3, 4, 5, 6]).unwrap();
            }
            assert_eq!(encoder.buffer_filled(), [1, 2, 3, 4, 5, 6]);
            assert_eq!(encoder.len_filled(), 6);
            assert_eq!(encoder.buffer().len(), initial_len.max(6));
            assert!(encoder.buffer()[6..].iter().all(|byte| *byte == 255));
            encoder.write_slice(&[]).unwrap();
            encoder.write([]).unwrap();
            assert_eq!(encoder.len_filled(), 6);
        }
    }
}

#[test]
fn reused_buffers_encode_complete_v4_and_v6_messages() {
    let mut v4_message = v4::Message::default();
    v4_message
        .opts_mut()
        .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
    let mut v6_message = v6::Message::new_with_id(v6::MessageType::Solicit, [1, 2, 3]);
    v6_message
        .opts_mut()
        .insert(v6::DhcpOption::ClientId(vec![1, 2, 3, 4]));

    for initial_len in [0, 1, 3, 5, 10, 100, 400] {
        let mut buffer = vec![255; initial_len];
        // Grow, shrink, then grow beyond the old packet's end without clearing
        // the buffer. Read only the encoder's documented filled region.
        for data_len in [300, 2, 800] {
            v4_message
                .opts_mut()
                .insert(v4::DhcpOption::Hostname("a".repeat(data_len)));
            let mut encoder = Encoder::new(&mut buffer);
            v4_message.encode(&mut encoder).unwrap();
            assert_eq!(encoder.buffer_filled(), v4_message.to_vec().unwrap());
            assert_eq!(
                v4::Message::decode(&mut Decoder::new(encoder.buffer_filled())).unwrap(),
                v4_message
            );

            v6_message
                .opts_mut()
                .insert(v6::DhcpOption::InterfaceId(vec![42; data_len]));
            let mut encoder = Encoder::new(&mut buffer);
            v6_message.encode(&mut encoder).unwrap();
            assert_eq!(encoder.buffer_filled(), v6_message.to_vec().unwrap());
            assert_eq!(
                v6::Message::decode(&mut Decoder::new(encoder.buffer_filled())).unwrap(),
                v6_message
            );
        }
    }
}
