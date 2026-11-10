use dhcproto::{Decodable, Decoder, Encodable, v6};

fn class_options(data: Vec<Vec<u8>>) -> [v6::DhcpOption; 2] {
    [
        v6::DhcpOption::UserClass(v6::UserClass { data: data.clone() }),
        v6::DhcpOption::VendorClass(v6::VendorClass { num: 32473, data }),
    ]
}

#[test]
fn class_option_wire_lengths_include_each_length_prefix() {
    let [user, vendor] = class_options(vec![b"PXE".to_vec(), vec![0, 255]]);
    assert_eq!(
        user.to_vec().unwrap(),
        [0, 15, 0, 9, 0, 3, b'P', b'X', b'E', 0, 2, 0, 255]
    );
    assert_eq!(
        vendor.to_vec().unwrap(),
        [
            0, 16, 0, 13, 0, 0, 126, 217, 0, 3, b'P', b'X', b'E', 0, 2, 0, 255
        ]
    );
}

#[test]
fn class_data_and_following_options_survive_message_roundtrip() {
    for data in [
        vec![],
        vec![vec![]],
        vec![b"PXE".to_vec()],
        vec![b"PXE".to_vec(), vec![0, 255]],
    ] {
        for option in class_options(data) {
            let mut message = v6::Message::new_with_id(v6::MessageType::Solicit, [1, 2, 3]);
            message
                .opts_mut()
                .insert(v6::DhcpOption::ClientId(vec![1, 2, 3, 4]));
            message.opts_mut().insert(option);
            message
                .opts_mut()
                .insert(v6::DhcpOption::InterfaceId(b"eth0".to_vec()));
            let bytes = message.to_vec().unwrap();
            let decoded = v6::Message::decode(&mut Decoder::new(&bytes)).unwrap();
            assert_eq!(decoded, message);
        }
    }
}

#[test]
fn class_option_length_boundaries() {
    for (index, max_data) in [(0, 65533), (1, 65529)] {
        let option = class_options(vec![vec![42; max_data]])[index].clone();
        let bytes = option.to_vec().unwrap();
        assert_eq!(&bytes[2..4], &u16::MAX.to_be_bytes());
        assert_eq!(bytes.len(), 4 + usize::from(u16::MAX));
        assert_eq!(
            v6::DhcpOption::decode(&mut Decoder::new(&bytes)).unwrap(),
            option
        );
        let too_long = class_options(vec![vec![42; max_data + 1]])[index].clone();
        assert!(too_long.to_vec().is_err());
    }
    // Every individual class fits, but their combined payload does not.
    for option in class_options(vec![vec![0; 32768], vec![1; 32768]]) {
        assert!(option.to_vec().is_err());
    }
}
