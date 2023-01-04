use proc_macro::{Group, Ident, TokenStream, TokenTree};

#[proc_macro]
pub fn declare_codes(input: TokenStream) -> TokenStream {
    // 1. Use syn to parse the input tokens into a syntax tree.
    // 2. Use quote to generate new tokens based on what we parsed.
    // 3. Return the generated tokens.
    struct Entry {
        code: u8,
        id: Ident,
        description: String,
        data_type: Option<Group>,
    }
    let mut entries = Vec::new();
    for x in input.into_iter() {
        if let TokenTree::Group(group) = x {
            let mut tokens = group.stream().into_iter().filter_map(|x| {
                if let TokenTree::Punct(_) = x {
                    None
                } else {
                    Some(x)
                }
            });
            let code = if let Some(TokenTree::Literal(lit)) = tokens.next() {
                lit.to_string().parse::<u8>().unwrap()
            } else {
                panic!("expected code");
            };
            let id = if let Some(TokenTree::Ident(id)) = tokens.next() {
                id
            } else {
                panic!("expected id");
            };
            let description = if let Some(TokenTree::Literal(description)) = tokens.next() {
                description.to_string()
            } else {
                panic!("expected description");
            };

            let data_type = match tokens.next() {
                Some(TokenTree::Group(x)) => Some(x),
                None => None,
                e => panic!("expected nothing or id not {e:?}"),
            };
            entries.push(Entry {
                code,
                id,
                description,
                data_type,
            })
        }
    }

    let enum_impl = std::iter::once(
        "
        /// DHCP Options
        #[cfg_attr(feature = \"serde\", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum OptionCode {"
            .to_owned(),
    )
    .chain(entries.iter().map(|e| {
        let description = &e.description[1..&e.description.len() - 1];
        let id = &e.id;
        let code = e.code;
        format!("/// {code} - {description}\n{id},")
    }))
    .chain(std::iter::once(
        "
    /// Unknown code
    Unknown(u8),
    }
    "
        .to_owned(),
    ));

    let impl_option_from_u8 = std::iter::once(
        "
        impl std::convert::From<u8> for OptionCode {
        fn from(x : u8) -> Self{
            match x {
        "
        .to_owned(),
    )
    .chain(entries.iter().map(|e| {
        let id = &e.id;
        let code = e.code;
        format!("{code} => Self::{id},")
    }))
    .chain(std::iter::once("_ => Self::Unknown(x)}}}".to_owned()));

    let impl_u8_from_option = std::iter::once(
        "
        impl std::convert::From<OptionCode> for u8 {
        fn from(x : OptionCode) -> Self{
            match x {
        "
        .to_owned(),
    )
    .chain(entries.iter().map(|e| {
        let id = &e.id;
        let code = e.code;
        format!("OptionCode::{id} => {code},")
    }))
    .chain(std::iter::once(
        "OptionCode::Unknown(code) => code }}}".to_owned(),
    ));

    let impl_dhcp_option = std::iter::once(
        "
        /// DHCP Options
        #[cfg_attr(feature = \"serde\", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum DhcpOption {"
            .to_owned(),
    )
    .chain(entries.iter().map(|e| {
        let description = &e.description[1..&e.description.len() - 1];
        let id = &e.id;
        let code = e.code;
        if let Some(data_description) = &e.data_type {
            format!("/// {code} - {description}\n{id}{data_description},")
        } else {
            format!("/// {code} - {description}\n{id},")
        }
    }))
    .chain(std::iter::once(
        "
        /// Unknown option
        Unknown(UnknownOption),
    }
    "
        .to_owned(),
    ));

    let impl_optioncode_from_dhcpoption_ref = std::iter::once(
        "
        impl From<&DhcpOption> for OptionCode {
            fn from(opt: &DhcpOption) -> Self {
                use DhcpOption::*;
                match opt {
        "
        .to_owned(),
    )
    .chain(entries.iter().map(|e| {
        let id = &e.id;
        let var_field = if let Some(data_description) = &e.data_type {
            // format!("///{id}(_) => ,")
            std::iter::once("(_")
                .chain(data_description.stream().into_iter().filter_map(|e| {
                    if let TokenTree::Punct(p) = e {
                        (p.as_char() == ',').then_some(",_")
                    } else {
                        None
                    }
                }))
                .chain(std::iter::once(")"))
                .collect()
        } else {
            // format!("/// {code} - {description}\n{id},")
            "".to_owned()
        };
        format!("{id}{var_field} => OptionCode::{id},")
    }))
    .chain(std::iter::once(
        "Unknown(n) => OptionCode::Unknown(n.code)}}}".to_owned(),
    ));
    let output_token_stream_str: TokenStream = enum_impl
        .chain(impl_option_from_u8)
        .chain(impl_u8_from_option)
        .chain(impl_dhcp_option)
        .chain(impl_optioncode_from_dhcpoption_ref)
        .collect::<String>()
        .parse()
        .unwrap();
    let output = output_token_stream_str;
    output
}
