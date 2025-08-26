use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, LitInt, LitStr, Token, Type,
    parse::{Parse, ParseStream, Result},
    parse_macro_input,
};

// parses a single entry in the format:
// {code, id, "description", (Type1, Type2, ...)}
struct Entry {
    code: u8,
    id: Ident,
    description: String,
    data_types: Option<Vec<Type>>,
}

impl Parse for Entry {
    // {code, id, "description", (Type1, Type2, ...)}
    fn parse(input: ParseStream) -> Result<Self> {
        let content;
        syn::braced!(content in input);

        let code: LitInt = content.parse()?;
        content.parse::<Token![,]>()?;

        let id: Ident = content.parse()?;
        content.parse::<Token![,]>()?;

        let description: LitStr = content.parse()?;

        let data_types = if content.peek(Token![,]) && content.peek2(syn::token::Paren) {
            content.parse::<Token![,]>()?;
            let types_content;
            syn::parenthesized!(types_content in content);

            let mut types = Vec::new();
            if !types_content.is_empty() {
                types.push(types_content.parse()?);
                while types_content.peek(Token![,]) {
                    types_content.parse::<Token![,]>()?;
                    if !types_content.is_empty() {
                        types.push(types_content.parse()?);
                    }
                }
            }
            Some(types)
        } else {
            None
        };

        Ok(Entry {
            code: code.base10_parse()?,
            id,
            description: description.value(),
            data_types,
        })
    }
}

struct DeclareCodesInput {
    entries: Vec<Entry>,
}

impl Parse for DeclareCodesInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut entries = Vec::new();

        while !input.is_empty() {
            entries.push(input.parse()?);

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(DeclareCodesInput { entries })
    }
}

fn generate_option_code_enum(entries: &[Entry]) -> proc_macro2::TokenStream {
    let variants = entries.iter().map(|e| {
        let id = &e.id;
        let code = e.code;
        let description = &e.description;
        let doc = format!("{code} - {description}");

        quote! {
            #[doc = #doc]
            #id,
        }
    });

    quote! {
        /// DHCP Options
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum OptionCode {
            #(#variants)*
            /// Unknown code
            Unknown(u8),
        }
    }
}

fn generate_option_code_from_u8(entries: &[Entry]) -> proc_macro2::TokenStream {
    let match_arms = entries.iter().map(|e| {
        let id = &e.id;
        let code = e.code;
        quote! { #code => Self::#id, }
    });

    quote! {
        impl core::convert::From<u8> for OptionCode {
            fn from(x: u8) -> Self {
                match x {
                    #(#match_arms)*
                    _ => Self::Unknown(x),
                }
            }
        }
    }
}

fn generate_u8_from_option_code(entries: &[Entry]) -> proc_macro2::TokenStream {
    let match_arms = entries.iter().map(|e| {
        let id = &e.id;
        let code = e.code;
        quote! { OptionCode::#id => #code, }
    });

    quote! {
        impl core::convert::From<OptionCode> for u8 {
            fn from(x: OptionCode) -> Self {
                match x {
                    #(#match_arms)*
                    OptionCode::Unknown(code) => code,
                }
            }
        }
    }
}

fn generate_dhcp_option_enum(entries: &[Entry]) -> proc_macro2::TokenStream {
    let variants = entries.iter().map(|e| {
        let id = &e.id;
        let code = e.code;
        let description = &e.description;
        let doc = format!("{code} - {description}");

        match &e.data_types {
            Some(types) => {
                quote! {
                    #[doc = #doc]
                    #id(#(#types),*),
                }
            }
            None => {
                quote! {
                    #[doc = #doc]
                    #id,
                }
            }
        }
    });

    quote! {
        /// DHCP Options
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum DhcpOption {
            #(#variants)*
            /// Unknown option
            Unknown(UnknownOption),
        }
    }
}

fn generate_option_code_from_dhcp_option(entries: &[Entry]) -> proc_macro2::TokenStream {
    let match_arms = entries.iter().map(|e| {
        let id = &e.id;

        match &e.data_types {
            Some(types) => {
                let wildcards = types.iter().map(|_| quote! { _ });
                quote! { DhcpOption::#id(#(#wildcards),*) => OptionCode::#id, }
            }
            None => quote! { DhcpOption::#id => OptionCode::#id, },
        }
    });

    quote! {
        impl From<&DhcpOption> for OptionCode {
            fn from(opt: &DhcpOption) -> Self {
                use DhcpOption as O;
                match opt {
                    #(#match_arms)*
                    O::Unknown(n) => OptionCode::Unknown(n.code),
                }
            }
        }
    }
}

#[proc_macro]
pub fn declare_codes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeclareCodesInput);
    let entries = &input.entries;

    let option_code_enum = generate_option_code_enum(entries);
    let option_code_from_u8 = generate_option_code_from_u8(entries);
    let u8_from_option_code = generate_u8_from_option_code(entries);
    let dhcp_option_enum = generate_dhcp_option_enum(entries);
    let option_code_from_dhcp_option = generate_option_code_from_dhcp_option(entries);

    let expanded = quote! {
        #option_code_enum
        #option_code_from_u8
        #u8_from_option_code
        #dhcp_option_enum
        #option_code_from_dhcp_option
    };

    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;
    use syn::parse_quote;

    #[test]
    fn test_macro_expansion() {
        let input: DeclareCodesInput = parse_quote! {
            {1, SubnetMask, "Subnet Mask", (Ipv4Addr)},
            {53, MessageType, "Message Type", (MessageType)},
        };

        let opt_code = generate_option_code_enum(&input.entries);

        // Check that it contains expected variants
        let expected = quote! {
            /// DHCP Options
            #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            pub enum OptionCode {
                #[doc = "1 - Subnet Mask"]
                SubnetMask,
                #[doc = "53 - Message Type"]
                MessageType,
                /// Unknown code
                Unknown(u8),
            }
        };
        println!("Generated OptionCode enum: {}", opt_code);

        // Compare token streams (this is approximate)
        assert_eq!(opt_code.to_string(), expected.to_string());
    }
}
