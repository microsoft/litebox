// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Procedural macros for `litebox_util_log`.
//!
//! This crate provides the `#[instrument]` attribute macro for automatically
//! instrumenting functions with spans.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, quote};
use syn::{
    FnArg, Ident, ItemFn, Pat, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
};

/// Specifies which arguments to capture and how.
#[derive(Debug, Clone)]
struct CapturedArg {
    /// The name of the argument to capture.
    name: Ident,
    /// The capture mode (e.g., `?` for Debug, `%` for Display).
    capture_mode: Option<CaptureMode>,
}

#[derive(Debug, Clone, Copy)]
enum CaptureMode {
    Debug,
    Display,
}

impl Parse for CapturedArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: Ident = input.parse()?;
        let capture_mode = if input.peek(Token![:]) {
            input.parse::<Token![:]>()?;
            if input.peek(Token![?]) {
                input.parse::<Token![?]>()?;
                Some(CaptureMode::Debug)
            } else if input.peek(Token![%]) {
                input.parse::<Token![%]>()?;
                Some(CaptureMode::Display)
            } else {
                let ident: Ident = input.parse()?;
                match ident.to_string().as_str() {
                    "debug" => Some(CaptureMode::Debug),
                    "display" => Some(CaptureMode::Display),
                    other => {
                        return Err(syn::Error::new(
                            ident.span(),
                            format!(
                                "unknown capture mode `{other}`, expected `?`, `%`, `debug`, or `display`"
                            ),
                        ));
                    }
                }
            }
        } else {
            None
        };

        Ok(CapturedArg { name, capture_mode })
    }
}

/// Arguments to the `#[instrument]` attribute.
#[derive(Default)]
struct InstrumentArgs {
    /// The log level for the span.
    level: Option<Ident>,
    /// Arguments to capture. If None, capture all arguments with Debug.
    fields: Option<Vec<CapturedArg>>,
    /// Custom span name. If None, use the function name.
    name: Option<String>,
    /// Arguments to skip from automatic capture.
    skip: Vec<Ident>,
    /// Skip all arguments.
    skip_all: bool,
}

impl Parse for InstrumentArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut args = InstrumentArgs::default();

        while !input.is_empty() {
            let key: Ident = input.parse()?;

            match key.to_string().as_str() {
                "level" => {
                    input.parse::<Token![=]>()?;
                    args.level = Some(input.parse()?);
                }
                "fields" => {
                    let content;
                    syn::parenthesized!(content in input);
                    let fields: Punctuated<CapturedArg, Token![,]> =
                        content.parse_terminated(CapturedArg::parse, Token![,])?;
                    args.fields = Some(fields.into_iter().collect());
                }
                "name" => {
                    input.parse::<Token![=]>()?;
                    let lit: syn::LitStr = input.parse()?;
                    args.name = Some(lit.value());
                }
                "skip" => {
                    let content;
                    syn::parenthesized!(content in input);
                    let skipped: Punctuated<Ident, Token![,]> =
                        content.parse_terminated(Ident::parse, Token![,])?;
                    args.skip = skipped.into_iter().collect();
                }
                "skip_all" => {
                    args.skip_all = true;
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown argument `{other}`"),
                    ));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(args)
    }
}

/// Instruments a function with a span that is entered on function entry and
/// exited on function return.
///
/// # Arguments
///
/// - `level` - The log level for the span (e.g., `info`, `debug`, `trace`).
///   Defaults to `info` if not specified.
/// - `fields(...)` - Specific function arguments to capture as span fields.
///   Each field can have a capture mode: `:?` or `:debug` for `Debug`,
///   `:%` or `:display` for `Display`. Defaults to `Debug` if not specified.
/// - `name` - Custom span name. Defaults to the function name.
/// - `skip(...)` - Arguments to skip from automatic capture.
/// - `skip_all` - Skip capturing all arguments.
///
/// # Example
///
/// ```ignore
/// use litebox_util_log::instrument;
///
/// // Basic usage - captures all arguments with Debug at info level
/// #[instrument(level = info)]
/// fn process_request(request_id: u64, data: &str) {
///     // ...
/// }
///
/// // Capture specific fields with custom modes
/// #[instrument(level = debug, fields(id:?, name:%))]
/// fn handle_user(id: u64, name: &str, password: &str) {
///     // password is not captured
/// }
///
/// // Skip specific arguments
/// #[instrument(level = trace, skip(sensitive_data))]
/// fn process(input: &str, sensitive_data: &[u8]) {
///     // ...
/// }
///
/// // Custom span name
/// #[instrument(level = info, name = "my_custom_span")]
/// fn my_function() {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as InstrumentArgs);
    let input_fn = parse_macro_input!(item as ItemFn);

    instrument_impl(args, input_fn).into()
}

fn instrument_impl(args: InstrumentArgs, mut input_fn: ItemFn) -> TokenStream2 {
    let fn_name = &input_fn.sig.ident;
    let span_name = args.name.unwrap_or_else(|| fn_name.to_string());

    // Determine the level
    let level = args.level.map_or_else(
        || quote! { ::litebox_util_log::Level::Info },
        |l| {
            let level_str = l.to_string().to_lowercase();
            match level_str.as_str() {
                "error" => quote! { ::litebox_util_log::Level::Error },
                "warn" => quote! { ::litebox_util_log::Level::Warn },
                "info" => quote! { ::litebox_util_log::Level::Info },
                "debug" => quote! { ::litebox_util_log::Level::Debug },
                "trace" => quote! { ::litebox_util_log::Level::Trace },
                _ => quote! { ::litebox_util_log::Level::#l },
            }
        },
    );

    // Extract function arguments that can be captured
    let fn_args: Vec<(Ident, bool)> = input_fn
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_type) = arg
                && let Pat::Ident(pat_ident) = &*pat_type.pat
            {
                let is_ref = matches!(&*pat_type.ty, syn::Type::Reference(_));
                return Some((pat_ident.ident.clone(), is_ref));
            }
            None
        })
        .collect();

    // Determine which fields to capture
    let captured_fields: Vec<(Ident, CaptureMode)> = if args.skip_all {
        Vec::new()
    } else if let Some(fields) = args.fields {
        // Use explicitly specified fields
        fields
            .into_iter()
            .map(|f| (f.name, f.capture_mode.unwrap_or(CaptureMode::Debug)))
            .collect()
    } else {
        // Capture all non-skipped arguments with Debug
        fn_args
            .iter()
            .filter(|(name, _)| !args.skip.iter().any(|s| s == name))
            .map(|(name, _)| (name.clone(), CaptureMode::Debug))
            .collect()
    };

    // Generate the span creation code
    let span_creation = if captured_fields.is_empty() {
        quote! {
            let __litebox_span = ::litebox_util_log::span!(#level, #span_name);
        }
    } else {
        // Build the field capturing expressions
        let field_tokens: Vec<TokenStream2> = captured_fields
            .iter()
            .map(|(name, mode)| {
                let mode_token = match mode {
                    CaptureMode::Debug => quote! { :? },
                    CaptureMode::Display => quote! { :% },
                };
                quote! { #name #mode_token }
            })
            .collect();

        quote! {
            let __litebox_span = ::litebox_util_log::span!(#level, #span_name, #(#field_tokens),*);
        }
    };

    // Wrap the function body
    let original_body = &input_fn.block;
    let new_body: syn::Block = syn::parse_quote! {
        {
            #span_creation
            #original_body
        }
    };

    input_fn.block = Box::new(new_body);

    input_fn.into_token_stream()
}
