// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Procedural macros for `litebox_util_log`.  Not to be imported directly.
//!
//! This crate provides the `#[instrument]` attribute macro for automatically
//! instrumenting functions with spans.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, quote};
use syn::{
    Expr, FnArg, Ident, ItemFn, Pat, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    token,
};

/// Specifies which arguments to capture and how.
#[derive(Debug, Clone)]
struct CapturedArg {
    /// The source of the value to capture (and implicit key when no explicit key/value).
    source: CaptureSource,
    /// The capture mode (e.g., `?` for Debug, `%` for Display).
    capture_mode: Option<CaptureMode>,
    /// Explicit value expression when `= <expr>` is provided.
    /// When `Some`, `source` holds the explicit key ident as `CaptureSource::Arg`.
    value_expr: Option<Expr>,
}

/// Where the captured value comes from.
#[derive(Debug, Clone)]
enum CaptureSource {
    /// A plain function argument, captured by name (also used as explicit key when
    /// `value_expr` is `Some`).
    Arg(Ident),
    /// A field on `self`, e.g. `self.value`. The key in the span is the field name.
    SelfField(Ident),
    /// The entirety of `&self`. The key in the span is `self_`.
    Self_,
}

#[derive(Debug, Clone, Copy)]
enum CaptureMode {
    Debug,
    Display,
}

impl Parse for CapturedArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let source = if input.peek(Token![self]) {
            input.parse::<token::SelfValue>()?;
            if input.peek(Token![.]) {
                input.parse::<Token![.]>()?;
                CaptureSource::SelfField(input.parse()?)
            } else {
                CaptureSource::Self_
            }
        } else {
            CaptureSource::Arg(input.parse()?)
        };
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

        // Optional `= <expr>` for an explicit value.  Only valid when the key is a
        // plain ident (i.e. not a bare `self` or `self.field` source).
        let value_expr = if input.peek(Token![=]) {
            match &source {
                CaptureSource::Arg(_) => {
                    input.parse::<Token![=]>()?;
                    Some(input.parse::<Expr>()?)
                }
                CaptureSource::SelfField(field) => {
                    return Err(syn::Error::new(
                        field.span(),
                        "`self.field = expr` is not valid; use `key = self.field` instead",
                    ));
                }
                CaptureSource::Self_ => {
                    return Err(syn::Error::new(
                        proc_macro2::Span::call_site(),
                        "`self = expr` is not valid; use `key = self` instead",
                    ));
                }
            }
        } else {
            None
        };

        Ok(CapturedArg {
            source,
            capture_mode,
            value_expr,
        })
    }
}

/// Arguments to the `#[instrument]` attribute.
#[derive(Default)]
struct InstrumentArgs {
    /// The log level for the span.
    level: Option<Ident>,
    /// Arguments to capture. If None, capture all non-skipped arguments with Debug.
    /// Supports plain argument names and `self.field` references for methods.
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
///   Defaults to `debug` if not specified.
/// - `fields(...)` - Specific fields to capture as span fields. When `fields(...)` is provided,
///   only the listed fields are captured; unlisted arguments (including `self` and its fields) are
///   ignored. Each entry has the form `key [':' mode] ['=' expr]`:
///   - `key` is an ident, `self`, or `self.field`.
///   - `mode` is `?`/`debug` for `Debug` or `%`/`display` for `Display`
///     (defaults to `Debug`).
///   - When `= expr` is omitted the value is inferred from `key`: a plain
///     ident reads the same-named fn argument, `self.field` reads that field,
///     and `self` captures `&self` under the span key `self_`.
///   - When `= expr` is present, `key` must be a plain ident and `expr` can
///     be any Rust expression (e.g. `self.bar`, `self`, `some_fn()`).
/// - `name` - Custom span name. Defaults to the function name.
/// - `skip(...)` - Arguments to skip from automatic capture. Has no effect on
///   `self` fields, which are never captured automatically.
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
/// // Capture self fields on a method
/// #[instrument(level = info, fields(self.id:?, self.name:%))]
/// fn process(&self) {
///     // ...
/// }
///
/// // Capture &self entirely on a method
/// #[instrument(level = debug, fields(self:?))]
/// fn process(&self) {
///     // ...
/// }
///
/// // Explicit key with an arbitrary value expression
/// #[instrument(level = debug, fields(user_id = self.id, name:% = self.name))]
/// fn process(&self) {
///     // user_id key uses Debug (default), name key uses Display
/// }
///
/// // Rename an argument in the span
/// #[instrument(level = info, fields(request = req))]
/// fn handle(req: &Request) {
///     // ...
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
        || quote! { ::litebox_util_log::Level::Debug },
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
    let captured_fields: Vec<CapturedArg> = if args.skip_all {
        Vec::new()
    } else if let Some(fields) = args.fields {
        fields
    } else {
        // Capture all non-skipped arguments with Debug
        fn_args
            .iter()
            .filter(|(name, _)| !args.skip.iter().any(|s| s == name))
            .map(|(name, _)| CapturedArg {
                source: CaptureSource::Arg(name.clone()),
                capture_mode: None,
                value_expr: None,
            })
            .collect()
    };

    // Generate the span creation code
    let span_creation = if captured_fields.is_empty() {
        quote! {
            let __litebox_span = ::litebox_util_log::span!(#level, #span_name);
        }
    } else {
        let field_tokens: Vec<TokenStream2> = captured_fields
            .iter()
            .map(|arg| {
                let mode_token = match arg.capture_mode.unwrap_or(CaptureMode::Debug) {
                    CaptureMode::Debug => quote! { :? },
                    CaptureMode::Display => quote! { :% },
                };
                if let Some(expr) = &arg.value_expr {
                    // Explicit `key [mode] = expr`
                    let CaptureSource::Arg(key) = &arg.source else {
                        unreachable!("parser rejects self/self.field with = expr")
                    };
                    quote! { #key #mode_token = #expr }
                } else {
                    match &arg.source {
                        CaptureSource::Arg(name) => quote! { #name #mode_token },
                        CaptureSource::SelfField(name) => {
                            quote! { #name #mode_token = self.#name }
                        }
                        CaptureSource::Self_ => quote! { self_ #mode_token = &self },
                    }
                }
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
