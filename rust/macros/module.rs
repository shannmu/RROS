// SPDX-License-Identifier: GPL-2.0

use crate::helpers::*;
use proc_macro::{token_stream, Delimiter, Group, Literal, TokenStream, TokenTree};
use std::fmt::Write;

fn expect_string_array(it: &mut token_stream::IntoIter) -> Vec<String> {
    let group = expect_group(it);
    assert_eq!(group.delimiter(), Delimiter::Bracket);
    let mut values = Vec::new();
    let mut it = group.stream().into_iter();

    while let Some(val) = try_string(&mut it) {
        assert!(val.is_ascii(), "Expected ASCII string");
        values.push(val);
        match it.next() {
            Some(TokenTree::Punct(punct)) => assert_eq!(punct.as_char(), ','),
            None => break,
            _ => panic!("Expected ',' or end of array"),
        }
    }
    values
}

struct ModInfoBuilder<'a> {
    module: &'a str,
    counter: usize,
    buffer: String,
    param_buffer: String,
}

impl<'a> ModInfoBuilder<'a> {
    fn new(module: &'a str) -> Self {
        ModInfoBuilder {
            module,
            counter: 0,
            buffer: String::new(),
            param_buffer: String::new(),
        }
    }

    fn emit_base(&mut self, field: &str, content: &str, builtin: bool, param: bool) {
        let string = if builtin {
            // Built-in modules prefix their modinfo strings by `module.`.
            format!(
                "{module}.{field}={content}\0",
                module = self.module,
                field = field,
                content = content
            )
        } else {
            // Loadable modules' modinfo strings go as-is.
            format!("{field}={content}\0", field = field, content = content)
        };

        let buffer = if param {
            &mut self.param_buffer
        } else {
            &mut self.buffer
        };        

        write!(
            buffer,
            "
                {cfg}
                #[doc(hidden)]
                #[link_section = \".modinfo\"]
                #[used]
                pub static __{module}_{counter}: [u8; {length}] = *{string};
            ",
            cfg = if builtin {
                "#[cfg(not(MODULE))]"
            } else {
                "#[cfg(MODULE)]"
            },
            module = self.module.to_uppercase(),
            counter = self.counter,
            length = string.len(),
            string = Literal::byte_string(string.as_bytes()),
        )
        .unwrap();

        self.counter += 1;
    }

    fn emit_only_builtin(&mut self, field: &str, content: &str, param: bool) {
        self.emit_base(field, content, true, param)
    }

    fn emit_only_loadable(&mut self, field: &str, content: &str, param: bool) {
        self.emit_base(field, content, false, param)
    }

    fn emit(&mut self, field: &str, content: &str) {
        self.emit_internal(field, content, false);        
    }

    fn emit_internal(&mut self, field: &str, content: &str, param: bool) {
        self.emit_only_builtin(field, content, param);
        self.emit_only_loadable(field, content, param);
    }

    fn emit_param(&mut self, field: &str, param: &str, content: &str) {
        let content = format!("{param}:{content}", param = param, content = content);
        self.emit_internal(field, &content, true);
    }

    fn emit_params(&mut self, info: &ModuleInfo) {
        if let Some(params) = &info.params {
            assert_eq!(params.delimiter(), Delimiter::Brace);

            let mut it = params.stream().into_iter();

            loop {
                let param_name = match it.next() {
                    Some(TokenTree::Ident(ident)) => ident.to_string(),
                    Some(_) => panic!("Expected Ident or end"),
                    None => break,
                };

                assert_eq!(expect_punct(&mut it), ':');
                let param_type = expect_ident(&mut it);
                let group = expect_group(&mut it);
                assert_eq!(expect_punct(&mut it), ',');

                assert_eq!(group.delimiter(), Delimiter::Brace);

                let mut param_it = group.stream().into_iter();
                let param_default = get_param_default(&mut param_it);
                let param_description = get_string(&mut param_it, "description");
                expect_end(&mut param_it);

                let (param_kernel_type, ops): (String, _) = (
                    param_type.to_string(),
                    param_ops_path(&param_type).to_string(),
                );

                self.emit_param("parmtype", &param_name, &param_kernel_type);
                self.emit_param("parm", &param_name, &param_description);
                let param_type_internal = param_type.clone();

                let read_func = format!(
                    "
                        pub(crate) fn read(&self)
                            -> &<{param_type_internal}
                                as kernel::module_param::ModuleParam>::Value {{
                            // Note: when we enable r/w parameters, we need to lock here.

                            // SAFETY: Parameters do not need to be locked because they are
                            // read only or sysfs is not enabled.
                            unsafe {{
                                <{param_type_internal} as kernel::module_param::ModuleParam>::value(
                                    &__{name}_{param_name}_value
                                )
                            }}
                        }}
                    ",
                    name = info.name,
                    param_name = param_name,
                    param_type_internal = param_type_internal,
                );

                let kparam = format!(
                    "
                    kernel::bindings::kernel_param__bindgen_ty_1 {{
                        // SAFETY: Access through the resulting pointer is
                        // serialized by C side and only happens before module
                        // `init` or after module `drop` is called.
                        arg: unsafe {{ &__{name}_{param_name}_value }}
                            as *const _ as *mut core::ffi::c_void,
                    }},
                ",
                    name = info.name,
                    param_name = param_name,
                );
                write!(
                    self.param_buffer,
                    "
                static mut __{name}_{param_name}_value: {param_type_internal} = {param_default};

                pub(crate) struct __{name}_{param_name};

                impl __{name}_{param_name} {{ {read_func} }}

                pub(crate) const {param_name}: __{name}_{param_name} = __{name}_{param_name};

                // Note: the C macro that generates the static structs for the `__param` section
                // asks for them to be `aligned(sizeof(void *))`. However, that was put in place
                // in 2003 in commit 38d5b085d2a0 (\"[PATCH] Fix over-alignment problem on x86-64\")
                // to undo GCC over-alignment of static structs of >32 bytes. It seems that is
                // not the case anymore, so we simplify to a transparent representation here
                // in the expectation that it is not needed anymore.
                // TODO: Revisit this to confirm the above comment and remove it if it happened.
                /// Newtype to make `bindings::kernel_param` `Sync`.
                #[repr(transparent)]
                struct __{name}_{param_name}_RacyKernelParam(kernel::bindings::kernel_param);

                // SAFETY: C kernel handles serializing access to this type. We
                // never access from Rust module.
                unsafe impl Sync for __{name}_{param_name}_RacyKernelParam {{
                }}

                #[cfg(not(MODULE))]
                const __{name}_{param_name}_name: *const core::ffi::c_char =
                    b\"{name}.{param_name}\\0\" as *const _ as *const core::ffi::c_char;

                #[cfg(MODULE)]
                const __{name}_{param_name}_name: *const core::ffi::c_char =
                    b\"{param_name}\\0\" as *const _ as *const core::ffi::c_char;

                #[link_section = \"__param\"]
                #[used]
                static __{name}_{param_name}_struct: __{name}_{param_name}_RacyKernelParam =
                    __{name}_{param_name}_RacyKernelParam(kernel::bindings::kernel_param {{
                        name: __{name}_{param_name}_name,
                        // SAFETY: `__this_module` is constructed by the kernel at load time
                        // and will not be freed until the module is unloaded.
                        #[cfg(MODULE)]
                        mod_: unsafe {{ &kernel::bindings::__this_module as *const _ as *mut _ }},
                        #[cfg(not(MODULE))]
                        mod_: core::ptr::null_mut(),
                        // SAFETY: This static is actually constant as seen by
                        // module code. But we need a unique address for it, so it
                        // must be static.
                        ops: unsafe {{ &{ops} }} as *const kernel::bindings::kernel_param_ops,
                        perm: 0, // Will not appear in sysfs
                        level: -1,
                        flags: 0,
                        __bindgen_anon_1: {kparam}
                    }});
                ",
                    name = info.name,
                    param_type_internal = param_type_internal,
                    read_func = read_func,
                    param_default = param_default,
                    param_name = param_name,
                    ops = ops,
                    kparam = kparam,
                )
                .unwrap();
            }
        }
    }

    // fn emit_params(&mut self, info: &ModuleInfo) { // patchv2.0
    //     if let Some(params) = &info.params {
    //         for param in params {
    //             let ops = param_ops_path(&param.ptype);

    //             self.emit_param("parmtype", &param.name, &param.ptype);
    //             self.emit_param("parm", &param.name, &param.description);

    //             write!(
    //                 self.param_buffer,
    //                 "
    //             static mut __{name}_{param_name}_value: {param_type} = {param_default};

    //             pub(crate) enum {param_name} {{}}

    //             impl {param_name} {{
    //                 pub(crate) fn read<'a>()
    //                     -> &'a <{param_type} as ::kernel::module_param::ModuleParam>::Value {{
    //                     // Note: when we enable r/w parameters, we need to lock here.

    //                     // SAFETY: Parameters do not need to be locked because they are
    //                     // read only or sysfs is not enabled.
    //                     unsafe {{
    //                         <{param_type} as ::kernel::module_param::ModuleParam>::value(
    //                             &__{name}_{param_name}_value
    //                         )
    //                     }}
    //                 }}
    //             }}

    //             /// Newtype to make `bindings::kernel_param` `Sync`.
    //             #[repr(transparent)]
    //             struct __{name}_{param_name}_RacyKernelParam(::kernel::bindings::kernel_param);

    //             // SAFETY: C kernel handles serializing access to this type. We
    //             // never access from Rust module.
    //             unsafe impl Sync for __{name}_{param_name}_RacyKernelParam {{ }}

    //             #[cfg(not(MODULE))]
    //             const __{name}_{param_name}_name: *const ::core::ffi::c_char =
    //                 b\"{name}.{param_name}\\0\" as *const _ as *const ::core::ffi::c_char;

    //             #[cfg(MODULE)]
    //             const __{name}_{param_name}_name: *const ::core::ffi::c_char =
    //                 b\"{param_name}\\0\" as *const _ as *const ::core::ffi::c_char;

    //             #[link_section = \"__param\"]
    //             #[used]
    //             static __{name}_{param_name}_struct: __{name}_{param_name}_RacyKernelParam =
    //                 __{name}_{param_name}_RacyKernelParam(::kernel::bindings::kernel_param {{
    //                     name: __{name}_{param_name}_name,
    //                     // SAFETY: `__this_module` is constructed by the kernel at load time
    //                     // and will not be freed until the module is unloaded.
    //                     #[cfg(MODULE)]
    //                     mod_: unsafe {{ &::kernel::bindings::__this_module as *const _ as *mut _ }},
    //                     #[cfg(not(MODULE))]
    //                     mod_: ::core::ptr::null_mut(),
    //                     ops: &{ops} as *const ::kernel::bindings::kernel_param_ops,
    //                     perm: 0, // Will not appear in sysfs
    //                     level: -1,
    //                     flags: 0,
    //                     __bindgen_anon_1:
    //                         ::kernel::bindings::kernel_param__bindgen_ty_1 {{
    //                             // SAFETY: As this is evaluated in const context, it is
    //                             // safe to take a reference to a mut static.
    //                             arg: unsafe {{
    //                                 ::core::ptr::addr_of_mut!(__{name}_{param_name}_value)
    //                                 }}.cast::<::core::ffi::c_void>(),
    //                         }},
    //                 }});
    //             ",
    //                 name = info.name,
    //                 param_type = param.ptype,
    //                 param_default = param.default,
    //                 param_name = param.name,
    //                 ops = ops,
    //             )
    //             .unwrap();
    //         }
    //     }
    // }
}

fn param_ops_path(param_type: &str) -> &'static str {
    match param_type {
        "i8" => "kernel::module_param::PARAM_OPS_I8",
        "u8" => "kernel::module_param::PARAM_OPS_U8",
        "i16" => "kernel::module_param::PARAM_OPS_I16",
        "u16" => "kernel::module_param::PARAM_OPS_U16",
        "i32" => "kernel::module_param::PARAM_OPS_I32",
        "u32" => "kernel::module_param::PARAM_OPS_U32",
        "i64" => "kernel::module_param::PARAM_OPS_I64",
        "u64" => "kernel::module_param::PARAM_OPS_U64",
        "isize" => "kernel::module_param::PARAM_OPS_ISIZE",
        "usize" => "kernel::module_param::PARAM_OPS_USIZE",
        t => panic!("Unsupported parameter type {}", t),
    }
}

fn get_param_default(param_it: &mut token_stream::IntoIter) -> String {
    assert_eq!(expect_ident(param_it), "default");
    assert_eq!(expect_punct(param_it), ':');
    let default = try_literal(param_it).expect("Expected default param value");
    assert_eq!(expect_punct(param_it), ',');
    default
}

fn expect_param_default(param_it: &mut token_stream::IntoIter) -> String {
    assert_eq!(expect_ident(param_it), "default");
    assert_eq!(expect_punct(param_it), ':');
    let default = try_literal(param_it).expect("Expected default param value");
    assert_eq!(expect_punct(param_it), ',');
    default
}

#[derive(Debug, Default)]
struct ModuleInfo {
    type_: String,
    license: String,
    name: String,
    author: Option<String>,
    description: Option<String>,
    alias: Option<Vec<String>>,
    params: Option<Group>,
}

#[derive(Debug)]
struct Parameter {
    name: String,
    ptype: String,
    default: String,
    description: String,
}

fn expect_params(it: &mut token_stream::IntoIter) -> Vec<Parameter> {
    let params = expect_group(it);
    assert_eq!(params.delimiter(), Delimiter::Brace);
    let mut it = params.stream().into_iter();
    let mut parsed = Vec::new();

    loop {
        let param_name = match it.next() {
            Some(TokenTree::Ident(ident)) => ident.to_string(),
            Some(_) => panic!("Expected Ident or end"),
            None => break,
        };

        assert_eq!(expect_punct(&mut it), ':');
        let param_type = expect_ident(&mut it);
        let group = expect_group(&mut it);
        assert_eq!(group.delimiter(), Delimiter::Brace);
        assert_eq!(expect_punct(&mut it), ',');

        let mut param_it = group.stream().into_iter();
        let param_default = expect_param_default(&mut param_it);
        let param_description = expect_string_field(&mut param_it, "description");
        expect_end(&mut param_it);

        parsed.push(Parameter {
            name: param_name,
            ptype: param_type,
            default: param_default,
            description: param_description,
        })
    }

    parsed
}

impl ModuleInfo {
    fn parse(it: &mut token_stream::IntoIter) -> Self {
        let mut info = ModuleInfo::default();

        const EXPECTED_KEYS: &[&str] = &[
            "type",
            "name",
            "author",
            "description",
            "license",
            "alias",
            "params",
        ];
        
        const REQUIRED_KEYS: &[&str] = &["type", "name", "license"];
        let mut seen_keys = Vec::new();

        loop {
            let key = match it.next() {
                Some(TokenTree::Ident(ident)) => ident.to_string(),
                Some(_) => panic!("Expected Ident or end"),
                None => break,
            };

            if seen_keys.contains(&key) {
                panic!(
                    "Duplicated key \"{}\". Keys can only be specified once.",
                    key
                );
            }

            assert_eq!(expect_punct(it), ':');

            match key.as_str() {
                "type" => info.type_ = expect_ident(it),
                "name" => info.name = expect_string_ascii(it),
                "author" => info.author = Some(expect_string(it)),
                "description" => info.description = Some(expect_string(it)),
                "license" => info.license = expect_string_ascii(it),
                "alias" => info.alias = Some(expect_string_array(it)),
                "params" => info.params = Some(expect_group(it)),
                _ => panic!(
                    "Unknown key \"{}\". Valid keys are: {:?}.",
                    key, EXPECTED_KEYS
                ),
            }

            assert_eq!(expect_punct(it), ',');

            seen_keys.push(key);
        }

        expect_end(it);

        for key in REQUIRED_KEYS {
            if !seen_keys.iter().any(|e| e == key) {
                panic!("Missing required key \"{}\".", key);
            }
        }

        let mut ordered_keys: Vec<&str> = Vec::new();
        for key in EXPECTED_KEYS {
            if seen_keys.iter().any(|e| e == key) {
                ordered_keys.push(key);
            }
        }

        if seen_keys != ordered_keys {
            panic!(
                "Keys are not ordered as expected. Order them like: {:?}.",
                ordered_keys
            );
        }

        info
    }
}

pub(crate) fn module(ts: TokenStream) -> TokenStream {
    let mut it = ts.into_iter();

    let info = ModuleInfo::parse(&mut it);

    let mut modinfo = ModInfoBuilder::new(info.name.as_ref());
    if let Some(author) = &info.author {
        modinfo.emit("author", author);
    }
    if let Some(description) = &info.description {
        modinfo.emit("description", description);
    }
    modinfo.emit("license", &info.license);
    if let Some(aliases) = &info.alias {
        for alias in aliases {
            modinfo.emit("alias", alias);
        }
    }

    // Built-in modules also export the `file` modinfo string.
    let file =
        std::env::var("RUST_MODFILE").expect("Unable to fetch RUST_MODFILE environmental variable");
        modinfo.emit_only_builtin("file", &file, false);
        
        modinfo.emit_params(&info);

    format!(
        "
            /// The module name.
            ///
            /// Used by the printing macros, e.g. [`info!`].
            const __LOG_PREFIX: &[u8] = b\"{name}\\0\";

            /// The \"Rust loadable module\" mark.
            //
            // This may be best done another way later on, e.g. as a new modinfo
            // key or a new section. For the moment, keep it simple.
            #[cfg(MODULE)]
            #[doc(hidden)]
            #[used]
            static __IS_RUST_MODULE: () = ();

            static mut __MOD: Option<{type_}> = None;

            // SAFETY: `__this_module` is constructed by the kernel at load time and will not be
            // freed until the module is unloaded.
            #[cfg(MODULE)]
            static THIS_MODULE: kernel::ThisModule = unsafe {{
                kernel::ThisModule::from_ptr(&kernel::bindings::__this_module as *const _ as *mut _)
            // static THIS_MODULE: ::kernel::ThisModule = unsafe {{
            //     ::kernel::ThisModule::from_ptr(
            //         &::kernel::bindings::__this_module as *const _ as *mut _
            //     )
            
            }};
            #[cfg(not(MODULE))]
            static THIS_MODULE: kernel::ThisModule = unsafe {{
                kernel::ThisModule::from_ptr(core::ptr::null_mut())
            // static THIS_MODULE: ::kernel::ThisModule = unsafe {{
            //     ::kernel::ThisModule::from_ptr(::core::ptr::null_mut())
            }};

            // Loadable modules need to export the `{{init,cleanup}}_module` identifiers.
            /// # Safety
            ///
            /// This function must not be called after module initialization, because it may be
            /// freed after that completes.
            #[cfg(MODULE)]
            #[doc(hidden)]
            #[no_mangle]
            #[link_section = \".init.text\"]
            pub unsafe extern \"C\" fn init_module() -> core::ffi::c_int {{
                __init()
            }}

            #[cfg(MODULE)]
            #[doc(hidden)]
            #[no_mangle]
            pub extern \"C\" fn cleanup_module() {{
                __exit()
            }}

            // Built-in modules are initialized through an initcall pointer
            // and the identifiers need to be unique.
            #[cfg(not(MODULE))]
            #[cfg(not(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS))]
            #[doc(hidden)]
            #[link_section = \"{initcall_section}\"]
            #[used]
            pub static __{name}_initcall: extern \"C\" fn() -> core::ffi::c_int = __{name}_init;
            // pub static __{name}_initcall: extern \"C\" fn()
            //     -> ::core::ffi::c_int = __{name}_init;

            #[cfg(not(MODULE))]
            #[cfg(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS)]
            core::arch::global_asm!(
                r#\".section \"{initcall_section}\", \"a\"
                __{name}_initcall:
                    .long   __{name}_init - .
                    .previous
                \"#
            );

            #[cfg(not(MODULE))]
            #[doc(hidden)]
            #[no_mangle]
            pub extern \"C\" fn __{name}_init() -> core::ffi::c_int {{
            // pub extern \"C\" fn __{name}_init() -> ::core::ffi::c_int {{
                __init()
            }}

            #[cfg(not(MODULE))]
            #[doc(hidden)]
            #[no_mangle]
            pub extern \"C\" fn __{name}_exit() {{
                __exit()
            }}

            fn __init() -> core::ffi::c_int {{
                match <{type_} as kernel::Module>::init(&THIS_MODULE) {{
            // fn __init() -> ::core::ffi::c_int {{
            //     match <{type_} as ::kernel::Module>::init(&THIS_MODULE) {{
                    Ok(m) => {{
                        unsafe {{
                            __MOD = Some(m);
                        }}
                        return 0;
                    }}
                    Err(e) => {{
                        return e.to_errno();
                    }}
                }}
            }}

            fn __exit() {{
                unsafe {{
                    // Invokes `drop()` on `__MOD`, which should be used for cleanup.
                    __MOD = None;
                }}
            }}

            {modinfo}

            mod module_parameters {{
                {params}
            }}
        ",
        type_ = info.type_,
        name = info.name,
        modinfo = modinfo.buffer,
        params = modinfo.param_buffer,
        initcall_section = ".initcall6.init"
    )
    .parse()
    .expect("Error parsing formatted string into token stream.")
}
