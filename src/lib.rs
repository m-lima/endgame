#![warn(clippy::pedantic)]

struct Module;

// impl ngx::http::HttpModule for Module {
//     fn module() -> &'static ngx::ffi::ngx_module_t {
//         todo!()
//     }
// }
//
// unsafe impl ngx::http::HttpModuleMainConf for Module {
//     type MainConf = ModuleConfig;
// }
//
// unsafe impl ngx::http::HttpModuleServerConf for Module {
//     type ServerConf = ModuleConfig;
// }
//
// unsafe impl ngx::http::HttpModuleLocationConf for Module {
//     type LocationConf = ModuleConfig;
// }

#[derive(Debug, Clone)]
struct ModuleConfig {
    enabled: bool,
    auth_config: AuthConfig,
    token_config: TokenConfig,
    session_config: SessionConfig,
    proxy_header_prefix: String,
    allowed_users: Vec<Email>,
}

#[derive(Debug, Clone)]
struct AuthConfig {
    client_id: String,
    client_secret: String,
    callback_url: String,
}

#[derive(Debug, Clone)]
struct TokenConfig {
    header_name: String,
    secret: [u8; 32],
}

#[derive(Debug, Clone)]
struct SessionConfig {
    name: String,
    secret: [u8; 32],
    ttl: std::time::Duration,
    domain: String,
}

#[derive(Debug, Clone)]
struct Email(String);

struct UserToken {
    email: Email,
    first_name: Option<String>,
    last_name: Option<String>,
    expiration: std::time::Instant,
}

// static mut NGX_HTTP_ENDGAME_COMMANDS: [ngx::ffi::ngx_command_t; _] = [
//     ngx::ffi::ngx_command_t {
//         name: ngx::ngx_string!("endgame_enabled"),
//         type_: (ngx::ffi::NGX_HTTP_MAIN_CONF
//             | ngx::ffi::NGX_HTTP_SRV_CONF
//             | ngx::ffi::NGX_HTTP_LOC_CONF
//             | ngx::ffi::NGX_CONF_TAKE1) as ngx::ffi::ngx_uint_t,
//         set: todo!(),
//         conf: todo!(),
//         offset: todo!(),
//         post: todo!(),
//     },
//     ngx::ffi::ngx_command_t::empty(),
// ];
