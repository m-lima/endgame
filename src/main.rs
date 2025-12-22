fn help<O: std::io::Write>(mut output: O) {
    let _ = writeln!(output, "Usage: engame <ARGS..> [EXTRAS..]");
    let _ = writeln!(output);
    let _ = writeln!(output, "ARGS:");
    let _ = writeln!(output, "  -k --key     Key in base64 format");
    let _ = writeln!(output, "  -e --email   Email to encrypt");
    let _ = writeln!(output);
    let _ = writeln!(output, "EXTRAS:");
    let _ = writeln!(output, "  -g --given   Given name to encrypt");
    let _ = writeln!(output, "  -f --family  Family name to encrypt");
    let _ = writeln!(output, "  -a --age     Age in seconds of the token");
}

fn parse_args<I: Iterator<Item = String>>(mut args: I) -> (crypter::Key, endgame::types::Token) {
    macro_rules! error {
        ($msg: literal) => {
            error!($msg,)
        };
        ($msg: literal, $($arg: tt)*) => {{
            eprintln!(concat!("[31m", $msg, "\n"), $($arg)*);
            help(std::io::stderr().lock());
            std::process::exit(1);
        }};
    }

    let mut key = None;
    let mut timestamp = None;
    let mut email = None;
    let mut given_name = None;
    let mut family_name = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                help(std::io::stdout().lock());
                std::process::exit(0);
            }
            "-k" | "--key" => {
                let Some(arg) = args.next() else {
                    error!("Missing key parameter");
                };
                let arg =
                    match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, arg) {
                        Ok(p) => p,
                        Err(err) => error!("Failed do decode base64: '{}'", err),
                    };

                if arg.len() != 32 {
                    error!("Key is not 32 bytes");
                }
                let mut buffer = [0; 32];
                buffer.copy_from_slice(&arg);
                key = Some(buffer);
            }
            "-e" | "--email" => {
                let Some(arg) = args.next() else {
                    error!("Missing email parameter");
                };
                email = Some(arg);
            }
            "-g" | "--given" => {
                let Some(arg) = args.next() else {
                    error!("Missing given name parameter");
                };
                given_name = Some(arg);
            }
            "-f" | "--family" => {
                let Some(arg) = args.next() else {
                    error!("Missing family name parameter");
                };
                family_name = Some(arg);
            }
            "-a" | "--age" => {
                let Some(arg) = args.next() else {
                    error!("Missing timestamp parameter");
                };
                let arg = match arg.parse() {
                    Ok(a) => a,
                    Err(err) => error!("Failed do parse timestamp: '{}'", err),
                };
                timestamp = Some(arg);
            }
            arg => {
                error!("Unrecognized argument: '{}'", arg);
            }
        }
    }

    let Some(key) = key else {
        error!("Missing key");
    };

    let Some(email) = email else {
        error!("Missing email");
    };

    let timestamp = endgame::types::Timestamp::now() - timestamp.unwrap_or(0);

    (
        key,
        endgame::types::Token {
            timestamp,
            email,
            given_name,
            family_name,
        },
    )
}

fn main() {
    let args = std::env::args().skip(1);
    let (key, token) = parse_args(args);

    let cookie = endgame::dencrypt::encrypt(key, &token).expect("Failed to encrypt");
    println!("{cookie}");
}
