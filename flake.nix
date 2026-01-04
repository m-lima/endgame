{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    crane.url = "github:ipetkov/crane";
    fenix = {
      url = "github:nix-community/fenix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    helper.url = "github:m-lima/nix-template";
  };

  outputs =
    {
      nixpkgs,
      fenix,
      flake-utils,
      helper,
      ...
    }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        module = {
          name = "endgame";
          meta = {
            description = "OpenIDC handler for nginx";
            license = [ pkgs.lib.licenses.mit ];
          };
          inputs = [ rust.packages.default ];
          src = ./module;
        };
        nginx = pkgs.nginx.override {
          modules = [ module ];
          # TODO
          withDebug = true;
        };
        nginx-src = pkgs.stdenvNoCC.mkDerivation {
          name = "${nginx.name}-src";
          inherit (nginx) version src;

          dontConfigure = true;
          dontBuild = true;

          installPhase = ''
            mkdir -p "$out"

            for f in $(find . -name '*.h' -type f); do
              cp "$f" "$out/$(basename "$f")"
            done
            touch "$out/ngx_auto_headers.h"
          '';
        };
        nginx-docker = pkgs.dockerTools.buildImage {
          name = "${nginx.pname}-${rust.packages.default.pname}";
          tag = rust.packages.default.version;
          runAsRoot = ''
            #!${pkgs.runtimeShell}
            mkdir -p /etc
            echo -n 'nobody:x:65534:65534:nobody:/:/sbin/nologin' > /etc/passwd
            echo -n 'nogroup:x:65533:\n' > /etc/group
          '';
          copyToRoot = [
            pkgs.cacert
          ];
          config = {
            Cmd = [
              "${nginx}/bin/nginx"
              "-e"
              "/dev/stderr"
              "-c"
              "${pkgs.writeText "nginx.conf" ''
                daemon off;
                pid /tmp/endgame.pid;

                events {}
                http {
                  log_format main '$host '
                    '- $remote_addr $request_method $request_uri ''${request_length}b '
                    '- $status ''${bytes_sent}b ''${request_time}s '
                    '- $http_user_agent';
                  access_log stderr main;
                  # TODO
                  error_log stderr debug;

                  server {
                    endgame on;
                    endgame_key raw MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=;
                    endgame_discovery_url https://accounts.google.com/;
                    endgame_client_id client;
                    endgame_client_secret secret;
                    endgame_callback_url http://localhost/callback;

                    listen 0.0.0.0:80 default_server;
                    listen [::0]:80 default_server;
                    server_name localhost;

                    location / {
                    }

                    location /on {
                      endgame on;
                      endgame_auto_login on;
                      endgame_key file ${pkgs.writeText "mockKey" "0123456789abcdef0123456789abcdef"};
                    }

                    location /off {
                      endgame off;
                    }

                    location /diff {
                      endgame on;
                      endgame_session_name diff;
                    }

                    location /callback {
                      endgame callback;
                    }
                  }
                }
              ''}"
            ];
          };
        };
        rust =
          (helper.lib.rust.helper inputs system ./. {
            # TODO
            mega = false;
            binary = false;
            bindgen = true;
            buildInputs = pkgs: [ pkgs.openssl ];
            nativeBuildInputs = pkgs: [ pkgs.pkg-config ];
            devPackages =
              let
                policy = pkgs.writeText "policy.json" ''{ "default": [ { "type": "insecureAcceptAnything" } ] }'';
              in
              pkgs: [
                pkgs.podman
                (pkgs.writeShellScriptBin "podman-build-nix" "podman build --signature-policy ${policy} $@")
                (pkgs.writeShellScriptBin "podman-load-nix" "podman load --signature-policy ${policy} $@")
              ];
            overrides.commonArgs = {
              C_INCLUDE_PATH = "${nginx-src}:${./include}";
              # TODO
              CARGO_PROFILE = "dev";
            };
          }).outputs;
      in
      rust
      // {
        packages = rust.packages // {
          inherit nginx nginx-src nginx-docker;
        };
      }
    );
}
