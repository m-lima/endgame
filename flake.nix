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
          copyToRoot = [ nginx ];
          runAsRoot = ''
            #!${pkgs.runtimeShell}
            mkdir -p /etc
            echo -n 'nobody:x:65534:65534:nobody:/:/sbin/nologin' > /etc/passwd
            echo -n 'nogroup:x:65533:\n' > /etc/group
          '';
          config = {
            Cmd = [
              "nginx"
              "-e"
              "/dev/stderr"
              "-c"
              "${pkgs.writeText "conf/nginx.conf" ''
                daemon off;
                pid /tmp/endgame.pid;

                events {}
                http {
                  log_format main '$host '
                    '- $remote_addr $request_method $request_uri ''${request_length}b '
                    '- $status ''${bytes_sent}b ''${request_time}s '
                    '- $http_user_agent';
                  access_log syslog:server=unix:/dev/log main;

                  server {
                    endgame on;
                    listen 0.0.0.0:80 default_server;
                    listen [::0]:80 default_server;
                    server_name localhost;
                    location /on {
                      endgame on;
                    }
                    location /off {
                      endgame off;
                    }
                    location /diff {
                      endgame on;
                      endgame_session_name diff;
                    }
                    location / {
                    }
                  }
                }
              ''}"
            ];
          };
        };
        rust =
          (helper.lib.rust.helper inputs system ./. {
            binary = false;
            bindgen = true;
            devPackages =
              let
                policy = pkgs.writeText "policy.json" ''{ "default": [ { "type": "insecureAcceptAnything" } ] }'';
              in
              pkgs: [
                pkgs.podman
                (pkgs.writeShellScriptBin "podman-build-nix" "podman build --signature-policy ${policy} $@")
                (pkgs.writeShellScriptBin "podman-load-nix" "podman load --signature-policy ${policy} $@")
              ];
            overrides.commonArgs.C_INCLUDE_PATH = "${nginx-src}:${./include}";
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
