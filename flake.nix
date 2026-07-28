{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
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
          inputs = [
            nginx.outputs.packages.default
            pkgs.openssl
          ];
          src = ./nginx/module;
        };
        nginx-headers = pkgs.stdenvNoCC.mkDerivation {
          name = "${pkgs.nginx.name}-headers";
          inherit (pkgs.nginx) version src;

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
        rustOptions = {
          binary = false;
          buildInputs = pkgs: [ pkgs.openssl ];
          nativeBuildInputs = pkgs: [
            pkgs.pkg-config
            pkgs.rust-cbindgen
          ];
          formatters = {
            clang-format.enable = true;
            mdformat.enable = true;
          };
          fmtExcludes = [
            "nginx/module/config"
            "nginx/include/endgame.h"
          ];
          overrides.devShell = {
            C_INCLUDE_PATH = "${nginx-headers}:${./nginx/include}";
          };
        };
        all = helper.lib.rust.helper inputs system ./. rustOptions;
        cli = helper.lib.rust.helper inputs system ./. (
          rustOptions
          // {
            binary = true;
            bindgen = false;
            overrides.mainArgs.cargoExtraArgs = "-p cli";
          }
        );
        nginx = helper.lib.rust.helper inputs system ./. (
          rustOptions
          // {
            overrides = {
              mainArgs = {
                cargoExtraArgs = "-p nginx";
                postInstall = ''
                  mkdir -p $out/include
                  cbindgen . --crate nginx --output $out/include/endgame.h
                '';
              };
            };
          }
        );
      in
      all.outputs
      // {
        inherit module;
        packages.default = cli.outputs.packages.default;
        apps.default = cli.outputs.apps.default;
      }
    );
}
