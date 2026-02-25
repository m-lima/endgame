{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
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
            pkgs.pkg-config
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
          bindgen = true;
          buildInputs = pkgs: [ pkgs.openssl ];
          nativeBuildInputs = pkgs: [ pkgs.pkg-config ];
          formatters = {
            clang-format.enable = true;
            mdformat.enable = true;
          };
          fmtExcludes = [
            "nginx/module/config"
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
            overrides.mainArgs.cargoExtraArgs = "-p cli";
          }
        );
        nginx = helper.lib.rust.helper inputs system ./. (
          rustOptions // { overrides.mainArgs.cargoExtraArgs = "-p nginx"; }
        );
      in
      all.outputs
      // {
        inherit module;
        packages = {
          cli = cli.outputs.packages.default;
          nginx = nginx.outputs.packages.default;
        };
        apps.default = cli.outputs.apps.default;
      }
    );
}
