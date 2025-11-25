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
          name = "$(pkgs.nginx.name}-src";
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
        rust =
          (helper.lib.rust.helper inputs system ./. {
            binary = false;
            bindgen = true;
            overrides.commonArgs.C_INCLUDE_PATH = "${nginx-src}:${./include}";
          }).outputs;
      in
      rust
      // {
        packages = rust.packages // {
          inherit nginx nginx-src;
        };
      }
    );
}
