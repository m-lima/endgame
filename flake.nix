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
        pkgs = nixpkgs.legacyPackages.${system} // {
          overlays = [ fenix.overlays.default ];
        };
        module = {
          name = "endgame";
          meta = {
            description = "OpenIDC handler for nginx";
            license = [ pkgs.lib.licenses.mit ];
          };
          src = ./.;
        };
        nginx =
          (pkgs.nginx.override {
            modules = [ module ];
          }).overrideAttrs
            (prev: {
              nativeBuildInputs = prev.nativeBuildInputs ++ [ fenix.packages.${system}.stable.minimalToolchain ];
            });
        nginx-src = (pkgs.nginx.override { modules = [ ]; }).overrideAttrs {
          outputs = [ "out" ];
          installPhase = ''
            mkdir -p $out
            cp -a . $out/
            # ln -s $PWD $out/src
          '';
        };
        # nginx-src = pkgs.stdenv.mkDerivation {
        #   name = "$(pkgs.nginx.name}-src";
        #   inherit (pkgs.nginx) version src;
        #
        #   # dontConfigure = true;
        #   # dontBuild = true;
        #
        #   installPhase = ''
        #     mkdir -p $out
        #     cp -r . $out/
        #   '';
        # };
        rust = (
          helper.lib.rust.helper inputs system ./. {
            binary = false;
            features = [ "vendored" ];
            nativeBuildInputs = pkgs: [
              (pkgs.writeShellScriptBin "gmake" ''exec ${pkgs.gnumake}/bin/make $@'')
              pkgs.llvmPackages.clang
            ];
            buildInputs = pkgs: [
              pkgs.openssl
            ];
            overrides = {
              commonArgs = {
                NGX_CONFIGURE_ARGS = builtins.concatStringsSep " " [
                  "--without-pcre"
                  "--without-http_rewrite_module"
                  "--without-http_gzip_module"
                ];
                LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
              };
            };
          }
        );
      in
      rust.outputs
      // {
        packages = rust.outputs.packages // {
          inherit nginx module nginx-src;
        };
      }
    );
}
