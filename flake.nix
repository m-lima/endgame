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
        nginx = pkgs.nginx.override {
          modules = [
            pkgs.nginxModules.moreheaders
            module
          ];
        };
        outputs =
          (helper.lib.rust.helper inputs system ./. {
            binary = false;
            features = [ "vendored" ];
            nativeBuildInputs = pkgs: [
              pkgs.gnumake
              (pkgs.writeShellScriptBin "gmake" ''exec make $@'')
              pkgs.llvmPackages.libclang.lib
              pkgs.llvmPackages.clang
              pkgs.pkg-config
              pkgs.glibc.dev
            ];
            buildInputs = pkgs: [
              pkgs.llvmPackages.libclang.lib
              pkgs.llvmPackages.clang
              pkgs.openssl
              pkgs.glibc.dev
              # pkgs.pcre2
              pkgs.pkg-config
            ];
            overrides = {
              commonArgs = {
                NGX_CONFIGURE_ARGS = builtins.concatStringsSep " " [
                  "--without-pcre"
                  "--without-http_rewrite_module"
                  "--without-http_gzip_module"
                ];
                LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
                # BINDGEN_EXTRA_CLANG_ARGS = "--sysroot=$(dirname $(dirname $(realpath $(which clang))))/../lib/clang/$(clang --version | head -n1 | awk '{print $3}')/include --sysroot=${pkgs.stdenv.cc.libc.dev}";
                BINDGEN_EXTRA_CLANG_ARGS = "--sysroot=${pkgs.stdenv.cc.libc.dev}";
              };
            };
          }).outputs;
      in
      outputs
      // {
        packages = outputs.packages // {
          inherit nginx module;
        };
      }
    );
}
