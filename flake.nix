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
        nginx = pkgs.nginx.override {
          modules = [
            pkgs.nginxModules.moreheaders
            {
              name = "endgame";
              meta = {
                description = "OpenIDC handler for nginx";
                license = [ pkgs.lib.licenses.mit ];
              };
              src = ./.;
            }
          ];
          # buildPhase = ""; # "runHook preBuild && runHook postBuild";
          # installPhase = ''
          #   runHook preInstall
          #   cp -a $src $out
          #   runHook postInstall
          # '';
        };
        # nginx = pkgs.stdenv.mkDerivation {
        #   name = "${pkgs.nginx.name}-src";
        #
        #   src = pkgs.nginx.src;
        #
        #   nativeBuildInputs = [
        #     pkgs.pcre
        #   ];
        #
        #   configurePhase = "runHook preConfigure && runHook postConfigure";
        #   buildPhase = "runHook preBuild && runHook postBuild";
        #   installPhase = ''
        #     runHook preInstall
        #     mkdir -p $out
        #     tar -xzf $src -C $out --strip-components=1
        #     $out/configure --without-http_gzip_module
        #     runHook postInstall
        #   '';
        # };
        outputs =
          (helper.lib.rust.helper inputs system ./. {
            binary = false;
            # nativeBuildInputs = pkgs: [ pkgs.nginx.src ];
            overrides = {
              commonArgs = {
                NGINX_SOURCE_DIR = nginx;
              };

              # devShell = {
              #   NGINX_SOURCE_DIR = nginx;
              # };

              # commonArgs =
              #   default:
              #   (builtins.removeAttrs default [ "src" ])
              #   // {
              #     srcs = [
              #       default.src
              #       pkgs.nginx.src
              #     ];
              #
              #     unpackPhase = "ls -lah && false";
              #   };
            };
          }).outputs;
      in
      outputs
      // {
        packages = outputs.packages // {
          inherit nginx;
        };
      }
    );
}
