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
      # let
      #   pkgs = nixpkgs.legacyPackages.${system} // {
      #     overlays = [ fenix.overlays.default ];
      #   };
      #   module = {
      #     name = "endgame";
      #     meta = {
      #       description = "OpenIDC handler for nginx";
      #       license = [ pkgs.lib.licenses.mit ];
      #     };
      #     src = ./.;
      #   };
      #   rust = (
      #     helper.lib.rust.helper inputs system ./. {
      #       binary = false;
      #       bindgen = true;
      #     }
      #   );
      # in
      # rust.outputs
      # // {
      #   packages = rust.outputs.packages // {
      #     inherit module;
      #   };
      # }
      (helper.lib.rust.helper inputs system ./. {
        binary = false;
        bindgen = true;
      }).outputs
    );
}
