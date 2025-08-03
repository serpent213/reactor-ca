{
  description = "ReactorCA - A Go-based CLI tool for managing private PKI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages = {
          reactor-ca = pkgs.buildGoModule {
            pname = "reactor-ca";
            version = "0.5.0";
            src = ./.;

            vendorHash = "sha256-tFd1p+bY1mSODyl35kj6XFBwVhTTQ5iotUn6Om2TgpA=";

            preBuild = ''
              go generate ./...
            '';

            subPackages = [ "cmd/ca" ];

            meta = with pkgs.lib; {
              description = "Go-based CLI tool for managing private PKI for homelab and small business environments";
              homepage = "https://github.com/serpent213/reactor-ca";
              license = licenses.bsd2;
              maintainers = [ ];
              platforms = platforms.all;
              mainProgram = "ca";
            };
          };

          default = self.packages.${system}.reactor-ca;
        };
      }
    );
}
