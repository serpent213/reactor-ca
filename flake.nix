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
            version = "0.3.0-unstable";
            src = ./.;

            vendorHash = "sha256-iBLMIoYM/1GiSS38Hwx4Ek/3kN51soQJL9UtbquLOS8=";

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
