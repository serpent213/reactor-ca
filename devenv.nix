{ pkgs, ... }:
{
  # https://devenv.sh/packages/
  packages = with pkgs; [
    openssl
  ];

  # https://devenv.sh/languages/
  languages.go.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
