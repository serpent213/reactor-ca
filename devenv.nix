{ pkgs, ... }:
{
  # https://devenv.sh/packages/
  packages = with pkgs; [
    # Test support
    openssl
    openssh
  ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
    age-plugin-se
  ];

  # https://devenv.sh/languages/
  languages.go.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
