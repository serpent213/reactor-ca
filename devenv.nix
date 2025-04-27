{ pkgs, lib, config, inputs, ... }:

{
  # https://devenv.sh/languages/
  languages.python.enable = true;
  languages.python.poetry.enable = true;
  languages.python.poetry.install.enable = true;
  languages.python.poetry.activate.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
