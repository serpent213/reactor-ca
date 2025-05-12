{
  # https://devenv.sh/basics/
  # Help the Python language server
  env.PYTHONPATH = ".venv/lib/python3.12/site-packages";

  # https://devenv.sh/languages/
  languages.python = {
    enable = true;
    poetry = {
      enable = true;
      install.enable = true;
      activate.enable = true;
    };
  };

  # See full reference at https://devenv.sh/reference/options/
}
