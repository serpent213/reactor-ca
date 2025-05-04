"""Password handling for ReactorCA."""

import os
from getpass import getpass
from pathlib import Path

from reactor_ca.models import CAConfig, Store
from reactor_ca.result import Failure, Result, Success


def get_password(
    store: Store,
    min_length: int,
    password_file: str | None = None,
    env_var: str | None = None,
    prompt_message: str = "Enter CA password: ",
    confirm: bool = False,
) -> Result[str, str]:
    """Get a password from multiple sources.

    The resolution order is:
    1. Use stored password if already unlocked
    2. Try password from file if specified
    3. Try password from environment variable if specified
    4. Prompt the user

    Args:
    ----
        store: Store object that might have a cached password
        min_length: Minimum allowed password length
        password_file: Optional path to a file containing the password
        env_var: Optional environment variable name containing the password
        prompt_message: Message to display when prompting for password
        confirm: Whether to ask for confirmation when prompting

    Returns:
    -------
        Result with the password string or error message

    """
    # If store is already unlocked, use the stored password
    if store.unlocked and store.password:
        return Success(store.password)

    # Try to get password from file if specified
    if password_file:
        file_result = read_password_from_file(Path(password_file))
        if file_result:
            password = file_result.unwrap()
            if len(password) >= min_length:
                return Success(password)
            return Failure(f"Password in file is too short (min {min_length} characters)")

    # Try to get password from environment variable if specified
    if env_var and env_var in os.environ:
        password = os.environ[env_var]
        if len(password) >= min_length:
            return Success(password)
        return Failure(f"Password in environment variable is too short (min {min_length} characters)")

    # If still no password, prompt the user
    try:
        password = getpass(prompt_message)

        if confirm:
            confirm_password = getpass("Confirm password: ")
            if password != confirm_password:
                return Failure("Passwords do not match")

        if len(password) < min_length:
            return Failure(f"Password must be at least {min_length} characters long")

        return Success(password)
    except Exception as e:
        return Failure(f"Failed to get password: {str(e)}")


def read_password_from_file(password_file: Path) -> Result[str, str]:
    """Read password from a file.

    Args:
    ----
        password_file: Path to the file containing the password

    Returns:
    -------
        Result with the password string or error message

    """
    try:
        if not password_file.exists():
            return Failure(f"Password file does not exist: {password_file}")

        with open(password_file, encoding="locale") as f:
            password = f.read().strip()
            return Success(password)
    except Exception as e:
        return Failure(f"Error reading password file: {str(e)}")


def verify_password(
    password: str, ca_config: CAConfig | None = None, min_length: int | None = None
) -> Result[str, str]:
    """Verify that a password meets the requirements.

    Args:
    ----
        password: Password string to verify
        ca_config: Optional CA config containing password requirements
        min_length: Explicit minimum length (overrides ca_config)

    Returns:
    -------
        Result with the validated password or error message

    """
    # Determine minimum length
    if min_length is None and ca_config is not None:
        min_length = ca_config.password.min_length
    elif min_length is None:
        min_length = 8  # Reasonable default

    # Verify length
    if len(password) < min_length:
        return Failure(f"Password must be at least {min_length} characters long")

    return Success(password)
