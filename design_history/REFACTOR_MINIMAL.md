# ReactorCA Ultra-Minimal Bootstrap Refactoring

This document outlines an extremely lean approach to bootstrap refactoring that addresses the current issues while making minimal changes to existing code.

## Core Approach

### 1. Add `load_config` to config.py 

The config.py file already has methods for loading specific configurations. We'll add a simple function to load all configurations at once:

```python
# Add to config.py
def load_config(config_dir: str | None = None, 
                store_dir: str | None = None,
                root_dir: str | None = None) -> Result[models.Config, str]:
    """Load all configurations and create a Config object.
    
    Args:
    ----
        config_dir: Optional path to configuration directory
        store_dir: Optional path to store directory 
        root_dir: Optional path to root directory
        
    Returns:
    -------
        Result with Config object containing paths and loaded configurations
    """
    # Resolve paths
    config_path_obj, store_path_obj = resolve_paths(config_dir, store_dir, root_dir)
    
    # Load CA config
    ca_config_result = load_ca_config(config_path_obj)
    if not ca_config_result:  # Using boolean conversion
        return ca_config_result
        
    # Load hosts config
    hosts_config_result = load_hosts_config(config_path_obj)
    if not hosts_config_result:  # Using boolean conversion
        return hosts_config_result
        
    # Create and return Config object
    return Success(
        models.Config(
            config_path=str(config_path_obj),
            store_path=str(store_path_obj),
            ca_config=ca_config_result.value,
            hosts_config=hosts_config_result.value
        )
    )
```

This respects the separation of concerns by keeping the config loading logic in config.py, while still enhancing the Config dataclass in models.py.

### 2. Continue Using `unlock` in store.py

The `unlock` function we added to store.py is perfect for our needs:

```python
# Already added to store.py
def unlock(store: Store, password: str) -> Result[Store, str]:
    """Unlock a store with the provided password."""
    # If store is already unlocked, just return it
    if store.unlocked and store.password:
        return Success(store)
    
    # If CA exists, validate password by trying to load the CA key
    if ca_exists(store.path):
        key_result = read_ca_key(store.path, password)
        if not key_result:  # Using boolean conversion
            return Failure(f"Invalid password: {key_result.error}")
    
    # Update store with password and mark as unlocked
    # Since Store isn't frozen, we can modify it directly
    store.password = password
    store.unlocked = True
    return Success(store)
```

### 3. Simple Resource Loading in Commands

Commands will load resources once at the beginning:

```python
@ca.command(name="info")
@click.pass_context
def ca_info(ctx: click.Context) -> None:
    """Show information about the Certificate Authority."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]
    
    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=False
        )
        if not password_result:  # Using boolean conversion
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)
            
        # Unlock the store
        unlock_result = unlock(store, password_result.value)
        if not unlock_result:  # Using boolean conversion
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)
    
    # Load the certificate once
    cert_result = read_ca_cert(store.path)
    if not cert_result:  # Using boolean conversion
        console.print(f"[bold red]Error:[/bold red] {cert_result.error}")
        ctx.exit(1)
    
    cert_data = cert_result.value
    
    # Load the key once
    key_result = read_ca_key(store.path, store.password)
    if not key_result:  # Using boolean conversion
        console.print(f"[bold red]Error:[/bold red] {key_result.error}")
        ctx.exit(1)
    
    key_data = key_result.value
    
    # Now use cert_data and key_data without reloading
    # ...
```

## CLI Integration

The CLI bootstrap uses our `load_config` function:

```python
@click.group()
@click.version_option(version=__version__)
@click.option("--config", type=click.Path(exists=False), help="Path to configuration directory")
@click.option("--store", type=click.Path(exists=False), help="Path to certificate store directory")
@click.option("--root", type=click.Path(exists=False), help="Root directory (config and store subdirectories)")
@click.option("--password", help="CA password (WARNING: visible in command history)", envvar="REACTOR_CA_PASSWORD")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str] = None, 
        store: Optional[str] = None, root: Optional[str] = None,
        password: Optional[str] = None) -> None:
    """ReactorCA - A CLI tool to manage a homelab Certificate Authority."""
    # Load config using the function from config.py
    config_result = load_config(config, store, root)
    
    if not config_result:  # Using boolean conversion
        console.print(f"[bold red]Error:[/bold red] {config_result.error}")
        ctx.exit(1)
    
    # Create store (using the existing Store model)
    store_obj = Store(
        path=config_result.value.store_path,
        password=None,
        unlocked=False
    )
    
    # If password was provided, try to unlock the store
    if password:
        unlock_result = unlock(store_obj, password)
        # We don't need to handle errors here - if unlock fails, the store
        # will remain locked and commands will prompt for password as needed
    
    # Store the objects for subcommands
    ctx.obj = {
        "config": config_result.value,
        "store": store_obj
    }
```

## Command Implementation 

Commands stay focused on their specific tasks:

```python
@ca.command(name="issue")
@click.pass_context
def ca_issue(ctx: click.Context) -> None:
    """Create or renew a CA certificate."""
    config = ctx.obj["config"]
    store = ctx.obj["store"]
    
    # Ensure store is unlocked
    if not store.unlocked:
        # Get password
        password_result = get_password(
            min_length=config.ca_config.password.min_length,
            password_file=config.ca_config.password.file,
            env_var=config.ca_config.password.env_var,
            prompt_message="Enter CA master password: ",
            confirm=ca_exists(store.path)  # Only confirm if creating new CA
        )
        if not password_result:  # Using boolean conversion
            console.print(f"[bold red]Error:[/bold red] {password_result.error}")
            ctx.exit(1)
            
        # Unlock the store
        unlock_result = unlock(store, password_result.value)
        if not unlock_result:  # Using boolean conversion
            console.print(f"[bold red]Error:[/bold red] {unlock_result.error}")
            ctx.exit(1)
    
    # Issue CA certificate
    # Use the store.password that's already set
    result = issue_ca(config, store)
    
    # Handle result...
    if not result:  # Using boolean conversion
        console.print(f"[bold red]Error:[/bold red] {result.error}")
        ctx.exit(1)
```

## Proper Separation of Concerns

This approach maintains proper separation of concerns:

1. **models.py**: Defines `Config` dataclass (with added fields for loaded configs)
2. **config.py**: Handles all config loading/validation (through `load_config`)
3. **store.py**: Manages storage operations and unlocking
4. **paths.py**: Handles path resolution and construction
5. **CLI**: Uses these components without adding its own logic

## Benefits of This Approach

1. **Respects Existing Design**: Each module maintains its proper responsibility
2. **Minimal Changes**: Only adds one function to config.py and enhances `Config` model
3. **Clean Error Handling**: Uses Boolean conversion for Result types (`if not result:`)
4. **Early Config Loading**: Loads configurations once at startup, not repeatedly
5. **Password Persistence**: The `Store` object keeps the password after unlocking
6. **Simple Resource Handling**: Just load resources once per command when needed
7. **Reuses Path Functions**: Directly uses paths.py functions where needed

## KISS Principle in Action

This ultra-minimal approach follows the KISS (Keep It Simple, Stupid) principle perfectly:

1. The CLI tool runs each command as a standalone operation
2. Each command gets a pre-loaded config with all settings
3. The store tracks the password after being unlocked once
4. Resources are loaded once per command as needed
5. Each module maintains its clear responsibility
6. No complex abstractions or unnecessary structures

Given ReactorCA's nature as a straightforward CLI tool performing simple operations on each run, this lean approach provides all the benefits of more complex solutions without their overhead.