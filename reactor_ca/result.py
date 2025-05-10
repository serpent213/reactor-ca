"""Result type for handling operation results.

This module provides a Result type similar to Rust's Result, for handling
operations that may succeed or fail, without using exceptions.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeGuard, TypeVar

# T represents the success value type
T = TypeVar("T")
# E represents the error value type (typically Exception, str, or custom error types)
E = TypeVar("E")


@dataclass(frozen=True)
class Success(Generic[T]):
    """Represents a successful operation with a value."""

    value: T

    def map(self: "Success[T]", f: Callable[[T], Any]) -> "Success[Any]":
        """Apply function to the value and return new Success."""
        return Success(f(self.value))

    def and_then(self: "Success[T]", f: Callable[[T], "Result[Any, E]"]) -> "Result[Any, E]":
        """Chain operations that also return Result."""
        return f(self.value)

    def unwrap(self: "Success[T]") -> T:
        """Get the value."""
        return self.value

    def unwrap_or(self: "Success[T]", _default: T) -> T:
        """Get the value or default.

        Args:
        ----
            _default: Default value (not used in Success case)

        Returns:
        -------
            The wrapped value

        """
        return self.value

    def map_error(self: "Success[T]", _f: Callable[[Any], Any]) -> "Success[T]":
        """Map function over the error (no-op for Success).

        Args:
        ----
            _f: Function to apply to error (not used in Success case)

        Returns:
        -------
            The same Success instance

        """
        return self


@dataclass(frozen=True)
class Failure(Generic[E]):
    """Represents a failed operation with an error."""

    error: E

    def map(self: "Failure[E]", _f: Callable[[Any], Any]) -> "Failure[E]":
        """No-op for failures."""
        return self

    def and_then(self: "Failure[E]", _f: Callable[[Any], "Result[Any, E]"]) -> "Failure[E]":
        """No-op for failures."""
        return self

    def unwrap(self: "Failure[E]") -> None:
        """Raise exception."""
        raise ValueError(f"Cannot unwrap Failure: {self.error}")

    @staticmethod
    def unwrap_or(default: T) -> T:
        """Return the default value.

        Args:
        ----
            default: Default value to return

        Returns:
        -------
            The default value

        """
        return default

    def map_error(self: "Failure[E]", f: Callable[[E], E]) -> "Failure[E]":
        """Map function over the error.

        Args:
        ----
            f: Function to apply to the error

        Returns:
        -------
            New Failure with transformed error

        """
        return Failure(f(self.error))


Result = Success[T] | Failure[E]


# Type guard functions
def is_success(result: Result[T, E]) -> TypeGuard[Success[T]]:
    """Type guard to check if a Result is a Success.

    Args:
    ----
        result: The Result to check

    Returns:
    -------
        True if result is a Success, with proper type inference

    """
    return isinstance(result, Success)


def is_failure(result: Result[T, E]) -> TypeGuard[Failure[E]]:
    """Type guard to check if a Result is a Failure.

    Args:
    ----
        result: The Result to check

    Returns:
    -------
        True if result is a Failure, with proper type inference

    """
    return isinstance(result, Failure)
