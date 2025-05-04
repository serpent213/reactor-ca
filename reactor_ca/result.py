from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, Union

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

    def unwrap_or(self: "Success[T]", default: T) -> T:
        """Get the value or default."""
        return self.value

    def __bool__(self: "Success[T]") -> bool:
        """Allow using the result in a boolean context."""
        return True


@dataclass(frozen=True)
class Failure(Generic[E]):
    """Represents a failed operation with an error."""

    error: E

    def map(self: "Failure[E]", f: Callable[[Any], Any]) -> "Failure[E]":
        """No-op for failures."""
        return self

    def and_then(self: "Failure[E]", f: Callable[[Any], "Result[Any, E]"]) -> "Failure[E]":
        """No-op for failures."""
        return self

    def unwrap(self: "Failure[E]") -> Any:
        """Raise exception."""
        raise ValueError(f"Cannot unwrap Failure: {self.error}")

    def unwrap_or(self: "Failure[E]", default: Any) -> Any:
        """Return the default value."""
        return default

    def __bool__(self: "Failure[E]") -> bool:
        """Allow using the result in a boolean context."""
        return False


Result = Union[Success[T], Failure[E]]
