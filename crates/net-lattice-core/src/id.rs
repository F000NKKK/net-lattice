use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

/// A phantom-typed identifier, generic over the domain object it names.
///
/// `net-lattice-model` defines per-domain aliases (`type RouteId = Id<Route>;`)
/// instead of hand-writing lookalike structs (`RouteId`, `InterfaceId`,
/// ...). Passing a `RouteId` where an `InterfaceId` is expected fails to
/// compile, rather than silently looking up the wrong object.
///
/// `Id<T>` serializes as its bare underlying value, independent of `T` —
/// see ARCHITECTURE.md's note on `Id<T>`'s serialization stability.
pub struct Id<T> {
    value: u64,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Id<T> {
    /// Wraps a raw identifier value as an `Id<T>`.
    pub const fn new(value: u64) -> Self {
        Self {
            value,
            _marker: PhantomData,
        }
    }

    /// Returns the raw underlying identifier value.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Id<T> {}

impl<T> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T> Eq for Id<T> {}

impl<T> Hash for Id<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl<T> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Id").field(&self.value).finish()
    }
}

impl<T> fmt::Display for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Route;
    struct Interface;

    #[test]
    fn same_value_is_equal_within_the_same_domain() {
        assert_eq!(Id::<Route>::new(1), Id::<Route>::new(1));
        assert_ne!(Id::<Route>::new(1), Id::<Route>::new(2));
    }

    #[test]
    fn different_domains_are_distinct_types() {
        // This is a compile-time property: `Id<Route>` and `Id<Interface>`
        // are different types, so a function expecting one cannot accept
        // the other. There is nothing to assert at runtime; this test
        // exists to keep both markers constructible and exercised.
        let route_id = Id::<Route>::new(1);
        let interface_id = Id::<Interface>::new(1);
        assert_eq!(route_id.value(), interface_id.value());
    }

    #[test]
    fn value_round_trips() {
        assert_eq!(Id::<Route>::new(42).value(), 42);
    }

    #[test]
    fn id_clone_hash_and_format_use_the_underlying_value() {
        use std::collections::hash_map::DefaultHasher;

        let id = Id::<Route>::new(42);
        assert_eq!(id, id.clone());
        assert_eq!(id.to_string(), "42");
        assert_eq!(format!("{id:?}"), "Id(42)");

        let mut first = DefaultHasher::new();
        id.hash(&mut first);
        let mut second = DefaultHasher::new();
        Id::<Route>::new(42).hash(&mut second);
        assert_eq!(first.finish(), second.finish());
    }
}
