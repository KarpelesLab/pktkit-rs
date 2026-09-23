//! Crate-internal macros.

/// Chainable setters for a `#[non_exhaustive]` config struct.
///
/// Config structs are `#[non_exhaustive]` so a new field is not a breaking
/// change, which also means other crates cannot build them with a struct
/// literal. These setters are how they do it instead:
///
/// ```text
/// let cfg = Config::new("eth0").rx_spin(1000).huge_pages(true);
/// ```
///
/// Each entry names how the setter takes its value:
/// - `set field: T` takes a `T`;
/// - `into field: T` takes `impl Into<T>` (for `String` fields);
/// - `some field: T` takes a `T` and stores `Some(value)` in an `Option<T>`
///   field that defaults to `None`.
// Unused in a build with none of the features that have a config struct.
#[allow(unused_macros)]
macro_rules! setters {
    ($ty:ty { $($kind:ident $field:ident: $t:ty;)* }) => {
        impl $ty {
            $( setters!(@$kind $field: $t); )*
        }
    };
    (@set $field:ident: $t:ty) => {
        #[doc = concat!("Set `", stringify!($field), "`.")]
        #[must_use]
        #[inline]
        pub fn $field(mut self, value: $t) -> Self {
            self.$field = value;
            self
        }
    };
    (@into $field:ident: $t:ty) => {
        #[doc = concat!("Set `", stringify!($field), "`.")]
        #[must_use]
        #[inline]
        pub fn $field(mut self, value: impl Into<$t>) -> Self {
            self.$field = value.into();
            self
        }
    };
    (@some $field:ident: $t:ty) => {
        #[doc = concat!("Set `", stringify!($field), "` to `Some(value)`.")]
        #[must_use]
        #[inline]
        pub fn $field(mut self, value: $t) -> Self {
            self.$field = Some(value);
            self
        }
    };
}
