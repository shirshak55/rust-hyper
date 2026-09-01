//! Extensions for HTTP messages in Hyper.
//!
//! This module provides types and utilities that extend the capabilities of HTTP requests and responses
//! in Hyper. Extensions are additional pieces of information or features that can be attached to HTTP
//! messages via the [`http::Extensions`] map, which is
//! accessible through methods like [`http::Request::extensions`] and [`http::Response::extensions`].
//!
//! # What are extensions?
//!
//! Extensions allow Hyper to associate extra metadata or behaviors with HTTP messages, beyond the standard
//! headers and body. These can be used by advanced users and library authors to access protocol-specific
//! features, track original header casing, handle informational responses, and more.
//!
//! # How to access extensions
//!
//! Extensions are stored in the `Extensions` map of a request or response. You can access them using:
//!
//! ```rust
//! # let response = http::Response::new(());
//! if let Some(ext) = response.extensions().get::<hyper::ext::ReasonPhrase>() {
//!     // use the extension
//! }
//! ```
//!
//! # Extension Groups
//!
//! The extensions in this module can be grouped as follows:
//!
//! - **HTTP/1 Reason Phrase**: [`ReasonPhrase`] — Access non-canonical reason phrases in HTTP/1 responses.
//! - **Informational Responses**: [`on_informational`] — Register callbacks for 1xx HTTP/1 responses on the client.
//! - **Header Case Tracking**: Internal types for tracking the original casing and order of headers as received.
//! - **HTTP/2 Protocol Extensions**: [`Protocol`] — Access the `:protocol` pseudo-header for Extended CONNECT in HTTP/2.
//!
//! Some extensions are only available for specific protocols (HTTP/1 or HTTP/2) or use cases (client, server, FFI).
//!
//! See the documentation on each item for details about its usage and requirements.

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
use bytes::Bytes;
#[cfg(any(
    all(any(feature = "client", feature = "server"), feature = "http1"),
    feature = "ffi"
))]
use http::header::HeaderName;
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
use http::header::{HeaderMap, HeaderValue, IntoHeaderName, ValueIter};
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
use std::collections::HashMap;
#[cfg(feature = "http2")]
use std::fmt;

#[cfg(any(feature = "http1", feature = "ffi"))]
mod h1_reason_phrase;
#[cfg(any(feature = "http1", feature = "ffi"))]
pub use h1_reason_phrase::ReasonPhrase;

#[cfg(all(feature = "http1", feature = "client"))]
mod informational;
#[cfg(all(feature = "http1", feature = "client"))]
pub use informational::on_informational;
#[cfg(all(feature = "http1", feature = "client"))]
pub(crate) use informational::OnInformational;
#[cfg(all(feature = "http1", feature = "client", feature = "ffi"))]
pub(crate) use informational::{on_informational_raw, OnInformationalCallback};

#[cfg(feature = "http2")]
/// Extension type representing the `:protocol` pseudo-header in HTTP/2.
///
/// The `Protocol` extension allows access to the value of the `:protocol` pseudo-header
/// used by the [Extended CONNECT Protocol](https://datatracker.ietf.org/doc/html/rfc8441#section-4).
/// This extension is only sent on HTTP/2 CONNECT requests, most commonly with the value `websocket`.
///
/// # Example
///
/// ```rust
/// use hyper::ext::Protocol;
/// use http::{Request, Method, Version};
///
/// let mut req = Request::new(());
/// *req.method_mut() = Method::CONNECT;
/// *req.version_mut() = Version::HTTP_2;
/// req.extensions_mut().insert(Protocol::from_static("websocket"));
/// // Now the request will include the `:protocol` pseudo-header with value "websocket"
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    inner: h2::ext::Protocol,
}

#[cfg(feature = "http2")]
impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            inner: h2::ext::Protocol::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    #[cfg(feature = "server")]
    pub(crate) fn from_inner(inner: h2::ext::Protocol) -> Self {
        Self { inner }
    }

    #[cfg(all(feature = "client", feature = "http2"))]
    pub(crate) fn into_inner(self) -> h2::ext::Protocol {
        self.inner
    }
}

#[cfg(feature = "http2")]
impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            inner: h2::ext::Protocol::from(value),
        }
    }
}

#[cfg(feature = "http2")]
impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

#[cfg(feature = "http2")]
impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// A map from header names to their original casing as received in an HTTP message.
///
/// If an HTTP/1 response `res` is parsed on a connection whose option
/// [`preserve_header_case`] was set to true and the response included
/// the following headers:
///
/// ```ignore
/// x-Bread: Baguette
/// X-BREAD: Pain
/// x-bread: Ficelle
/// ```
///
/// Then `res.extensions().get::<HeaderCaseMap>()` will return a map with:
///
/// ```ignore
/// HeaderCaseMap({
///     "x-bread": ["x-Bread", "X-BREAD", "x-bread"],
/// })
/// ```
///
/// [`preserve_header_case`]: /client/struct.Client.html#method.preserve_header_case
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug)]
pub struct HeaderCaseMap(HeaderMap<Bytes>);

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl HeaderCaseMap {
    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    pub fn get_all<'a>(&'a self, name: &HeaderName) -> impl Iterator<Item = &'a Bytes> + 'a {
        self.get_all_internal(name)
    }

    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    #[cfg(any(feature = "client", feature = "server"))]
    pub(crate) fn get_all_internal(&self, name: &HeaderName) -> ValueIter<'_, Bytes> {
        self.0.get_all(name).into_iter()
    }

    /// An empty map, for messages whose original spelling is known to the caller
    /// (a proxy relaying a response received over another transport).
    pub fn new() -> Self {
        Self(HeaderMap::default())
    }

    #[cfg(any(feature = "client", feature = "server"))]
    pub(crate) fn default() -> Self {
        Self::new()
    }

    #[cfg(any(test, feature = "ffi"))]
    pub(crate) fn insert(&mut self, name: HeaderName, orig: Bytes) {
        self.0.insert(name, orig);
    }

    /// Records another spelling of `name`, in order of appearance.
    pub fn append<N>(&mut self, name: N, orig: Bytes)
    where
        N: IntoHeaderName,
    {
        self.0.append(name, orig);
    }
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl Default for HeaderCaseMap {
    fn default() -> Self {
        Self::new()
    }
}

/// The order in which headers were received, including repeated names.
///
/// Recorded alongside [`HeaderCaseMap`] when `preserve_header_case` is enabled
/// and stored as an extension on the parsed message; the encoders write headers
/// back in this order. Each entry is a header name plus the index of that value
/// among the values of the same name.
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug)]
pub struct OriginalHeaderOrder {
    /// Stores how many entries a Headername maps to. This is used
    /// for accounting.
    num_entries: HashMap<HeaderName, usize>,
    /// Stores the ordering of the headers. ex: `vec[i] = (headerName, idx)`,
    /// The vector is ordered such that the ith element
    /// represents the ith header that came in off the line.
    /// The `HeaderName` and `idx` are then used elsewhere to index into
    /// the multi map that stores the header values.
    entry_order: Vec<(HeaderName, usize)>,
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl OriginalHeaderOrder {
    /// An empty order, for messages whose original order is known to the caller.
    pub fn new() -> Self {
        OriginalHeaderOrder {
            num_entries: HashMap::new(),
            entry_order: Vec::new(),
        }
    }

    pub(crate) fn default() -> Self {
        Self::new()
    }

    #[cfg(feature = "ffi")]
    pub(crate) fn insert(&mut self, name: HeaderName) {
        if !self.num_entries.contains_key(&name) {
            let idx = 0;
            self.num_entries.insert(name.clone(), 1);
            self.entry_order.push((name, idx));
        }
        // Replacing an already existing element does not
        // change ordering, so we only care if its the first
        // header name encountered
    }

    /// Records the next header as `name`, in order of appearance.
    pub fn append<N>(&mut self, name: N)
    where
        N: IntoHeaderName + Into<HeaderName> + Clone,
    {
        let name: HeaderName = name.into();
        let idx = match self.num_entries.entry(name.clone()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let idx = *entry.get();
                *entry.get_mut() += 1;
                idx
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(1);
                0
            }
        };
        self.entry_order.push((name, idx));
    }

    /// Header names, each paired with its index among the values of that name,
    /// in the order they were originally received.
    ///
    /// # Examples
    /// ```
    /// use hyper::ext::OriginalHeaderOrder;
    /// use hyper::header::{HeaderMap, HeaderName, HeaderValue};
    ///
    /// let mut order = OriginalHeaderOrder::new();
    /// let mut map = HeaderMap::new();
    /// for (name, value) in [
    ///     ("set-cookie", "a=b"),
    ///     ("content-encoding", "gzip"),
    ///     ("set-cookie", "c=d"),
    /// ] {
    ///     let name = HeaderName::from_static(name);
    ///     map.append(name.clone(), HeaderValue::from_static(value));
    ///     order.append(name);
    /// }
    ///
    /// let wire: Vec<(&str, usize)> = order
    ///     .get_in_order()
    ///     .map(|(name, index)| (name.as_str(), *index))
    ///     .collect();
    /// assert_eq!(
    ///     wire,
    ///     [("set-cookie", 0), ("content-encoding", 0), ("set-cookie", 1)]
    /// );
    /// assert_eq!(map.get_all("set-cookie").iter().nth(1).unwrap(), "c=d");
    /// ```
    pub fn get_in_order(&self) -> impl Iterator<Item = &(HeaderName, usize)> {
        self.entry_order.iter()
    }

    /// `headers`' values in the recorded order: `(name, n, value)` where `value`
    /// is the `n`-th value of `name`. Values the recorded order doesn't cover
    /// (headers added after parsing) follow in map order; recorded entries whose
    /// header was removed are skipped.
    pub fn entries(&self, headers: &HeaderMap) -> Vec<(HeaderName, usize, HeaderValue)> {
        let mut slots: HashMap<&HeaderName, Vec<Option<&HeaderValue>>> = HashMap::new();
        for name in headers.keys() {
            slots.insert(name, headers.get_all(name).iter().map(Some).collect());
        }
        let mut out = Vec::with_capacity(headers.len());
        for (name, nth) in self.get_in_order() {
            if let Some(value) = slots.get_mut(name).and_then(|values| values.get_mut(*nth)) {
                if let Some(value) = value.take() {
                    out.push((name.clone(), *nth, value.clone()));
                }
            }
        }
        for name in headers.keys() {
            if let Some(values) = slots.get_mut(name) {
                for (nth, value) in values.iter_mut().enumerate() {
                    if let Some(value) = value.take() {
                        out.push((name.clone(), nth, value.clone()));
                    }
                }
            }
        }
        out
    }
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl Default for OriginalHeaderOrder {
    fn default() -> Self {
        Self::new()
    }
}

/// Sends interim (1xx) response heads to the client ahead of the service's final
/// response, on an HTTP/1 connection built with
/// [`informational_responses`](crate::server::conn::http1::Builder::informational_responses).
///
/// hyper inserts one into each request's extensions. Every [`send`](Self::send)
/// writes `HTTP/1.1 <status> <reason>` plus the given headers to the client as
/// soon as the connection can write. Sends after the final response head has
/// been written are dropped.
#[cfg(all(feature = "http1", feature = "server"))]
#[derive(Clone, Debug)]
pub struct InformationalSender {
    tx: tokio::sync::mpsc::UnboundedSender<http::Response<()>>,
}

#[cfg(all(feature = "http1", feature = "server"))]
impl InformationalSender {
    /// Queues an interim head. Returns the response back when its status is not
    /// 1xx, or when the connection no longer accepts interim heads.
    pub fn send(&self, res: http::Response<()>) -> Result<(), http::Response<()>> {
        if !res.status().is_informational() {
            return Err(res);
        }
        self.tx.send(res).map_err(|err| err.0)
    }
}

#[cfg(all(feature = "http1", feature = "server"))]
pub(crate) struct InformationalReceiver {
    rx: tokio::sync::mpsc::UnboundedReceiver<http::Response<()>>,
}

#[cfg(all(feature = "http1", feature = "server"))]
impl InformationalReceiver {
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<http::Response<()>>> {
        self.rx.poll_recv(cx)
    }
}

#[cfg(all(feature = "http1", feature = "server"))]
pub(crate) fn informational_channel() -> (InformationalSender, InformationalReceiver) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (InformationalSender { tx }, InformationalReceiver { rx })
}
