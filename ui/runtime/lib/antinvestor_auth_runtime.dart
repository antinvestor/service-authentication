/// Auth runtime for Antinvestor Flutter apps.
///
/// Implements the Stawi auth protocol (OAuth2 + PKCE, adaptive DPoP,
/// rotating refresh tokens with reuse detection) with Isolate-isolated
/// tokens, hardware-backed storage, Riverpod providers and Material
/// widgets.
///
/// Public surface is assembled in later task groups; this file is the
/// package barrel.
library;
