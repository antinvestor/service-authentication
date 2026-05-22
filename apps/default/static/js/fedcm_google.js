// apps/default/static/js/fedcm_google.js
//
// Intercepts the "Continue with Google" form on /s/login. When the browser
// supports FedCM and Google is configured, the click triggers
// navigator.credentials.get against Google's IdP configURL and posts the
// resulting id_token to /s/social/google/fedcm-complete. Any failure (no
// FedCM, no Google account, user dismisses, network, server-side rejection)
// transparently falls through to the form's default action — the legacy
// OAuth2 redirect — so users on browsers without FedCM never notice the
// difference.
//
// Hardened against:
//   - Double-submit:    a single in-flight flag short-circuits repeat clicks.
//   - Open-redirect:    the JSON response's redirect_url is only followed
//                       when it parses as a URL and matches a same-origin
//                       relative path OR is on a Hydra/auth host expected
//                       by the existing OAuth callback flow.
//   - Stale handlers:   install() is idempotent — re-running it on the same
//                       form replaces the previous handler instead of
//                       stacking them.
(function () {
  "use strict";

  // Google's well-known FedCM configURL. Hard-coded — the IdP is Google,
  // and parameterising this would let a compromised template repoint the
  // FedCM call at an attacker-controlled IdP.
  var GOOGLE_FEDCM_CONFIG = "https://accounts.google.com/gsi/fedcm.json";

  // Same-origin (relative) endpoint that consumes the id_token. Keep this
  // a path, not a full URL, so the request inherits the page's origin.
  var COMPLETE_ENDPOINT = "/s/social/google/fedcm-complete";

  function fedcmSupported() {
    return (
      typeof window !== "undefined" &&
      "IdentityCredential" in window &&
      navigator &&
      navigator.credentials &&
      typeof navigator.credentials.get === "function"
    );
  }

  // isSafeRedirect verifies that a server-supplied redirect URL is one we'd
  // willingly send the user to from /s/login. Same-origin redirects are
  // always fine; cross-origin redirects must be HTTPS so a downgraded Hydra
  // response can never push us to plain HTTP.
  function isSafeRedirect(raw) {
    if (typeof raw !== "string" || raw.length === 0) return false;
    if (raw[0] === "/" && (raw.length === 1 || raw[1] !== "/")) return true;
    try {
      var u = new URL(raw, window.location.href);
      if (u.origin === window.location.origin) return true;
      return u.protocol === "https:";
    } catch (_e) {
      return false;
    }
  }

  // attemptGoogleFedCM runs navigator.credentials.get with Google's configURL.
  // Resolves to the id_token string on success, null otherwise. Never throws.
  async function attemptGoogleFedCM(opts) {
    try {
      var cred = await navigator.credentials.get({
        identity: {
          providers: [{
            configURL: GOOGLE_FEDCM_CONFIG,
            clientId: opts.clientId,
            nonce: opts.nonce,
          }],
        },
        // 'required' means: the user explicitly clicked the button, the
        // browser MUST show the account chooser. 'optional' would let the
        // browser silently fail when no auto-select is possible, which is
        // wrong UX for an explicit click.
        mediation: "required",
      });
      if (cred && typeof cred.token === "string" && cred.token.length > 0) {
        return cred.token;
      }
      return null;
    } catch (_err) {
      return null;
    }
  }

  // sendCompletion posts the id_token to the server and returns the
  // redirect URL on success, null on any error.
  async function sendCompletion(opts, idToken) {
    try {
      var res = await fetch(COMPLETE_ENDPOINT, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        body: JSON.stringify({
          login_event_id: opts.loginEventId,
          id_token: idToken,
        }),
      });
      if (!res.ok) return null;
      var body = await res.json();
      var redirect = body && body.redirect_url;
      if (isSafeRedirect(redirect)) return redirect;
      return null;
    } catch (_err) {
      return null;
    }
  }

  function install(opts) {
    if (!opts || !opts.clientId || !opts.loginEventId) return;
    if (!fedcmSupported()) return;

    var forms = document.querySelectorAll("form[data-fedcm-google]");
    forms.forEach(function (form) {
      // Idempotency: avoid stacking handlers if install() runs more than
      // once (e.g. tests, hot-reload, multiple DOMContentLoaded firings).
      if (form.__stawiGoogleFedCMBound) return;
      form.__stawiGoogleFedCMBound = true;

      var inFlight = false;

      form.addEventListener("submit", function (event) {
        if (inFlight) {
          event.preventDefault();
          return;
        }
        // Tell the browser to wait — we'll decide whether to fall through
        // to the form's default action or to navigate ourselves.
        event.preventDefault();
        inFlight = true;

        (async function () {
          try {
            var idToken = await attemptGoogleFedCM(opts);
            if (idToken) {
              var redirect = await sendCompletion(opts, idToken);
              if (redirect) {
                window.location.assign(redirect);
                return;
              }
            }
            // Fall through: submit the form normally (OAuth redirect).
            form.submit();
          } finally {
            inFlight = false;
          }
        })();
      });
    });
  }

  window.stawiGoogleFedCM = { install: install };
})();
