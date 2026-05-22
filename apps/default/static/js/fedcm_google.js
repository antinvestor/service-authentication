// apps/default/static/js/fedcm_google.js
//
// Google FedCM on /s/login: two complementary flows on the same page.
//
//   1. Auto-chip (passive): on DOM-ready, attempts FedCM with
//      mediation:"optional" so the browser shows Chrome's One Tap-style
//      account chip without any user action — but only when Google can
//      produce a candidate without prompting. If the chip is dismissed or
//      no account is eligible the browser silently returns null and we
//      stay on the page.
//
//   2. Explicit click (active): the existing "Continue with Google" form
//      retains its click handler with mediation:"required" so users who
//      ignore the chip and click the button get an explicit account chooser.
//      Any failure transparently falls back to the legacy OAuth2 redirect
//      (form.submit()).
//
// Hardened against:
//   - Double-submit:    a single in-flight flag short-circuits repeat clicks
//                       AND prevents the auto-chip from racing the click.
//   - Open-redirect:    the JSON response's redirect_url is only followed
//                       when it is a same-origin path or an HTTPS URL.
//   - Stale handlers:   install() is idempotent — re-running it on the same
//                       form is a no-op.
//   - Silent IdP swap:  Google's configURL is hard-coded; not template-driven.
//
// Telemetry: every state transition emits a window.stawiTrack(...) event so
// PostHog dashboards see the funnel from chip-shown → chip-dismissed → form
// click → token verified → server-side login complete.
(function () {
  "use strict";

  // Google's well-known FedCM configURL. Hard-coded — the IdP is Google,
  // and parameterising this would let a compromised template repoint the
  // FedCM call at an attacker-controlled IdP.
  var GOOGLE_FEDCM_CONFIG = "https://accounts.google.com/gsi/fedcm.json";

  // Same-origin (relative) endpoint that consumes the id_token. Keep this
  // a path, not a full URL, so the request inherits the page's origin.
  var COMPLETE_ENDPOINT = "/s/social/google/fedcm-complete";

  // Module-level guard so the auto-chip and click handler can't both run
  // their network completion at the same time. Modifying this is the only
  // way one flow tells the other "back off".
  var inFlight = false;

  function track(event, props) {
    try {
      if (typeof window.stawiTrack === "function") {
        window.stawiTrack(event, props || {});
      }
    } catch (_e) {
      // Analytics must never break login.
    }
  }

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
  // mediation: "required" forces the account chooser; "optional" lets the
  // browser auto-select without UI when a returning user is eligible (One
  // Tap chip behaviour); "silent" never shows UI at all.
  async function attemptGoogleFedCM(opts, mediation) {
    try {
      var cred = await navigator.credentials.get({
        identity: {
          providers: [
            {
              configURL: GOOGLE_FEDCM_CONFIG,
              clientId: opts.clientId,
              nonce: opts.nonce,
            },
          ],
        },
        mediation: mediation || "required",
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

  // runFlow is the shared body for both the auto-chip and click handler:
  //   1. Ask FedCM for a Google id_token (mediation differs)
  //   2. If we got one, post it to /s/social/google/fedcm-complete
  //   3. If the server returns a safe redirect URL, navigate to it
  // Returns true if the navigation kicks off; false otherwise (caller may
  // fall back to a different path — e.g. submitting the OAuth form).
  async function runFlow(opts, mediation, source) {
    if (inFlight) return false;
    inFlight = true;
    try {
      track("fedcm_google_attempt", {
        mediation: mediation,
        source: source,
        login_event_id: opts.loginEventId,
      });

      var idToken = await attemptGoogleFedCM(opts, mediation);
      if (!idToken) {
        track("fedcm_google_no_token", {
          mediation: mediation,
          source: source,
        });
        return false;
      }

      track("fedcm_google_token_received", {
        mediation: mediation,
        source: source,
      });

      var redirect = await sendCompletion(opts, idToken);
      if (!redirect) {
        track("fedcm_google_server_rejected", { source: source });
        return false;
      }

      track("fedcm_google_redirect", { source: source });
      window.location.assign(redirect);
      return true;
    } finally {
      inFlight = false;
    }
  }

  // bindClick wires the explicit-click flow on every form tagged
  // data-fedcm-google. On click we attempt FedCM with mediation:"required";
  // on failure we let the form submit normally so the OAuth fallback runs.
  function bindClick(opts) {
    var forms = document.querySelectorAll("form[data-fedcm-google]");
    forms.forEach(function (form) {
      if (form.__stawiGoogleFedCMBound) return;
      form.__stawiGoogleFedCMBound = true;

      form.addEventListener("submit", function (event) {
        if (inFlight) {
          event.preventDefault();
          return;
        }
        event.preventDefault();
        track("sign_in_method_clicked", {
          method: "google",
          fedcm_supported: true,
        });
        (async function () {
          var navigated = await runFlow(opts, "required", "click");
          if (!navigated) {
            // OAuth fallback — preserves the user's progress when FedCM
            // is unavailable, the chooser was dismissed, or the server
            // refused the token.
            track("fedcm_google_fallback_to_oauth");
            form.submit();
          }
        })();
      });
    });
  }

  // autoChip kicks off a passive FedCM attempt at DOM-ready. mediation
  // "optional" tells the browser to show its auto-prompt UI (One Tap chip)
  // when it has a candidate but to silently no-op otherwise. We never call
  // this with "silent" — silent mediation would auto-sign-in users without
  // any UI confirmation, which is the wrong default for a sign-in page.
  function autoChip(opts) {
    if (!opts.autoChip) return;
    // Defer to the next tick so the page paints first; the chip appearing
    // mid-paint causes visible jank.
    setTimeout(function () {
      // Don't trigger the chip if a click is already in flight (user was
      // faster than the auto-chip).
      if (inFlight) return;
      void runFlow(opts, "optional", "auto_chip");
    }, 0);
  }

  function install(opts) {
    if (!opts || !opts.clientId || !opts.loginEventId) return;
    if (!fedcmSupported()) {
      // Still emit a telemetry signal so we know how many users land
      // without FedCM and rely on the OAuth fallback.
      track("fedcm_unsupported", { provider: "google" });
      return;
    }
    bindClick(opts);
    autoChip(opts);
  }

  window.stawiGoogleFedCM = { install: install };
})();
