// apps/default/static/js/fedcm_google.js
//
// Google FedCM on /s/login — instant account chooser on page load.
//
// Two flows, tried in order:
//
//   1. Auto-prompt (immediate): fires FedCM with mediation:"optional"
//      the moment install() is called — no setTimeout, no waiting for
//      paint. If the user has a prior FedCM session, Chrome shows the
//      One Tap chip and login completes in ~200ms.
//
//   2. Explicit click (manual): prefers classic OAuth (JSON redirect from
//      /s/social/login) so Google always receives a complete authorize URL
//      including response_type=code. FedCM is still tried first on click;
//      on any failure we fall back to OAuth.
//
// Hardened against:
//   - Double-submit:    a single in-flight flag short-circuits repeat clicks
//                       and prevents auto-prompt from racing a manual click.
//   - Open-redirect:    the JSON response's redirect_url is only followed
//                       when it is a same-origin path or an HTTPS URL.
//   - Opaque redirects: fetch cannot read Location for cross-origin 303s;
//                       the server returns JSON {redirect_url} instead.
//   - Stale handlers:   install() is idempotent — re-running it on the same
//                       form is a no-op.
//   - Silent IdP swap:  Google's configURL is hard-coded; not template-driven.
(function () {
  "use strict";

  var GOOGLE_FEDCM_CONFIG = "https://accounts.google.com/gsi/fedcm.json";
  var COMPLETE_ENDPOINT = "/s/social/google/fedcm-complete";
  var inFlight = false;

  function track(event, props) {
    try {
      if (typeof window.stawiTrack === "function") {
        window.stawiTrack(event, props || {});
      }
    } catch (_e) {}
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

  function isSafeRedirect(raw) {
    if (typeof raw !== "string" || raw.length === 0) return false;
    if (raw[0] === "/" && (raw.length === 1 || raw[1] !== "/")) return true;
    try {
      var u = new URL(raw, window.location.href);
      if (u.origin === window.location.origin) return true;
      // Google authorize / accounts hosts only — never open arbitrary https.
      if (u.protocol !== "https:") return false;
      var host = u.hostname;
      return (
        host === "accounts.google.com" ||
        host === "oauth2.googleapis.com" ||
        host.endsWith(".google.com")
      );
    } catch (_e) {
      return false;
    }
  }

  async function attemptGoogleFedCM(opts, mediation) {
    try {
      var cred = await navigator.credentials.get({
        identity: {
          providers: [
            {
              configURL: GOOGLE_FEDCM_CONFIG,
              clientId: opts.clientId,
              params: {nonce: opts.nonce},
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

  async function sendCompletion(opts, idToken) {
    try {
      var res = await fetch(COMPLETE_ENDPOINT, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
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

  function bindFallbackTracking() {
    var forms = document.querySelectorAll("form[data-fedcm-google]");
    forms.forEach(function (form) {
      if (form.__stawiGoogleFallbackTracked) return;
      form.__stawiGoogleFallbackTracked = true;
      form.addEventListener("submit", function () {
        track("sign_in_method_clicked", {
          method: "google",
          fedcm_supported: false,
        });
      });
    });
  }

  // Ask /s/social/login for JSON {redirect_url} so we can navigate the top
  // window to Google's authorize URL. fetch+redirect:manual cannot read
  // Location when it is cross-origin (opaque redirect) — that was the bug
  // behind Google's "Required parameter is missing: response_type" page.
  async function oauthRedirectFallback(form) {
    var action = form.getAttribute("action") || "";
    if (!action) {
      nativeFormPost(form);
      return;
    }
    try {
      var res = await fetch(action, {
        method: "POST",
        credentials: "include",
        headers: {
          Accept: "application/json",
        },
      });
      if (res.ok) {
        var body = await res.json();
        var redirect = body && body.redirect_url;
        if (isSafeRedirect(redirect)) {
          // Hard-require response_type so we never send a broken Google URL.
          try {
            var u = new URL(redirect);
            if (!u.searchParams.get("response_type")) {
              track("fedcm_google_oauth_missing_response_type");
              nativeFormPost(form);
              return;
            }
          } catch (_e) {
            nativeFormPost(form);
            return;
          }
          track("fedcm_google_oauth_json_redirect");
          window.location.assign(redirect);
          return;
        }
        track("fedcm_google_oauth_unsafe_redirect");
      } else {
        track("fedcm_google_oauth_http_error", { status: res.status });
      }
    } catch (err) {
      track("fedcm_google_oauth_fetch_failed", {
        message: err && err.message ? String(err.message) : "unknown",
      });
    }
    // Last resort: top-level form POST; browser follows 303 to Google.
    nativeFormPost(form);
  }

  function nativeFormPost(form) {
    var action = form.getAttribute("action") || "";
    if (!action) {
      form.submit();
      return;
    }
    // Fresh form avoids disabled-submit-button races and stale listeners.
    var f = document.createElement("form");
    f.method = "POST";
    f.action = action;
    f.style.display = "none";
    document.body.appendChild(f);
    f.submit();
  }

  function setGoogleButtonBusy(form, busy) {
    var btn = form.querySelector("button");
    if (!btn) return;
    if (busy) {
      btn.disabled = true;
      btn.setAttribute("aria-busy", "true");
      btn.classList.add("btn-loading");
    } else {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.classList.remove("btn-loading");
    }
  }

  function bindClick(opts) {
    var forms = document.querySelectorAll("form[data-fedcm-google]");
    forms.forEach(function (form) {
      if (form.__stawiGoogleFedCMBound) return;
      form.__stawiGoogleFedCMBound = true;

      form.addEventListener("submit", function (event) {
        event.preventDefault();
        if (inFlight) {
          track("fedcm_google_click_while_inflight");
          return;
        }
        track("sign_in_method_clicked", {
          method: "google",
          fedcm_supported: true,
        });
        setGoogleButtonBusy(form, true);
        (async function () {
          try {
            // Prefer classic OAuth on explicit click — FedCM often fails when
            // the browser has no Google IdP session and previously left users
            // on a broken authorize URL. Still try FedCM first for one-tap.
            var navigated = await runFlow(opts, "required", "click");
            if (!navigated) {
              track("fedcm_google_fallback_to_oauth");
              await oauthRedirectFallback(form);
            }
          } finally {
            setGoogleButtonBusy(form, false);
          }
        })();
      });
    });
  }

  // autoPrompt fires FedCM immediately — no setTimeout, no waiting for
  // paint. If mediation:"optional" returns null (first visit / no
  // candidate), the explicit Google button remains available. We do not
  // synthesize a click: OAuth starts only after a real user action.
  async function autoPrompt(opts) {
    if (inFlight) return;
    await runFlow(opts, "optional", "auto_prompt");
  }

  function install(opts) {
    if (!opts || !opts.clientId || !opts.loginEventId) return;
    if (!fedcmSupported()) {
      track("fedcm_unsupported", { provider: "google" });
      bindFallbackTracking();
      // Even without FedCM, intercept submit so we use the JSON OAuth path.
      bindClick(opts);
      return;
    }
    bindClick(opts);
    autoPrompt(opts);
  }

  window.stawiGoogleFedCM = { install: install };
})();
