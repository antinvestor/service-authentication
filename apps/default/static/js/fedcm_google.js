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
//   2. Explicit click (manual): if the user dismisses the auto-chooser
//      and later clicks the Google button themselves, the same
//      mediation:"required" flow runs again with an OAuth fallback.
//
// Hardened against:
//   - Double-submit:    a single in-flight flag short-circuits repeat clicks
//                       and prevents auto-prompt from racing a manual click.
//   - Open-redirect:    the JSON response's redirect_url is only followed
//                       when it is a same-origin path or an HTTPS URL.
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
      return u.protocol === "https:";
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

  // After an await, HTMLFormElement.submit() is unreliable: user-activation
  // may be gone, and sibling handlers (auth.js) may have disabled the submit
  // button. Fetch the OAuth start endpoint ourselves and follow Location so
  // the browser always lands on Google's authorize URL with response_type=code.
  async function oauthRedirectFallback(form) {
    var action = form.getAttribute("action") || "";
    if (!action) {
      form.submit();
      return;
    }
    try {
      var res = await fetch(action, {
        method: "POST",
        credentials: "include",
        redirect: "manual",
        headers: {
          Accept: "text/html,application/xhtml+xml",
        },
      });
      // Same-origin 303: expose Location. Cross-origin would be opaqueredirect.
      var loc =
        res.headers.get("Location") ||
        res.headers.get("location") ||
        "";
      if (
        (res.status === 303 ||
          res.status === 302 ||
          res.status === 301 ||
          res.status === 307 ||
          res.status === 308) &&
        isSafeRedirect(loc)
      ) {
        track("fedcm_google_oauth_redirect", { status: res.status });
        window.location.assign(loc);
        return;
      }
      // 0 + opaqueredirect can happen if a proxy rewrites the Location host.
      if (res.type === "opaqueredirect") {
        track("fedcm_google_oauth_opaque_redirect");
      } else {
        track("fedcm_google_oauth_unexpected_status", {
          status: res.status,
          type: res.type,
        });
      }
    } catch (err) {
      track("fedcm_google_oauth_fetch_failed", {
        message: err && err.message ? String(err.message) : "unknown",
      });
    }
    // Last resort: native submit (works when the click stack is still sync).
    form.submit();
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
          // Auto-prompt already running; do not leave the button stuck.
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
            var navigated = await runFlow(opts, "required", "click");
            if (!navigated) {
              track("fedcm_google_fallback_to_oauth");
              await oauthRedirectFallback(form);
            }
          } finally {
            // If we navigated away this is a no-op; if fallback failed,
            // re-enable so the user can retry.
            setGoogleButtonBusy(form, false);
          }
        })();
      });
    });
  }

  // autoPrompt fires FedCM immediately — no setTimeout, no waiting for
  // paint. If mediation:"optional" returns null (first visit / no
  // candidate), the explicit Google button remains available. We do not
  // synthesize a click: required mediation and the OAuth fallback both
  // need to stay attached to a real user action.
  async function autoPrompt(opts) {
    if (inFlight) return;
    await runFlow(opts, "optional", "auto_prompt");
  }

  function install(opts) {
    if (!opts || !opts.clientId || !opts.loginEventId) return;
    if (!fedcmSupported()) {
      track("fedcm_unsupported", { provider: "google" });
      bindFallbackTracking();
      return;
    }
    bindClick(opts);
    autoPrompt(opts);
  }

  window.stawiGoogleFedCM = { install: install };
})();
