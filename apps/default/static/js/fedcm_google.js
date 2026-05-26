// apps/default/static/js/fedcm_google.js
//
// Google FedCM on /s/login — instant account chooser on page load.
//
// Three flows, tried in order:
//
//   1. Auto-prompt (immediate): fires FedCM with mediation:"optional"
//      the moment install() is called — no setTimeout, no waiting for
//      paint. If the user has a prior FedCM session, Chrome shows the
//      One Tap chip and login completes in ~200ms.
//
//   2. Auto-escalation: if the auto-prompt returns null (first visit),
//      we programmatically click the Google button. The click gives
//      Chrome the transient user activation it needs for
//      mediation:"required", which opens the full account chooser.
//      The user sees the chooser within ~300ms of page load.
//
//   3. Explicit click (manual): if the user dismisses the auto-chooser
//      and later clicks the Google button themselves, the same
//      mediation:"required" flow runs again with an OAuth fallback.
//
// Hardened against:
//   - Double-submit:    a single in-flight flag short-circuits repeat clicks
//                       AND prevents auto-escalation from racing a manual click.
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
            track("fedcm_google_fallback_to_oauth");
            form.submit();
          }
        })();
      });
    });
  }

  // autoPrompt fires FedCM immediately — no setTimeout, no waiting for
  // paint. If mediation:"optional" returns null (first visit / no
  // candidate), we escalate by programmatically clicking the Google
  // button to gain transient activation for mediation:"required".
  async function autoPrompt(opts) {
    if (inFlight) return;

    var navigated = await runFlow(opts, "optional", "auto_prompt");
    if (navigated) return;

    // Escalate: click the Google button to get transient activation,
    // which lets mediation:"required" show the full account chooser.
    var btn = document.querySelector("form[data-fedcm-google] button");
    if (btn && !inFlight) {
      track("fedcm_google_auto_escalate");
      btn.click();
    }
  }

  function install(opts) {
    if (!opts || !opts.clientId || !opts.loginEventId) return;
    if (!fedcmSupported()) {
      track("fedcm_unsupported", { provider: "google" });
      return;
    }
    bindClick(opts);
    autoPrompt(opts);
  }

  window.stawiGoogleFedCM = { install: install };
})();
