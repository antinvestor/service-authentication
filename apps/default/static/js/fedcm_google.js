// apps/default/static/js/fedcm_google.js
//
// Google sign-in on /s/login.
//
// DESIGN (v2.0.4) — explicit click is OAuth-primary:
//
//   Why not FedCM on click?
//   Browser repro on production showed navigator.credentials.get() either
//   hanging or erroring ("Not signed in with the identity provider") and
//   never reaching /s/social/login. Users then saw broken Google error pages
//   (e.g. missing response_type) or infinite spinner. Classic OAuth with a
//   server-built authorize URL is the reliable path.
//
//   Click path:
//     POST /s/social/login/{id}?provider=google  Accept: application/json
//     → { redirect_url: "https://accounts.google.com/o/oauth2/v2/auth?...&response_type=code&prompt=select_account&..." }
//     → window.location.assign(redirect_url)
//
//   Auto-prompt path (optional, non-blocking):
//     FedCM mediation:optional for returning users only. Never blocks the
//     Google button. Never auto-escalates to multi-page OAuth.
//
// Server contract: ProviderLoginEndpointV2 returns JSON when Accept includes
// application/json (avoids opaque cross-origin Location on 303→Google).
(function () {
  "use strict";

  var GOOGLE_FEDCM_CONFIG = "https://accounts.google.com/gsi/fedcm.json";
  var COMPLETE_ENDPOINT = "/s/social/google/fedcm-complete";
  // Separate flags so auto-prompt cannot block explicit OAuth click.
  var autoPromptInFlight = false;
  var clickInFlight = false;

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
      if (u.protocol !== "https:") return false;
      var host = u.hostname;
      return (
        host === "accounts.google.com" ||
        host === "oauth2.googleapis.com" ||
        host.endsWith(".google.com") ||
        host.endsWith(".stawi.org") ||
        host.endsWith(".antinvestor.com")
      );
    } catch (_e) {
      return false;
    }
  }

  function isCompleteGoogleAuthorizeURL(raw) {
    try {
      var u = new URL(raw);
      if (u.protocol !== "https:" || u.hostname !== "accounts.google.com") {
        return false;
      }
      // Required OAuth params — incomplete URLs produce Google's
      // "Required parameter is missing: response_type" error page.
      return (
        u.searchParams.get("response_type") === "code" &&
        !!u.searchParams.get("client_id") &&
        !!u.searchParams.get("redirect_uri") &&
        !!u.searchParams.get("scope")
      );
    } catch (_e) {
      return false;
    }
  }

  async function attemptGoogleFedCM(opts, mediation) {
    try {
      var cred = await navigator.credentials.get({
        identity: {
          context: "signin",
          providers: [
            {
              configURL: GOOGLE_FEDCM_CONFIG,
              clientId: opts.clientId,
              params: {nonce: opts.nonce},
            },
          ],
        },
        mediation: mediation || "optional",
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

  // Silent/returning-user path only. Must never block the Google button.
  async function autoPrompt(opts) {
    if (!fedcmSupported() || autoPromptInFlight || clickInFlight) return;
    autoPromptInFlight = true;
    try {
      track("fedcm_google_attempt", {
        mediation: "optional",
        source: "auto_prompt",
        login_event_id: opts.loginEventId,
      });
      var idToken = await attemptGoogleFedCM(opts, "optional");
      if (!idToken) {
        track("fedcm_google_no_token", { source: "auto_prompt" });
        return;
      }
      var redirect = await sendCompletion(opts, idToken);
      if (!redirect) {
        track("fedcm_google_server_rejected", { source: "auto_prompt" });
        return;
      }
      track("fedcm_google_redirect", { source: "auto_prompt" });
      window.location.assign(redirect);
    } finally {
      autoPromptInFlight = false;
    }
  }

  // Reliable OAuth start: JSON body with full authorize URL (includes
  // response_type=code). Never rely on reading 303 Location to Google
  // (opaque redirect — Location is not exposed to JS).
  async function startGoogleOAuth(form) {
    var action = form.getAttribute("action") || "";
    if (!action) {
      throw new Error("missing form action");
    }
    var res = await fetch(action, {
      method: "POST",
      credentials: "include",
      headers: {
        Accept: "application/json",
      },
    });
    if (!res.ok) {
      var text = "";
      try {
        text = await res.text();
      } catch (_e) {}
      throw new Error("oauth_start_http_" + res.status + ":" + text.slice(0, 80));
    }
    var body = await res.json();
    var redirect = body && body.redirect_url;
    if (!isSafeRedirect(redirect) || !isCompleteGoogleAuthorizeURL(redirect)) {
      track("fedcm_google_oauth_bad_redirect", {
        has_url: !!redirect,
        complete: redirect ? isCompleteGoogleAuthorizeURL(redirect) : false,
      });
      throw new Error("incomplete_google_authorize_url");
    }
    track("fedcm_google_oauth_json_redirect");
    window.location.assign(redirect);
  }

  function nativeFormPost(form) {
    var action = form.getAttribute("action") || "";
    if (!action) {
      form.submit();
      return;
    }
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

  function bindClick() {
    var forms = document.querySelectorAll("form[data-fedcm-google]");
    forms.forEach(function (form) {
      if (form.__stawiGoogleOAuthBound) return;
      form.__stawiGoogleOAuthBound = true;

      form.addEventListener("submit", function (event) {
        event.preventDefault();
        if (clickInFlight) return;
        clickInFlight = true;
        track("sign_in_method_clicked", {
          method: "google",
          path: "oauth_primary",
          fedcm_supported: fedcmSupported(),
        });
        setGoogleButtonBusy(form, true);
        (async function () {
          try {
            await startGoogleOAuth(form);
          } catch (err) {
            track("fedcm_google_oauth_failed", {
              message: err && err.message ? String(err.message) : "unknown",
            });
            // Last resort: top-level form POST (browser follows 303).
            nativeFormPost(form);
          } finally {
            // If navigation succeeded this is a no-op; if not, re-enable.
            clickInFlight = false;
            setGoogleButtonBusy(form, false);
          }
        })();
      });
    });
  }

  function install(opts) {
    if (!opts || !opts.clientId || !opts.loginEventId) return;
    // Always bind OAuth-primary click — works with or without FedCM support.
    bindClick();
    // Optional silent FedCM for returning users; never blocks the button.
    if (fedcmSupported()) {
      autoPrompt(opts);
    } else {
      track("fedcm_unsupported", { provider: "google" });
    }
  }

  window.stawiGoogleFedCM = { install: install };
})();
