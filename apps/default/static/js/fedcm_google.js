// apps/default/static/js/fedcm_google.js
//
// Google sign-in on /s/login — classic OAuth only (v2.0.5).
//
// Why FedCM is disabled for Google:
//   Production screencast (2026-07-10) showed Google's FedCM account picker
//   ("Sign in to stawi.org with google.com") → "Verifying…" → popup to
//   accounts.google.com/signin/oauth/error with
//   "Required parameter is missing: response_type" (Error 400: invalid_request).
//   That popup is Google's FedCM→OAuth escalation, not our authorize URL.
//   Server-built OAuth (response_type=code + prompt=select_account) is reliable.
//
// Click path:
//   POST /s/social/login/{id}?provider=google  Accept: application/json
//   → { redirect_url: "https://accounts.google.com/o/oauth2/v2/auth?...&response_type=code&..." }
//   → window.location.assign(redirect_url)  (full-page navigation)
//
// No auto-prompt. No navigator.credentials.get() for Google.
// Server contract: ProviderLoginEndpointV2 returns JSON when Accept includes
// application/json (avoids opaque cross-origin Location on 303→Google).
(function () {
  "use strict";

  var clickInFlight = false;

  function track(event, props) {
    try {
      if (typeof window.stawiTrack === "function") {
        window.stawiTrack(event, props || {});
      }
    } catch (_e) {}
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
      track("google_oauth_bad_redirect", {
        has_url: !!redirect,
        complete: redirect ? isCompleteGoogleAuthorizeURL(redirect) : false,
      });
      throw new Error("incomplete_google_authorize_url");
    }
    track("google_oauth_json_redirect");
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
          path: "oauth_only",
        });
        setGoogleButtonBusy(form, true);
        (async function () {
          try {
            await startGoogleOAuth(form);
          } catch (err) {
            track("google_oauth_failed", {
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

  function install(_opts) {
    // OAuth-only: bind the Google button. No FedCM auto-prompt.
    bindClick();
  }

  window.stawiGoogleFedCM = { install: install };
})();
