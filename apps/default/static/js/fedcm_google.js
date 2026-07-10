// apps/default/static/js/fedcm_google.js
//
// Google sign-in on /s/login — account picker → logged in, minimal screens.
//
// Preferred path (FedCM button mode):
//   User clicks "Sign in with Google" → browser account picker → id_token →
//   POST /s/social/google/fedcm-complete → redirect into Hydra → done.
//   No full-page Google OAuth screens when FedCM works.
//
// Fallback (classic OAuth, only if FedCM unavailable/fails):
//   JSON redirect to Google authorize with prompt=select_account so a signed-in
//   Google session is usually just account pick → redirect back.
//
// Auto-prompt (optional mediation) still runs on page load for returning users
// who already have a FedCM session (one-tap style).
//
// Hardened against:
//   - Opaque cross-origin Location headers (JSON redirect_url instead)
//   - Open-redirect (HTTPS + Google hosts / same-origin only)
//   - Double-submit / in-flight races
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

  async function attemptGoogleFedCM(opts, mediation, mode) {
    try {
      var provider = {
        configURL: GOOGLE_FEDCM_CONFIG,
        clientId: opts.clientId,
        params: {nonce: opts.nonce},
      };
      // Button mode is the Sign-in-with-Google account picker UX (no full
      // redirect pages). Passive browsers ignore unknown fields.
      if (mode) {
        provider.mode = mode;
      }
      var cred = await navigator.credentials.get({
        identity: {
          context: "signin",
          providers: [provider],
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
      if (!res.ok) {
        track("fedcm_google_server_status", { status: res.status });
        return null;
      }
      var body = await res.json();
      var redirect = body && body.redirect_url;
      if (isSafeRedirect(redirect)) return redirect;
      return null;
    } catch (_err) {
      return null;
    }
  }

  async function runFlow(opts, mediation, source, mode) {
    if (inFlight) return false;
    inFlight = true;
    try {
      track("fedcm_google_attempt", {
        mediation: mediation,
        source: source,
        mode: mode || "",
        login_event_id: opts.loginEventId,
      });

      var idToken = await attemptGoogleFedCM(opts, mediation, mode);
      if (!idToken) {
        track("fedcm_google_no_token", {
          mediation: mediation,
          source: source,
          mode: mode || "",
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

  // Classic OAuth via JSON {redirect_url} — used only when FedCM cannot
  // complete. Server builds the full authorize URL (response_type=code +
  // prompt=select_account).
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
    nativeFormPost(form);
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
          fedcm_supported: fedcmSupported(),
        });
        setGoogleButtonBusy(form, true);
        (async function () {
          try {
            // Button-mode FedCM = in-browser account picker, then done.
            // Only if that fails do we open classic Google OAuth pages.
            if (fedcmSupported()) {
              var navigated = await runFlow(
                opts,
                "required",
                "click",
                "button"
              );
              if (navigated) return;
              // Retry without mode for older browsers that reject mode:button.
              navigated = await runFlow(opts, "required", "click_retry", "");
              if (navigated) return;
            }
            track("fedcm_google_fallback_to_oauth");
            await oauthRedirectFallback(form);
          } finally {
            setGoogleButtonBusy(form, false);
          }
        })();
      });
    });
  }

  // Returning-user one-tap: silent/optional FedCM only — never auto-escalate
  // to multi-page OAuth (that would surprise the user with new screens).
  async function autoPrompt(opts) {
    if (inFlight) return;
    await runFlow(opts, "optional", "auto_prompt", "");
  }

  function install(opts) {
    if (!opts || !opts.clientId || !opts.loginEventId) return;
    if (!fedcmSupported()) {
      track("fedcm_unsupported", { provider: "google" });
      bindFallbackTracking();
      bindClick(opts);
      return;
    }
    bindClick(opts);
    autoPrompt(opts);
  }

  window.stawiGoogleFedCM = { install: install };
})();
