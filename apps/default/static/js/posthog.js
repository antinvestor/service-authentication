// apps/default/static/js/posthog.js
//
// Lightweight PostHog client-side bootstrap for the login page. Loaded as a
// deferred script from login.html; reads its config from a window-scoped
// object populated by the template.
//
// Design notes:
//   - We don't bundle posthog-js itself — we use their official CDN snippet
//     so dashboards stay aligned with the latest SDK without us shipping
//     megabytes of JS. The script load is async + non-blocking.
//   - When window.stawiAnalytics.apiKey is empty (env disabled analytics),
//     this whole module noops. Other JS files call window.stawiTrack(...)
//     unconditionally and we silently absorb the call.
//   - The distinct ID is left to PostHog defaults (a stable browser-stored
//     UUID). On successful login the server emits an Alias call so pre-
//     login events show up on the same person timeline.
//   - We capture page-view automatically, plus exported helpers for the
//     button-click and FedCM lifecycle events.
(function () {
  "use strict";

  var cfg = window.stawiAnalytics || {};
  var noop = function () {};

  // Always expose stawiTrack as a callable, even if PostHog ends up disabled.
  // This lets the rest of the page emit events without a feature-detect.
  window.stawiTrack = window.stawiTrack || noop;

  if (!cfg.apiKey || !cfg.host) {
    return;
  }

  // PostHog official loader snippet (truncated; this is the v1 init pattern).
  // Loads /static/array.js from PostHog's CDN; once ready, the global
  // posthog object replaces our stub.
  !(function (t, e) {
    var o, n, p, r;
    e.__SV ||
      ((window.posthog = e),
      (e._i = []),
      (e.init = function (i, s, a) {
        function g(t, e) {
          var o = e.split(".");
          2 == o.length && ((t = t[o[0]]), (e = o[1]));
          t[e] = function () {
            t.push([e].concat(Array.prototype.slice.call(arguments, 0)));
          };
        }
        ((p = t.createElement("script")).type = "text/javascript"),
          (p.crossOrigin = "anonymous"),
          (p.async = !0),
          (p.src =
            s.api_host.replace(".i.posthog.com", "-assets.i.posthog.com") +
            "/static/array.js"),
          (r = t.getElementsByTagName("script")[0]).parentNode.insertBefore(p, r);
        var u = e;
        for (
          void 0 !== a ? (u = e[a] = []) : (a = "posthog"),
            u.people = u.people || [],
            u.toString = function (t) {
              var e = "posthog";
              return "posthog" !== a && (e += "." + a), t || (e += " (stub)"), e;
            },
            u.people.toString = function () {
              return u.toString(1) + ".people (stub)";
            },
            o =
              "init me ms capture register register_once register_for_session unregister unregister_for_session getFeatureFlag getFeatureFlagPayload isFeatureEnabled reloadFeatureFlags updateEarlyAccessFeatureEnrollment getEarlyAccessFeatures on onFeatureFlags onSessionId getSurveys getActiveMatchingSurveys renderSurvey canRenderSurvey identify setPersonProperties group resetGroups setPersonPropertiesForFlags resetPersonPropertiesForFlags setGroupPropertiesForFlags resetGroupPropertiesForFlags reset get_distinct_id getGroups get_session_id get_session_replay_url alias set_config startSessionRecording stopSessionRecording sessionRecordingStarted captureException loadToolbar get_property getSessionProperty createPersonProfile opt_in_capturing opt_out_capturing has_opted_in_capturing has_opted_out_capturing clear_opt_in_out_capturing debug getPageViewId captureTraceFeedback captureTraceMetric".split(
                " "
              ),
            n = 0;
          n < o.length;
          n++
        )
          g(u, o[n]);
        e._i.push([i, s, a]);
      }),
      (e.__SV = 1));
  })(document, window.posthog || []);

  window.posthog.init(cfg.apiKey, {
    api_host: cfg.host,
    // Capture pageviews + clicks on inputs/buttons automatically. The
    // login page is small and we already get good signal from autocapture.
    autocapture: true,
    capture_pageview: true,
    // Don't try to capture identified user properties before identify() —
    // pre-login events stay on the anon distinct ID until the server's
    // Alias call associates them.
    person_profiles: "identified_only",
    // Disable session recording on the login page by default; enable later
    // via a feature flag if needed. Session recordings would capture form
    // input including emails before sanitisation.
    disable_session_recording: true,
  });

  // Replace the noop with a real emitter now that the SDK is loaded. Other
  // scripts can call window.stawiTrack(eventName, properties) and we'll
  // forward to PostHog. Wrapping defends against any future SDK API changes.
  window.stawiTrack = function (eventName, properties) {
    try {
      if (window.posthog && typeof window.posthog.capture === "function") {
        window.posthog.capture(eventName, properties || {});
      }
    } catch (_e) {
      // Never let analytics errors break the login UX.
    }
  };
})();
