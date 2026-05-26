// apps/default/static/js/fedcm.js
// Browser-side FedCM probe. Graceful no-op on unsupported browsers.
(function () {
  "use strict";

  if (!("IdentityCredential" in window)) {
    return;
  }

  async function probe(opts) {
    try {
      const cred = await navigator.credentials.get({
        identity: {
          providers: [{
            configURL: opts.configURL,
            clientId: opts.clientId,
            params: {nonce: opts.nonce},
          }],
        },
        mediation: opts.mediation || "optional",
      });
      if (cred && cred.token) {
        return cred.token;
      }
      return null;
    } catch (err) {
      return null;
    }
  }

  async function complete(loginEventId, idToken) {
    const resp = await fetch("/s/login/" + encodeURIComponent(loginEventId) + "/fedcm-complete", {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({id_token: idToken}),
    });
    if (!resp.ok) {
      return null;
    }
    const body = await resp.json();
    return body.redirect_url || null;
  }

  window.stawiFedCM = {
    probeAndComplete: async function (opts) {
      const token = await probe(opts);
      if (!token) {
        return null;
      }
      const redirect = await complete(opts.loginEventId, token);
      if (redirect) {
        window.location.assign(redirect);
        return true;
      }
      return null;
    },
  };
})();
