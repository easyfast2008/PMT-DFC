// PMT-DFC Cloudflare Worker Relay
//
// Deploy this as a Cloudflare Worker (free tier: 100K requests/day).
// It acts as a transparent HTTP relay: the censored client sends fronted
// requests to the Worker, this Worker forwards them to your VPS
// tunnel-node, and returns the response.
//
// The Worker is "dumb" — it does not interpret the batch protocol.
// All intelligence lives in the VPS tunnel-node.
//
// Setup:
//   1. Install wrangler: npm install -g wrangler
//   2. Set your VPS URL and auth key in wrangler.toml [vars].
//   3. wrangler deploy
//   4. Copy your Worker URL into client config's "worker_url".
//
// Protocol inspired by MhR (https://github.com/masterking32/MasterHttpRelayVPN).

export default {
  async fetch(request, env) {
    // Health check.
    if (request.method === "GET") {
      return new Response("PMT-DFC relay is running.", {
        headers: { "Content-Type": "text/plain" },
      });
    }

    if (request.method !== "POST") {
      return new Response("method not allowed", { status: 405 });
    }

    try {
      const body = await request.text();
      let payload;
      try {
        payload = JSON.parse(body);
      } catch {
        return new Response('{"e":"invalid json"}', {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Verify auth key at the relay level.
      const authKey = env.AUTH_KEY || "CHANGE_ME";
      if (payload.k !== authKey) {
        return new Response('{"e":"unauthorized"}', {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Forward to VPS tunnel-node.
      const tunnelURL = env.TUNNEL_SERVER_URL || "https://YOUR_VPS_IP:8080";
      const resp = await fetch(tunnelURL + "/tunnel/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body,
      });

      const respBody = await resp.text();
      return new Response(respBody, {
        status: resp.status,
        headers: { "Content-Type": "application/json" },
      });
    } catch (err) {
      return new Response(
        JSON.stringify({ e: "relay error: " + err.message }),
        {
          status: 502,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  },
};
