// PMT-DFC Apps Script Relay
//
// Deploy this as a Google Apps Script Web App. It acts as a transparent
// HTTP relay: the censored client sends fronted requests to
// script.google.com, this script forwards them to your VPS tunnel-node,
// and returns the response.
//
// The relay is "dumb" — it does not interpret the batch protocol.
// All intelligence (session management, auth verification, TCP proxying)
// lives in the VPS tunnel-node.
//
// Setup:
//   1. Open https://script.google.com and create a new project.
//   2. Replace the default code with this file.
//   3. Set TUNNEL_SERVER_URL to your VPS's public URL.
//   4. Set AUTH_KEY to the same secret as your VPS's PMT_AUTH_KEY.
//   5. Deploy → New deployment → Web app.
//      - Execute as: Me
//      - Who has access: Anyone
//   6. Copy the Deployment ID into your client config's "script_id".
//
// Protocol inspired by MhR (https://github.com/masterking32/MasterHttpRelayVPN).
// Credit to @masterking32 for the original Apps Script relay concept.

// ===== CONFIGURATION =====
const TUNNEL_SERVER_URL = "https://YOUR_VPS_IP:8080";
const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
// =========================

function doPost(e) {
  try {
    var payload = JSON.parse(e.postData.contents);

    // Verify auth key at the relay level (defense in depth;
    // the VPS also verifies).
    if (payload.k !== AUTH_KEY) {
      return ContentService.createTextOutput(
        JSON.stringify({ e: "unauthorized" })
      ).setMimeType(ContentService.MimeType.JSON);
    }

    // Forward the entire JSON payload to the VPS tunnel-node.
    var options = {
      method: "post",
      contentType: "application/json",
      payload: e.postData.contents,
      muteHttpExceptions: true,
      // Apps Script has a 60-second UrlFetch timeout.
      // The VPS should respond well within that.
    };

    var response = UrlFetchApp.fetch(
      TUNNEL_SERVER_URL + "/tunnel/batch",
      options
    );

    return ContentService.createTextOutput(response.getContentText())
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService.createTextOutput(
      JSON.stringify({ e: "relay error: " + err.message })
    ).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  return ContentService.createTextOutput("PMT-DFC relay is running.")
    .setMimeType(ContentService.MimeType.TEXT);
}
