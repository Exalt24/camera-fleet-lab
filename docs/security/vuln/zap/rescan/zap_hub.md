# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 2 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Info | Informational | http://172.30.0.10:8000 | Percentage of responses with status code 2xx | 86 % |
| Info | Informational | http://172.30.0.10:8000 | Percentage of responses with status code 4xx | 13 % |
| Info | Informational | http://172.30.0.10:8000 | Percentage of endpoints with content type application/json | 85 % |
| Info | Informational | http://172.30.0.10:8000 | Percentage of endpoints with content type text/html | 14 % |
| Info | Informational | http://172.30.0.10:8000 | Percentage of endpoints with method GET | 100 % |
| Info | Informational | http://172.30.0.10:8000 | Count of total endpoints | 7    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Modern Web Application | Informational | 2 |
| Non-Storable Content | Informational | Systemic |




## Alert Detail



### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

* URL: http://172.30.0.10:8000
  * Node Name: `http://172.30.0.10:8000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script>
const WHY = {
  up: "Video decodes through the tunnel.",
  degraded: "The port answers but no video decodes. A camera or encoder problem, not the network.",
  blocked: "Packets cross the VPN, the camera port does not answer. Look at the NAT rule, the firewall, the camera.",
  tunnel_down: "No packet crosses the VPN. Look at WireGuard, the keys, the endpoint, the 4G link."
};
const $ = id => document.getElementById(id);
function light(prefix, ok, skipped, text, detail) {
  $("d-" + prefix).className = "dot " + (skipped ? "skip" : ok ? "ok" : "bad");
  // a layer that was not checked has nothing to explain: showing the upstream error under it reads as a second failure
  $("t-" + prefix).textContent = text; $("x-" + prefix).textContent = skipped ? "" : (detail || "");
}
async function tick() {
  try {
    const [s, h] = await Promise.all([fetch("/status").then(r => r.json()), fetch("/history?limit=60").then(r => r.json())]);
    const st = $("state"); st.textContent = s.state.replace("_", " "); st.className = "state s-" + s.state;
    $("why").textContent = WHY[s.state] || "";
    light("tunnel", s.tunnel_ok, false, s.tunnel_ok ? "ping crosses" : "no reply", "last handshake " + (s.handshake_age_s ?? "never") + " s ago");
    const tunnelDown = !s.tunnel_ok;
    light("tcp", s.tcp_ok, tunnelDown, tunnelDown ? "not checked" : s.tcp_ok ? "open" : "silent", s.tcp_ms != null ? s.tcp_ms + " ms" : (tunnelDown ? "" : s.error));
    light("rtsp", s.rtsp_ok, tunnelDown || !s.tcp_ok, (tunnelDown || !s.tcp_ok) ? "not checked" : s.rtsp_ok ? (s.codec + " " + s.resolution) : "no video", s.rtsp_ok ? "" : (s.error || ""));
    const cells = $("cells"); cells.innerHTML = "";
    h.slice().reverse().forEach(p => { const c = document.createElement("div"); c.className = "cell c-" + p.state; c.title = p.ts + " " + p.state; cells.appendChild(c); });
  } catch (e) { $("why").textContent = "dashboard cannot reach the API: " + e; }
}
window.setCaption = t => { const c = $("caption"); c.style.display = t ? "block" : "none"; c.textContent = t || ""; };
// Behind the SSO proxy (security/iam/) this shows who is signed in and with which role; without it nothing is shown.
fetch("/whoami").then(r => r.json()).then(w => { if (w.user) { const e = $("who"); e.style.display = "block"; e.textContent = "Signed in as " + w.user + " (" + (w.roles.join(", ") || "no role") + ")"; } }).catch(() => {});
tick(); setInterval(tick, 1000);
</script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://172.30.0.10:8000/
  * Node Name: `http://172.30.0.10:8000/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script>
const WHY = {
  up: "Video decodes through the tunnel.",
  degraded: "The port answers but no video decodes. A camera or encoder problem, not the network.",
  blocked: "Packets cross the VPN, the camera port does not answer. Look at the NAT rule, the firewall, the camera.",
  tunnel_down: "No packet crosses the VPN. Look at WireGuard, the keys, the endpoint, the 4G link."
};
const $ = id => document.getElementById(id);
function light(prefix, ok, skipped, text, detail) {
  $("d-" + prefix).className = "dot " + (skipped ? "skip" : ok ? "ok" : "bad");
  // a layer that was not checked has nothing to explain: showing the upstream error under it reads as a second failure
  $("t-" + prefix).textContent = text; $("x-" + prefix).textContent = skipped ? "" : (detail || "");
}
async function tick() {
  try {
    const [s, h] = await Promise.all([fetch("/status").then(r => r.json()), fetch("/history?limit=60").then(r => r.json())]);
    const st = $("state"); st.textContent = s.state.replace("_", " "); st.className = "state s-" + s.state;
    $("why").textContent = WHY[s.state] || "";
    light("tunnel", s.tunnel_ok, false, s.tunnel_ok ? "ping crosses" : "no reply", "last handshake " + (s.handshake_age_s ?? "never") + " s ago");
    const tunnelDown = !s.tunnel_ok;
    light("tcp", s.tcp_ok, tunnelDown, tunnelDown ? "not checked" : s.tcp_ok ? "open" : "silent", s.tcp_ms != null ? s.tcp_ms + " ms" : (tunnelDown ? "" : s.error));
    light("rtsp", s.rtsp_ok, tunnelDown || !s.tcp_ok, (tunnelDown || !s.tcp_ok) ? "not checked" : s.rtsp_ok ? (s.codec + " " + s.resolution) : "no video", s.rtsp_ok ? "" : (s.error || ""));
    const cells = $("cells"); cells.innerHTML = "";
    h.slice().reverse().forEach(p => { const c = document.createElement("div"); c.className = "cell c-" + p.state; c.title = p.ts + " " + p.state; cells.appendChild(c); });
  } catch (e) { $("why").textContent = "dashboard cannot reach the API: " + e; }
}
window.setCaption = t => { const c = $("caption"); c.style.display = t ? "block" : "none"; c.textContent = t || ""; };
// Behind the SSO proxy (security/iam/) this shows who is signed in and with which role; without it nothing is shown.
fetch("/whoami").then(r => r.json()).then(w => { if (w.user) { const e = $("who"); e.style.display = "block"; e.textContent = "Signed in as " + w.user + " (" + (w.roles.join(", ") || "no role") + ")"; } }).catch(() => {});
tick(); setInterval(tick, 1000);
</script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`


Instances: 2

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://172.30.0.10:8000
  * Node Name: `http://172.30.0.10:8000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://172.30.0.10:8000/favicon.ico
  * Node Name: `http://172.30.0.10:8000/favicon.ico`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://172.30.0.10:8000/history%3Flimit=60
  * Node Name: `http://172.30.0.10:8000/history (limit)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://172.30.0.10:8000/robots.txt
  * Node Name: `http://172.30.0.10:8000/robots.txt`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://172.30.0.10:8000/sitemap.xml
  * Node Name: `http://172.30.0.10:8000/sitemap.xml`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``

Instances: Systemic


### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3


