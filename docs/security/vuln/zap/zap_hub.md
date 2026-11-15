# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 2 |
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
| CSP: script-src unsafe-inline | Medium | 2 |
| CSP: style-src unsafe-inline | Medium | 2 |
| Modern Web Application | Informational | 2 |
| Storable and Cacheable Content | Informational | Systemic |




## Alert Detail



### [ CSP: script-src unsafe-inline ](https://www.zaproxy.org/docs/alerts/10055/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://172.30.0.10:8000
  * Node Name: `http://172.30.0.10:8000`
  * Method: `GET`
  * Parameter: `content-security-policy`
  * Attack: ``
  * Evidence: `default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  * Other Info: `script-src includes unsafe-inline.`
* URL: http://172.30.0.10:8000/
  * Node Name: `http://172.30.0.10:8000/`
  * Method: `GET`
  * Parameter: `content-security-policy`
  * Attack: ``
  * Evidence: `default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  * Other Info: `script-src includes unsafe-inline.`


Instances: 2

### Solution

Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### Reference


* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://caniuse.com/#search=content+security+policy ](https://caniuse.com/#search=content+security+policy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)
* [ https://github.com/HtmlUnit/htmlunit-csp ](https://github.com/HtmlUnit/htmlunit-csp)
* [ https://web.dev/articles/csp#resource-options ](https://web.dev/articles/csp#resource-options)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ CSP: style-src unsafe-inline ](https://www.zaproxy.org/docs/alerts/10055/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://172.30.0.10:8000
  * Node Name: `http://172.30.0.10:8000`
  * Method: `GET`
  * Parameter: `content-security-policy`
  * Attack: ``
  * Evidence: `default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  * Other Info: `style-src includes unsafe-inline.`
* URL: http://172.30.0.10:8000/
  * Node Name: `http://172.30.0.10:8000/`
  * Method: `GET`
  * Parameter: `content-security-policy`
  * Attack: ``
  * Evidence: `default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  * Other Info: `style-src includes unsafe-inline.`


Instances: 2

### Solution

Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### Reference


* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://caniuse.com/#search=content+security+policy ](https://caniuse.com/#search=content+security+policy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)
* [ https://github.com/HtmlUnit/htmlunit-csp ](https://github.com/HtmlUnit/htmlunit-csp)
* [ https://web.dev/articles/csp#resource-options ](https://web.dev/articles/csp#resource-options)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

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

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: http://172.30.0.10:8000
  * Node Name: `http://172.30.0.10:8000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://172.30.0.10:8000/robots.txt
  * Node Name: `http://172.30.0.10:8000/robots.txt`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://172.30.0.10:8000/whoami
  * Node Name: `http://172.30.0.10:8000/whoami`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`

Instances: Systemic


### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3


