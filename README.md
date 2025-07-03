# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-06-27  
**Scanned By:** [CyberZ]  
**Target Application:** http://ifis.iium.edu.my/online, https://ifis.iium.edu.my , http://studentrepo.iium.edu.my.  
**Scan Type:** Active   
**Scan Duration:** ~2 minutes  

---

## 1. Executive Summary

| Metric                          | Value                                     |
|--------------------------------|-------------------------------------------|
| Total Issues Identified        | 18                                        |
| Critical Issues                | 0                                         |
| High-Risk Issues               | 0                                         |
| Medium-Risk Issues             | 6                                         |
| Low-Risk/Informational Issues | 12                                         |
| Remediation Status             | Pending                                   |
| Key Takeaway                   | The scan found no critical or high-risk issues. However, 6 medium-risk and several low-risk issues were identified. CSP header is notably missing and should be prioritized. |

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability                    |
|------------|------------------|------------------------------------------|
| Critical   | 0                | -                                        |
| High       | 0                | -                                        |
| Medium     | 6                | Absence of Anti-CSRF Tokens, Content Security Policy (CSP) Header Not Set |
| Low        | 11                | Cookie No HttpOnly Flag, Cookie without SameSite Attribute, Server Leaks Version Information via "Server" HTTP Response Header Field |
| Info       | 1                | Session Management Response Identified |

---

## 3. Detailed Findings

### Content Security Policy (CSP) Header Not Set

**Severity:** Medium    
**Description:**    
Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.  
**Affected URLs:**    
- https://ifis.iium.edu.my
- https://ifis.iium.edu.my/robots.txt
- https://ifis.iium.edu.my/sitemap.xml  
**Business Impact:**    
- Without CSP, malicious actors can inject unauthorized scripts, compromising the integrity and security of the site.
- Sensitive user information such as login credentials, personal data, or payment details can be intercepted or stolen due to insufficient content restrictions.  
**OWASP Reference:**    
[https://owasp.org/www-community/controls/Content_Security_Policy](https://owasp.org/www-community/controls/Content_Security_Policy)  
**Recommendation:**  
Add the following HTTP header in the server or middleware to enforce same-origin-only loading :  
`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; media-src 'self'; frame-src 'self';`  
**Prevention Strategy:**    
- Add relevant CSP directives.
- Set values for each directives with `self`.
- Apply regular code reviews and testing.  
> **Responsible Team:** Backend developers, security team, QA   
> **Target Remediation Date:** 1 June 2025

---

### Missing Anti-clickjacking Header

**Severity:** Medium  
**Description:**  
The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options. With the `frame-ancestor` directive, it disallows the site from being displayed in a frame  
**Affected URLs:**
- [https://ifis.iium.edu.my](https://ifis.iium.edu.my)  
**Business Impact:**    
- **Clickjacking Attack**  
    Attackers can embed the site in an invisible <iframe> and tricks users into clicking buttons or links while thinking they are interacting with something else.  
- **Phishing & Brand Abuse**  
    Malicious actors can embed site within deceptive pages, making it appears as if the content is legit.  
**OWASP Reference:**  [https://owasp.org/www-community/attacks/Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)  
**Recommendation:**
In the server or middleware use this header to restrict all resource types to self and block framing :  
`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; media-src 'self'; frame-src 'self'; frame-ancestors 'none';`  
**Prevention Strategy:**    
- Add `frame-ancestor` directive for the Content Security Policy.
- Set value of the directive with `none`.
- Apply regular code reviews and testing.  

> **Responsible Team:** Backend developers, security team, QA   
> **Target Remediation Date:** 1 June 2025

---

### Server Leaks Version Information via "Server" HTTP Response Header Field
**Severity:** Low  
**Description:**  
The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.  
**Affected URLs:**
- [https://ifis.iium.edu.my](https://ifis.iium.edu.my)  
**Business Impact:**    
- Helps attackers identify specific software and version, making targeted exploits easier.
- Increases the risk of automated attacks using known vulnerabilities.
- May lead to full system compromise if known exploits are available for the disclosed version.  
**OWASP Reference:** [https://owasp.org/www-project-secure-headers/](https://owasp.org/www-project-secure-headers/)  
**Recommendation:**  
Configure the web server to either remove the "Server" HTTP response header entirely or replace it with a generic value (e.g., "Web Server") to prevent disclosing detailed version information that could aid attackers in identifying and exploiting known vulnerabilities.  
`# Apache (httpd.conf or .htaccess)
ServerSignature Off
ServerTokens Prod
<IfModule mod_headers.c>
    Header always unset Server
    Header always set Server "Web Server"
</IfModule>`

- **Prevention Strategy:**    
  - Disable or modify the "Server" header in the web server configuration (e.g., Apache, Nginx, IIS).  
  - Use a reverse proxy (like Nginx or HAProxy) to strip or overwrite response headers.  
  - Regularly update and patch web server software to reduce risk even if version info is exposed.  
  - Conduct security scans to detect unintentional header exposures.  
  - Implement security headers using a Web Application Firewall (WAF) or middleware solutions.   
> **Responsible Team:** Backend developers, security team, QA   
> **Target Remediation Date:** 1 June 2025

---


###  Content Security Policy (CSP) Header Not Set  
**Severity:** Medium  
**Confidence:** High  
**Description:**  
The application does not implement a Content Security Policy (CSP) header, which helps mitigate attacks like Cross-Site Scripting (XSS).  
**Affected URL:** http://ifis.iium.edu.my/online  
**Business Impact:**  
Without CSP, browsers will load resources from any origin, increasing the risk of script injection attacks.  
**Recommendation:**  
Add the following HTTP header in the server or middleware to enforce same-origin-only loading :  
`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; media-src 'self'; frame-src 'self';`   
**OWASP Reference:** https://owasp.org/www-community/controls/Content_Security_Policy  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Absence of Anti-CSRF Tokens  
**Severity:** Medium  
**Confidence:** Low  
**Description:**  
No Anti-CSRF tokens were found in a HTML submission form.  
**Affected URL:** http://ifis.iium.edu.my/online  
**Business Impact:**  
The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.  
**Recommendation:**  
Register a vetted CSRF protection library at the framework level.  
`<!-- in the <head> -->`  
`<script src="/CSRFGuard.js"></script>`  
**OWASP Reference:** https://owasp.org/www-community/attacks/csrf  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Cookie No HttpOnly Flag
**Severity:** Low  
**Confidence:** Medium  
**Description:**  
A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript.  
**Affected URL:** http://ifis.iium.edu.my/online  
**Business Impact:**  
Malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.  
**Recommendation:**  
At the application or proxy layer, ensure every Set-Cookie header includes HttpOnly (and ideally Secure/SameSite) to prevent JavaScript access.  
`## Node.js ##`
`app.use(require('express-session')({
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 3600000
  }
}));`  

`## PHP (7.3+) ##`
`setcookie(
  'session_id',
  $token,
  [
    'expires'  => time() + 3600,
    'path'     => '/',
    'domain'   => 'example.com',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict'
  ]
);`

`## Apache (httpd.conf or .htaccess)## `  
`<IfModule mod_headers.c>
    Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
</IfModule>`  
**OWASP Reference:** https://owasp.org/www-community/HttpOnly  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Cookie without SameSite Attribute
**Severity:** Low  
**Confidence:** Medium  
**Description:**  
A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request.  
**Affected URL:** http://ifis.iium.edu.my/online  
**Business Impact:**  
Attackers can perform unauthorized actions on behalf of authenticated users, leading to data loss, account manipulation, or financial fraud.  
**Recommendation:**  
Set all Set-Cookie headers with SameSite=Strict (or Lax)  
`Set-Cookie: sessionId=abc123; Path=/; HttpOnly; Secure; SameSite=Strict`  
**OWASP Reference:** https://owasp.org/www-community/SameSite  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Server Leaks Version Information via 'Server' HTTP Header  
**Severity:** Low  
**Confidence:** High  
**Description:**  
The 'Server' header discloses the web server version used by the application.  
**Affected URL:** http://ifis.iium.edu.my/online  
**Business Impact:**  
Facilitates fingerprinting attacks and exploitation of known vulnerabilities.  
**Recommendation:**  
Configure server to hide version info in the response headers.
`# Apache (httpd.conf or .htaccess)
ServerSignature Off
ServerTokens Prod
<IfModule mod_headers.c>
    Header always unset Server
    Header always set Server "Web Server"
</IfModule>`  
**OWASP Reference:** https://owasp.org/www-project-secure-headers/  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Content Security Policy (CSP) Header Not Set  
**Severity:** Medium  
**Confidence:** High  
**Description:**  
The application does not implement a Content Security Policy (CSP) header, which helps mitigate attacks like Cross-Site Scripting (XSS).  
**Affected URL:** http://studentrepo.iium.edu.my  
**Business Impact:**  
Without CSP, browsers will load resources from any origin, increasing the risk of script injection attacks.

**Recommendation:**  
Add the following HTTP header in the server or middleware to enforce same-origin-only loading :  
`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; media-src 'self'; frame-src 'self';`    
**OWASP Reference:** https://owasp.org/www-community/controls/Content_Security_Policy  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Missing Anti-clickjacking Header  
**Severity:** Medium  
**Confidence:** Medium  
**Description:**  
The page does not set an 'X-Frame-Options' or 'frame-ancestors' directive.  
**Affected URL:** http://studentrepo.iium.edu.my  
**Business Impact:**  
Leaves application vulnerable to clickjacking.

**Recommendation:**  
In the server or middleware use this header to restrict all resource types to self and block framing :  
`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; media-src 'self'; frame-src 'self'; frame-ancestors 'none';`    
**OWASP Reference:** https://owasp.org/www-community/attacks/Clickjacking  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Server Leaks Information via 'X-Powered-By' HTTP Header  
**Severity:** Low  
**Confidence:** Medium  
**Description:**  
The server includes 'X-Powered-By' in the response header, revealing the technology stack.  
**Affected URL:** http://studentrepo.iium.edu.my  
**Business Impact:**  
Attackers can target known vulnerabilities of disclosed technologies.

**Recommendation:**  
Disable or override the X-Powered-By header at the app or proxy layer.  
`// Express (Node.js)
app.disable('x-powered-by');`  

`// Nginx
more_clear_headers X-Powered-By;
more_set_headers 'X-Powered-By: Web Server';`  
**OWASP Reference:** https://owasp.org/www-community/attacks/Information_exposure_through_HTTP_headers  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Server Leaks Version Information via 'Server' HTTP Header  
**Severity:** Low  
**Confidence:** High  
**Description:**  
The 'Server' header discloses the web server version used by the application.  
**Affected URL:** http://studentrepo.iium.edu.my  
**Business Impact:**  
Facilitates fingerprinting attacks and exploitation of known vulnerabilities.  

**Recommendation:**  
Configure server to hide version info in the response headers.
`# Apache (httpd.conf or .htaccess)
ServerSignature Off
ServerTokens Prod
<IfModule mod_headers.c>
    Header always unset Server
    Header always set Server "Web Server"
</IfModule>`
**OWASP Reference:** https://owasp.org/www-project-secure-headers/  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Strict-Transport-Security Header Not Set  
**Severity:** Low  
**Confidence:** High  
**Description:**  
The Strict-Transport-Security header is not set, which means users might access the site over an insecure connection.  
**Affected URL:** http://studentrepo.iium.edu.my  
**Business Impact:**  
Users may be vulnerable to SSL stripping attacks if they initially connect over HTTP.  

**Recommendation:**  
Add the HSTS header with a long max‐age, include all subdomains, and enable preload.  
`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`  
**OWASP Reference:** https://owasp.org/www-project-secure-headers/#strict-transport-security  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  X-Content-Type-Options Header Missing  
**Severity:** Low  
**Confidence:** Medium  
**Description:**  
Missing this header can allow the browser to interpret files as a different MIME type.  
**Affected URL:** http://studentrepo.iium.edu.my  
**Business Impact:**  
Could lead to script execution in the wrong context, risking XSS.  

**Recommendation:**  
Set `X-Content-Type-Options: nosniff` on all responses.  
**OWASP Reference:** https://owasp.org/www-project-secure-headers/#x-content-type-options  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Application Error Disclosure  
**Severity:** Low  
**Confidence:** Medium  
**Description:**  
The application discloses technical error messages in responses.  
**Affected URL:** http://studentrepo.iium.edu.my  
**Business Impact:**  
Could provide attackers with information about the app’s internal structure or technology stack.  

**Recommendation:**  
In production, register a generic error‐handler that logs full error details internally and returns a generic response.  
`app.use((err, req, res, next) => { logger.error(err.stack); res.status(500).json({ error: 'Internal Server Error' }); });`  
**OWASP Reference:** https://owasp.org/www-community/Improper_Error_Handling  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Cookie with SameSite Attribute None  
**Severity:** Low  
**Confidence:** Medium  
**Description:**  
Cookies are set with `SameSite=None` which may expose them to cross-site request forgery attacks.  
**Affected URL:** http://studentrepo.iium.edu.my  
**Business Impact:**  
Could lead to CSRF attacks if cookies are sent cross-site without secure validation. 

**Recommendation:**  
Set all Set-Cookie headers with SameSite=Strict (or Lax)  
`Set-Cookie: sessionId=abc123; Path=/; HttpOnly; Secure; SameSite=Strict`  
**OWASP Reference:** https://owasp.org/www-community/controls/SameSite  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---

###  Information Disclosure – Debug Error Messages  
**Severity:** Low  
**Confidence:** Medium  
**Description:**  
The server response contains debug error messages that can reveal application internals or misconfigurations.  
**Affected URL:** https://studentrepo.iium.edu.my/server/opensearch/search?format=rss&query=*&scope=...  
**Business Impact:**  
Exposes information such as file paths, server errors, or code stack traces that attackers can leverage. 

**Recommendation:**  
Configure the server to suppress debug error messages in production. Display only user-friendly error pages. 
`if (process.env.NODE_ENV === 'production') {
  app.use((err, req, res, next) => {
    logger.error(err.stack);
    res.status(500).render('error', { message: 'Something went wrong. Please try again later.' });
  });
}`
**OWASP Reference:** https://owasp.org/www-community/Improper_Error_Handling  
> **Responsible Team:** Backend Developers  
> **Target Remediation Date:** 1 June 2025

---



## 4. Recommendations & Next Steps

- Prioritize fixing medium-risk issues immediately  
- Re-test after remediation  
- Apply secure HTTP headers and configurations  
- Schedule monthly security scans  
- Consider a deeper security assessment via pen-test  

---

## Appendix

- **Sites Scanned**:
  - https://ifis.iium.edu.my 
  - http://ifis.iium.edu.my/online 
  - https://ifis.iium.edu.my/robots.txt
  - https://ifis.iium.edu.my/sitemap.xml
  - http://studentrepo.iium.edu.my 
- **ZAP Version:** 2.16.1  
- **Total Alerts Analyzed:** 17
- **Person In Charge**
  - Muhammad Hakim Bin Md Nazri 2110457 (hakimnazry@gmail.com)
  - Muhammad Fadly 2117999 (m.fadly@gmail.com)
  - Muhammad Iqbal As Sufi bin Mahamad A'sim 2124165 (iqbalassufi@gmail.com)
