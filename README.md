# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-06-27  
**Scanned By:** [CyberZ]  
**Target Application:** http://ifis.iium.edu.my/online, https://ifis.iium.edu.my .  
**Scan Type:** Active   
**Scan Duration:** ~2 minutes  

---

## 1. Executive Summary

| Metric                          | Value                                     |
|--------------------------------|-------------------------------------------|
| Total Issues Identified        | 9                                        |
| Critical Issues                | 0                                         |
| High-Risk Issues               | 0                                         |
| Medium-Risk Issues             | 4                                          |
| Low-Risk/Informational Issues |  5                                       |
| Remediation Status             | Pending                                   |
| Key Takeaway                   | The scan found no critical or high-risk issues. However, 6 medium-risk and several low-risk issues were identified. CSP header is notably missing and should be prioritized. |

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability                    |
|------------|------------------|------------------------------------------|
| Critical   | 0                | -                                        |
| High       | 0                | -                                        |
| Medium     | 4                 | Absence of Anti-CSRF Tokens, Content Security Policy (CSP) Header Not Set |
| Low        | 4                | Cookie No HttpOnly Flag, Cookie without SameSite Attribute, Server Leaks Version Information via "Server" HTTP Response Header Field |
| Info       | 1                | Session Management Response Identified |

A total of **9 security issues** were identified during the assessment.

- **No critical or high-risk vulnerabilities** were found.
- **4 issues were classified as medium-risk**, including the absence of anti-CSRF tokens, missing Content Security Policy (CSP) headers, and other related protections that help mitigate common web attacks like XSS and CSRF.
- **4 low-risk issues** were found, involving common misconfigurations such as:
  - Cookies missing `HttpOnly` and `SameSite` attributes
  - Exposure of server version details via response headers
- **1 informational-level issue** was observed related to session management response behavior.
  
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


---

## 4. Recommendations & Next Steps

### Immediate Remediation (Medium-Risk Issues)

- **Implement a Content Security Policy (CSP)** to restrict the sources of scripts, styles, media, and frames:
  - Add a `Content-Security-Policy` header at the web server or application middleware level.
  - Example:  
    `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none';`
- **Add anti-clickjacking protection** using either `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none';`
- **Ensure CSRF protection** is applied to all forms and authenticated endpoints:
  - Use Laravel’s built-in `@csrf` directive or a validated token-based CSRF protection mechanism.

### Technical Fixes for Low-Risk Issues
- **Secure cookies with `HttpOnly`, `Secure`, and `SameSite` attributes**:
  - All cookies should be configured with `HttpOnly` and `SameSite=Strict` (or `Lax`) to prevent XSS and CSRF attacks.
- **Hide server version and technology disclosures**:
  - Disable or mask the `Server` and `X-Powered-By` headers in Apache, Nginx, or application-level config:
    ```apache
    ServerSignature Off
    ServerTokens Prod
    Header always unset X-Powered-By
    Header always unset Server
    Header always set Server "Web Server"
    ```
- **Add missing security headers**:
  - `X-Content-Type-Options: nosniff`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Frame-Options: DENY`

### Laravel-Specific Adjustments
- Update `.env` with secure defaults:
  ```env
  APP_ENV=production
  APP_DEBUG=false
  SESSION_SECURE_COOKIE=true

---

## Appendix

- **Sites Scanned**:
  - https://ifis.iium.edu.my 
  - http://ifis.iium.edu.my/online 
  - https://ifis.iium.edu.my/robots.txt
  - https://ifis.iium.edu.my/sitemap.xml

- **ZAP Version:** 2.16.1  
- **Total Alerts Analyzed:** 9
- **Person In Charge**
  - Muhammad Hakim Bin Md Nazri 2110457 (hakimnazry@gmail.com)
  - Muhammad Fadly 2117999 (m.fadly@gmail.com)
