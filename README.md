# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP    
**Date of Scan:** [YYYY-MM-DD]    
**Scanned By:** [Name/Team]    
**Target Application:** [Application Name or URL]    
**Scan Type:** [Active / Passive]    
**Scan Duration:** [Start Time – End Time]

---

## 1. Executive Summary

| Metric                                                  | Value                        |
|-------------------------------|------------------|
| Total Issues Identified              | [11]        |
| Critical Issues                              | [0]                    |
| High-Risk Issues                            | [0]                    |
| Medium-Risk Issues                        | [4]                    |
| Low-Risk/Informational Issues | [0]                    |
| Remediation Status                        | [Pending] |

**Key Takeaway:**    
[Brief overview: e.g., "The scan identified 2 high-risk vulnerabilities that require immediate attention. No critical issues were found."]

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability                    |
|------------|------------------|--------------------------------|
| Critical      | [0]                    | - |
| High              | [0]                    |- |
| Medium          | [4]                    | CSP Header Missing, Anti-clickjacking Header Missing |
| Low                | [7]                    | Debug Errors, Info Leaks, Missing Headers         |
| Info              | [0]                    |-|

---

## 3. Detailed Findings

### Content Security Policy (CSP) Header Not Set

- **Severity:** Medium  
- **Description:**
  - Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

- **Affected URLs:**
  - https://ifis.iium.edu.my

- **Business Impact:**    
  - Without CSP, malicious actors can inject unauthorized scripts, compromising the integrity and security of the site.
  - Sensitive user information such as login credentials, personal data, or payment details can be intercepted or stolen due to insufficient content restrictions.

- **OWASP Reference:**    
    [https://owasp.org/www-community/controls/Content_Security_Policy](https://owasp.org/www-community/controls/Content_Security_Policy)

- **Recommendation:**
  - Implement CSP at HTTP response by adding relevant CSP directives such as `default-src`, `script-src`, `style-src`, `media-src`, and `frame-src`. Set value for each directives with `self` to allow resources from same origin only. Documentation of Content Security Policy can be found at [https://content-security-policy.com/](https://content-security-policy.com/). Detailed implementations may differ depending on what web frameworks and web servers used in the production.

- **Prevention Strategy:**    
  - Add relevant CSP directives.
  - Set values for each directives with `self`.
  - Apply regular code reviews and testing.

> **Responsible Team:** Backend developers, security team, QA   
> **Target Remediation Date:** 1 June 2025

---

### Missing Anti-clickjacking Header

- **Severity:** Medium  
- **Description:**
  - The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options. With the `frame-ancestor` directive, it disallows the site from being displayed in a frame

- **Affected URLs:**
  - [https://ifis.iium.edu.my](https://ifis.iium.edu.my) 

- **Business Impact:**    
  - **Clickjacking Attack**
    Attackers can embed the site in an invisible <iframe> and tricks users into clicking buttons or links while thinking they are interacting with something else.
  - **Phishing & Brand Abuse**
    Malicious actors can embed site within deceptive pages, making it appears as if the content is legit.

- **OWASP Reference:**
  - [https://owasp.org/www-community/attacks/Clickjacking](https://owasp.org/www-community/attacks/Clickjacking) 

- **Recommendation:**
  - Add `frame-ancestor` Content Security Policy directive and set it to `none` to prevent the site from becoming framable. Implementation may differ depending on web frameworks and web servers used.

- **Prevention Strategy:**    
  - Add `frame-ancestor` directive for the Content Security Policy.
  - Set value of the directive with `none`.
  - Apply regular code reviews and testing.

> **Responsible Team:** Backend developers, security team, QA   
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
Add a CSP header with directives like default-src, script-src, style-src, etc., to restrict the sources of content.  
**OWASP Reference:** https://owasp.org/www-community/controls/Content_Security_Policy  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

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
Add appropriate CSP directive or X-Frame-Options header.  
**OWASP Reference:** https://owasp.org/www-community/attacks/Clickjacking  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

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
Remove or obfuscate the 'X-Powered-By' header.  
**OWASP Reference:** https://owasp.org/www-community/attacks/Information_exposure_through_HTTP_headers  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

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
**OWASP Reference:** https://owasp.org/www-project-secure-headers/  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

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
Add the HSTS header to enforce HTTPS connections.  
**OWASP Reference:** https://owasp.org/www-project-secure-headers/#strict-transport-security  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

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
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

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
Suppress detailed error messages in production environments and log them securely.  
**OWASP Reference:** https://owasp.org/www-community/Improper_Error_Handling  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

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
Set the `SameSite` attribute to `Lax` or `Strict` depending on your application's requirements.  
**OWASP Reference:** https://owasp.org/www-community/controls/SameSite  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

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
**OWASP Reference:** https://owasp.org/www-community/Improper_Error_Handling  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 June 2025

---

## 4. Recommendations & Next Steps

- Address **Critical** and **High** vulnerabilities **immediately**.
- Re-test the application after remediation.
- Integrate secure coding standards.
- Schedule periodic scans (e.g., monthly or post-deployment).
- Consider a penetration test for in-depth analysis.

---

## Appendix (Optional)

- Scan configuration details
- **Sites Scanned**:    
- https://studentrepo.iium.edu.my  
- http://studentrepo.iium.edu.my
  *Total Alerts Analyzed:* 11

---

**Prepared by:**    
[Your Name]    
[Your Role / Department]    
[Email / Contact]    
[Date]
