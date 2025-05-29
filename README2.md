# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-05-25  
**Scanned By:** [Your Name or Team]  
**Target Application:** https://studentrepo.iium.edu.my  
**Scan Type:** Active  
**Scan Duration:** Not specified  

---

## 1. Executive Summary

| Metric                          | Value                                     |
|--------------------------------|-------------------------------------------|
| Total Issues Identified        | 9                                        |
| Critical Issues                | 0                                         |
| High-Risk Issues               | 0                                         |
| Medium-Risk Issues             | 2                                         |
| Low-Risk/Informational Issues | 7                                         |
| Remediation Status             | Pending                                   |
| Key Takeaway                   | The scan found no critical or high-risk issues. However, 3 medium-risk and several low-risk issues were identified. CSP header is notably missing and should be prioritized. |

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability                     |
|------------|------------------|------------------------------------------|
| Critical   | 0                | -                                        |
| High       | 0                | -                                        |
| Medium     | 2               | CSP Header Missing, Anti-clickjacking Header Missing |
| Low        | 7                | Debug Errors, Info Leaks, Missing Headers |
| Info       | 0                | -                                        |

---

## 3. Detailed Findings

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

- Prioritize fixing medium-risk issues immediately  
- Re-test after remediation  
- Apply secure HTTP headers and configurations  
- Schedule monthly security scans  
- Consider a deeper security assessment via pen-test  

---

## Appendix

- **Sites Scanned**:  
  - https://studentrepo.iium.edu.my  
  - http://studentrepo.iium.edu.my  
- **ZAP Version:** 2.16.1  
- **Total Alerts Analyzed:** 9
