# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-06-27  
**Scanned By:** [Your Name or Team]  
**Target Application:** http://ifis.iium.edu.my/online  
**Scan Type:** Active   
**Scan Duration:** Not specified  

---

## 1. Executive Summary

| Metric                          | Value                                     |
|--------------------------------|-------------------------------------------|
| Total Issues Identified        | 18                                        |
| Critical Issues                | 0                                         |
| High-Risk Issues               | 0                                         |
| Medium-Risk Issues             | 4                                         |
| Low-Risk/Informational Issues | 14                                         |
| Remediation Status             | Pending                                   |
| Key Takeaway                   | The scan found no critical or high-risk issues. However, 4 medium-risk and several low-risk issues were identified. CSP header is notably missing and should be prioritized. |

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability                     |
|------------|------------------|------------------------------------------|
| Critical   | 0                | -                                        |
| High       | 0                | -                                        |
| Medium     | 2               | Absence of Anti-CSRF Tokens, Content Security Policy (CSP) Header Not Set |
| Low        | 3                | Cookie No HttpOnly Flag, Cookie without SameSite Attribute, Server Leaks Version Information via "Server" HTTP Response Header Field |
| Info       | 1                | Session Management Response Identified |

---

## 3. Detailed Findings

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
Add a CSP header with directives like default-src, script-src, style-src, etc., to restrict the sources of content.  
**OWASP Reference:** https://owasp.org/www-community/controls/Content_Security_Policy  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 July 2025

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
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid. For example, use anti-CSRF packages such as the OWASP CSRFGuard.  
**OWASP Reference:** https://owasp.org/www-community/attacks/csrf  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 July 2025

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
Ensure that the HttpOnly flag is set for all cookies.  
**OWASP Reference:** https://owasp.org/www-community/HttpOnly  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 July 2025

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
Ensure that the SameSite attribute is set to either 'lax' or ideally 'strict' for all cookies.  
**OWASP Reference:** https://owasp.org/www-community/SameSite  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 July 2025

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
**OWASP Reference:** https://owasp.org/www-project-secure-headers/  
**Responsible Team:** Backend Developers  
**Target Remediation Date:** 1 July 2025

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
  - http://ifis.iium.edu.my/online 
  - https://ifis.iium.edu.my/robots.txt
  - https://ifis.iium.edu.my/sitemap.xml
- **ZAP Version:** 2.16.1  
- **Total Alerts Analyzed:** 6
