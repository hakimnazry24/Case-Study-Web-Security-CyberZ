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
| Total Issues Identified              | [Total Count]        |
| Critical Issues                              | [Count]                    |
| High-Risk Issues                            | [Count]                    |
| Medium-Risk Issues                        | [Count]                    |
| Low-Risk/Informational Issues | [Count]                    |
| Remediation Status                        | [Pending/In Progress/Complete] |

**Key Takeaway:**    
[Brief overview: e.g., "The scan identified 2 high-risk vulnerabilities that require immediate attention. No critical issues were found."]

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability                    |
|------------|------------------|--------------------------------|
| Critical      | [Count]                    | [e.g., Remote Code Execution]    |
| High              | [Count]                    | [e.g., SQL Injection]                    |
| Medium          | [Count]                    | [e.g., Insecure Cookies]              |
| Low                | [Count]                    | [e.g., Missing HTTP Headers]      |
| Info              | [Count]                    | [e.g., Server Version Exposed] |

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
    Implement CSP at HTTP response by adding relevant CSP directives such as `default-src`, `script-src`, `style-src`, `media-src`, and `frame-src`. Set value for each directives with `self` to allow resources from same origin only. Documentation of Content Security Policy can be found at [https://content-security-policy.com/](https://content-security-policy.com/). Detailed implementations may differ depending on what web frameworks and web servers used in the production.

- **Prevention Strategy:**    
  - Add relevant CSP directives.
  - Set values for each directives with `self`.
  - Apply regular code reviews and testing.

> **Responsible Team:** Backend developers, security team, QA    
> **Target Remediation Date:** 1 June 2025

---

(Repeat for each major vulnerability)

---

## 4. Recommendations & Next Steps

- Address **Critical** and **High** vulnerabilities **immediately**.
- Re-test application after remediation.
- Integrate secure coding standards.
- Schedule periodic scans (e.g., monthly or post-deployment).
- Consider a penetration test for in-depth analysis.

---

## Appendix (Optional)

- Scan configuration details    
- List of all scanned URLs    
- Full technical findings (for security team)

---

**Prepared by:**    
[Your Name]    
[Your Role / Department]    
[Email / Contact]    
[Date]
