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

### [Content Security Policy (CSP) Header Not Set At ifis.iium.edu.my]

- **Severity:** Medium    
- **Description:**    
    Content Security Policy (CSP) is a security feature implemented by web browsers to help prevent cross-site scripting (XSS), clickjacking, and other code injection attacks. It allows a website to control which resources (like scripts, styles, images, fonts, etc.) can be loaded and executed in the browser.

- **Affected URLs:**    
    - https://ifis.iium.edu.my
    - 

- **Business Impact:**    
    - **Cross-Site Scripting (XSS) Attack**
  Malicious scripts can be injected into your site to steal user data, cookies, or session tokens.
   - **Clickjacking**
  Without CSP and related headers, attackers can trick users into clicking on hidden buttons or links, performing actions they didn’t intend.


- **OWASP Reference:**    
    https://owasp.org/www-community/controls/Content_Security_Policy

- **Recommendation:**    
    Full documentation and examples on how to implement CSP can be found at https://content-security-policy.com. For example, Javascript scripts from other sources can be blocked using CSP by adding the following header into the HTTP response,
  `Content-Security-Policy: script-src 'self'`. This way, attacks such as Cross-Site Scripting and Clickjacking can be blocked. Implementation of CSP may differs depending on what web framework and web servers are used, therefore it is advisable to refer to documentation that is specific to web frameworks and web server used in production.


- **Prevention Strategy:**    
    - Add all relevant Content Security Policy directives at the HTTP response such as `default-src`, `script-src`, `style-src`, `media-src` and `frame-src`   
    - Set each directive with the value of `self`. For example, `Content-Security-Policy: script-src 'self'`. This will prevent any other Javascript scripts source from running in the website.
    - Apply regular code reviews and testing.

> **Responsible Team:** Backend developers, Security team, QA 
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
