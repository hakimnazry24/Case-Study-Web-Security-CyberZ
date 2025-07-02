# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-06-27  
**Scanned By:** [CyberZ]  
**Target Application:** http://studentrepo.iium.edu.my.
**Scan Type:** Active   
**Scan Duration:** ~2 minutes  

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
| Key Takeaway                   | The scan found no critical or high-risk issues. However, 2 medium-risk and several low-risk issues were identified. CSP header is notably missing and should be prioritized. |

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability                    |
|------------|------------------|------------------------------------------|
| Critical   | 0                | -                                        |
| High       | 0                | -                                        |
| Medium     | 2                | Absence of Anti-CSRF Tokens, Content Security Policy (CSP) Header Not Set |
| Low        | 7                | Cookie No HttpOnly Flag, Cookie without SameSite Attribute, Server Leaks Version Information via "Server" HTTP Response Header Field |
| Info       | 0                | -                                        |

---

## 3. Detailed Findings

✅ [CSP Specific] - Content Security Policy Related Only
### Content Security Policy (CSP) Header Not Set

**Severity:** Medium\
**Confidence:** High

**Description:**\
The application does not include a `Content-Security-Policy` (CSP) HTTP header. This header helps prevent various injection attacks such as **Cross-Site Scripting (XSS)** by specifying which sources the browser should trust to load content (e.g., scripts, styles, images).

**Affected URL:** <http://studentrepo.iium.edu.my>

**Business Impact:**\
Without a CSP, modern browsers will load JavaScript, stylesheets, images, and other resources from **any origin**. This increases the risk of malicious content being injected or loaded from untrusted sources --- especially dangerous if the app is vulnerable to reflected or stored XSS.

**Recommendation:**\
Implement a strict but functional Content Security Policy that defines the allowed sources for different types of content (e.g., `script-src`, `style-src`, `img-src`). This significantly reduces the impact of XSS and similar attacks by **limiting what gets executed in the browser**.

**OWASP Reference:**\
<https://owasp.org/www-community/controls/Content_Security_Policy>

* * * * *

#### 🛠️ Remediation Steps for Developers

**Approach:** Use [`spatie/laravel-csp`](https://github.com/spatie/laravel-csp) to enforce a CSP via middleware in Laravel.

**Step 1: Install CSP package**

`composer require spatie/laravel-csp`

This package simplifies the process of adding CSP headers by allowing policy-based definitions.


**Step 2: Publish the configuration file**


`php artisan vendor:publish --provider="Spatie\Csp\CspServiceProvider"`

This generates the config file:\
📄 `config/csp.php`


**Step 3: Create a custom CSP policy**\
Create this file:\
📄 `app/Csp/CustomPolicy.php`


```
php
namespace App\Csp;
use Spatie\Csp\Policies\Policy;
use Spatie\Csp\Directive;
use Spatie\Csp\Keyword;

class CustomPolicy extends Policy
{
    public function configure()
    {
        $this
            ->addDirective(Directive::DEFAULT_SRC, [Keyword::SELF])
            ->addDirective(Directive::SCRIPT_SRC, [Keyword::SELF, 'https://cdnjs.cloudflare.com'])
            ->addDirective(Directive::STYLE_SRC, [Keyword::SELF, 'https://fonts.googleapis.com'])
            ->addDirective(Directive::IMG_SRC, [Keyword::SELF, 'data:']) // allow base64 images
            ->addDirective(Directive::CONNECT_SRC, [Keyword::SELF]);
    }
}
```


> This policy restricts most resource loading to the same origin (`'self'`), with specific exceptions (e.g., CDNs).


**Step 4: Register your policy in the config**\
Open `config/csp.php` and set the custom policy:

php

`'policy' => App\Csp\CustomPolicy::class,`


**Step 5: Register the middleware**\
In `app/Http/Kernel.php`, register the middleware globally by adding:

php


`\Spatie\Csp\AddCspHeaders::class,`

to the `$middleware` array.

This middleware will automatically inject the `Content-Security-Policy` header into every HTTP response.


**Expected Result:**\
When visiting any route, your app should respond with a CSP header like:

`Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self'`

---

### Missing Anti-clickjacking Header

**Severity:** Medium\
**Confidence:** Medium

**Description:**\
The page response does not include any protection against **clickjacking** --- a form of attack where the web page is embedded inside a hidden or transparent iframe on a malicious site. The attacker tricks users into clicking something they didn't intend to (e.g., "Delete", "Pay", or "Submit").

**Affected URL:** <http://studentrepo.iium.edu.my>

**Business Impact:**\
Without anti-clickjacking protection, your app can be embedded into another site using an `<iframe>`, potentially leading to unauthorized actions triggered by user clicks, especially on sensitive components like buttons or forms.

**Recommendation:**\
To prevent this, restrict iframe embedding by either:

-   Using the legacy `X-Frame-Options: DENY` header

-   Or using the modern and CSP-based `frame-ancestors 'none'` directive

> ✅ Since CSP is already being used (via Spatie), we recommend enforcing iframe protection through `frame-ancestors`.

**OWASP Reference:**\
<https://owasp.org/www-community/attacks/Clickjacking>

* * * * *

#### 🛠️ Remediation Steps for Developers

**Approach:** Add the `frame-ancestors` directive using the same custom CSP policy.

**Step 1: Update `app/Csp/CustomPolicy.php`**\
Add the following directive in the `configure()` method:

`$this->addDirective(Directive::FRAME_ANCESTORS, [Keyword::NONE]);`

> This directive tells the browser **not to allow the page to be embedded** in any `<iframe>`, effectively blocking all clickjacking attempts.

Optional:\
If your application legitimately needs to be embedded (e.g., in your own domain), you can use:

`$this->addDirective(Directive::FRAME_ANCESTORS, ["'self'"]);`

**Step 2: No further steps required**\

The middleware is already active from the CSP setup. The new directive will be included in the existing `Content-Security-Policy` header automatically.

**Expected Result:**\
Response header now includes:

`Content-Security-Policy: frame-ancestors 'none';`

- This prevents the page from being displayed in any iframe, stopping clickjacking.

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


---
[Information Disclosure] - Error Messages & Internal Info
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

---
🍪 [Cookie Security]
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
  - http://studentrepo.iium.edu.my 
- **ZAP Version:** 2.16.1  
- **Total Alerts Analyzed:** 17

