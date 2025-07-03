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

[CSP Specific] - Content Security Policy Related Only

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



#### Remediation Steps for Developers

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

>  Since CSP is already being used (via Spatie), we recommend enforcing iframe protection through `frame-ancestors`.

**OWASP Reference:**\
<https://owasp.org/www-community/attacks/Clickjacking>


####  Remediation Steps for Developers

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
1.
###  X-Content-Type-Options Header Missing

**Severity:** Low\
**Confidence:** Medium\
**Affected URL:** `http://studentrepo.iium.edu.my`


#### Description:

The application does not include the `X-Content-Type-Options` HTTP header. Without it, browsers are allowed to perform MIME-type sniffing, potentially interpreting files as a different MIME type than declared.


#### Business Impact:

If an attacker uploads a file with a misleading extension (e.g., `.txt` or `.jpg`) but with malicious JavaScript inside, and the browser "sniffs" and treats it as a script, it could lead to **script execution in the wrong context** --- increasing the risk of XSS and client-side attacks.



####  Recommendation:

Set the following HTTP header on all responses:


`X-Content-Type-Options: nosniff`

This prevents the browser from guessing the MIME type, forcing it to follow the server-declared `Content-Type`.


**OWASP Reference:**\
🔗 <https://owasp.org/www-project-secure-headers/#x-content-type-options>


### Remediation in Laravel

#### Step 1: Create Middleware

`php artisan make:middleware AddSecurityHeaders`

File generated at:

`app/Http/Middleware/AddSecurityHeaders.php`


#### Step 2: Add the Header Logic



```
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AddSecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Prevent MIME-type sniffing by browser
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        return $response;
    }
}
```


#### Step 3: Register the Middleware Globally

In `app/Http/Kernel.php`, add to the `$middleware` array:


`\App\Http\Middleware\AddSecurityHeaders::class,`


#### Result:

Every response will now include:

`X-Content-Type-Options: nosniff`

-You can verify this by inspecting HTTP response headers in browser dev tools → **Network tab → Headers**.

---

2.
###  Strict-Transport-Security Header Not Set

**Severity:** Low\
**Confidence:** High\
**Affected URL:** `http://studentrepo.iium.edu.my`



####  Description:

The application does not return the `Strict-Transport-Security` (HSTS) HTTP header. This header is used to tell browsers that the site should only be accessed over **secure HTTPS connections**, and to prevent any attempts to downgrade to HTTP.



#### Business Impact:

Without the HSTS header:

-   Users might connect over **insecure HTTP** if they manually type the URL or click a non-HTTPS link.

-   This leaves users vulnerable to **SSL stripping attacks**, where attackers intercept and downgrade the connection to plaintext.



####  Recommendation:

Send the following header with **all HTTPS responses**:

`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

-   `max-age=31536000` = 1 year

-   `includeSubDomains` = applies to all subdomains

-   `preload` = allows the domain to be added to browser preload lists (optional but recommended)

**OWASP Reference:**\
🔗 <https://owasp.org/www-project-secure-headers/#strict-transport-security>


###  Remediation in Laravel

This fix should only apply to **HTTPS connections**. So make sure your site is already using HTTPS (with a valid SSL certificate) before enforcing HSTS.


#### Step 1: Reuse or Extend Existing Middleware

If you've already created the `AddSecurityHeaders` middleware (from the previous `nosniff` fix), just **add** the following line:

`$response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');`

So your updated `handle()` method becomes:

```
public function handle(Request $request, Closure $next): Response
{
    $response = $next($request);

    $response->headers->set('X-Content-Type-Options', 'nosniff');
    $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

    return $response;
}
```

>  Optional: You can wrap it in a condition to apply only when HTTPS is used:

```
if ($request->isSecure()) {
    $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
}
```

#### Step 2: Middleware Already Registered

As long as your `AddSecurityHeaders` middleware is registered globally in `app/Http/Kernel.php` under `$middleware`, you're good to go:


`\App\Http\Middleware\AddSecurityHeaders::class,`


#### Result:

Once implemented, HTTPS responses will include:

`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

-You can verify this in browser dev tools or with tools like [securityheaders.com](https://securityheaders.com/).

---

3.
### Server Leaks Version Information via 'Server' HTTP Header

**Severity:** Low\
**Confidence:** High\
**Affected URL:** `http://studentrepo.iium.edu.my`


#### 📄 Description:

The application exposes the underlying **web server type and version** via the `Server` HTTP response header. For example:

`Server: Apache/2.4.54 (Ubuntu)`

This header is automatically sent by most web servers (e.g., Apache, Nginx) unless explicitly disabled.


####  Business Impact:

Disclosing the server type and version makes it easier for attackers to:

-   **Fingerprint** the application stack

-   Identify known vulnerabilities specific to that version

-   Target automated exploits based on the server version


####  Recommendation:

**Suppress or obfuscate** the `Server` header in your web server configuration (not in Laravel).


### 🛠️ Remediation (Web Server Level)

####  If you're using Apache:

Edit your Apache configuration (e.g., `apache2.conf` or a relevant `.conf` site file):

1.  Disable server signature and server tokens:


`ServerSignature Off
ServerTokens Prod`

This will make the `Server` header look like:

`Server: Apache`

Or if you want to remove it completely, use a reverse proxy or security module (see below).

2.  Restart Apache:

`sudo systemctl restart apache2`


#### If you're using Nginx:

Edit your `nginx.conf` file or site config:

`server {
    ...
    server_tokens off;
}`

Then reload Nginx:

`sudo nginx -s reload`

To fully remove or mask the header, consider using a reverse proxy like **Cloudflare**, or **mod_headers** (Apache) / **headers_more** (Nginx) modules.

---
4.  
### Server Leaks Information via `X-Powered-By` HTTP Header

**Severity:** Low\
**Confidence:** Medium\
**Affected URL:** `http://studentrepo.iium.edu.my`


#### 📄 Description:

The application includes the `X-Powered-By` HTTP response header, which reveals internal details about the technology stack, such as the PHP version:

`X-Powered-By: PHP/8.2.9`

This header is typically sent by the PHP engine (or other language runtimes) unless explicitly disabled.


####  Business Impact:

Revealing the technology version and platform exposes the application to:

-   **Targeted attacks** based on known vulnerabilities for that specific PHP version or framework.

-   Easier fingerprinting for automated scanners and botnets.


####  Recommendation:

Disable the `X-Powered-By` header entirely to prevent technology leakage.


### 🛠️ Remediation Steps (PHP & Laravel)

Laravel itself doesn't add this header. It's sent by PHP and needs to be turned off in the **php.ini** configuration.


#### Step 1: Locate your `php.ini` file

This file is usually found at:

-   `/etc/php/8.x/apache2/php.ini` (for Apache)

-   `/etc/php/8.x/fpm/php.ini` (for Nginx + PHP-FPM)

You can confirm the location by running:

`php --ini`


#### Step 2: Disable `X-Powered-By` in `php.ini`

Find this line:

`expose_php = On`

Change it to:

`expose_php = Off`


#### Step 3: Restart your web server

Depending on what you're using:

`# Apache
sudo systemctl restart apache2`

`# Nginx + PHP-FPM
sudo systemctl restart php8.x-fpm
sudo systemctl reload nginx`


#### Result:

After this, the `X-Powered-By` header will be removed from all HTTP responses.

You can verify it via browser dev tools or cURL:

`curl -I http://studentrepo.iium.edu.my`

You should no longer see:

`X-Powered-By: PHP/8.2.9`


---
[Information Disclosure] - Error Messages & Internal Info

### Improper Error Handling and Debug Information Disclosure

**Severity:** Low\
**Confidence:** Medium\
**Affected URL(s):**

-   `http://studentrepo.iium.edu.my`

-   `https://studentrepo.iium.edu.my/server/opensearch/search?format=rss&query=*&scope=...`

#### Description:

The application reveals detailed **internal error messages** in HTTP responses. These include:

-   PHP stack traces

-   Exception class names

-   Function/method names

-   Full file system paths

-   SQL error messages

This behavior is often caused by:

-   The Laravel application running with `APP_DEBUG=true`

-   Unhandled exceptions that bubble up to the UI

-   Debug mode misconfiguration in production



#### Business Impact:

Exposing internal error details provides attackers with useful insight into the application's structure and logic, such as:

-   File locations

-   Backend technologies

-   Query structures

-   Vulnerable endpoints

This makes the app more susceptible to targeted attacks like SQL injection, file inclusion, and logic exploitation.


#### Recommendation:

1.  **Disable debug mode** in production:

    -   Ensure `.env` file contains:

        `APP_ENV=production
        APP_DEBUG=false`

2.  **Customize user-facing error pages**:

    -   Blade templates in `resources/views/errors/` should return **non-technical messages**, such as:

        `An unexpected error occurred. Please try again later.`

3.  **Avoid exposing exception messages** in API responses:

    -   In `app/Exceptions/Handler.php`, override the `render()` method:

        ```
        public function render($request, Throwable $exception)
        {
            if ($request->expectsJson()) {
                return response()->json([
                    'message' => 'An internal error occurred.'
                ], 500);
            }

            return parent::render($request, $exception);
        }
        
        ```
4.  **Log sensitive details internally**:

    -   Laravel logs errors automatically to `storage/logs/laravel.log`.

    -   Make sure logging is enabled but not exposed to the frontend.


#### OWASP Reference:

-   [https://owasp.org/www-community/Improper_Error_Handling](https://owasp.org/www-community/Improper_Error_Handling)
---

🍪 [Cookie Security]
### Cookie with `SameSite=None` Attribute

**Severity:** Low\
**Confidence:** Medium\
**Affected URL:** `http://studentrepo.iium.edu.my`


####  Description:

Cookies set by the application have the attribute `SameSite=None`, **without the `Secure` flag**, or are missing the `SameSite` attribute entirely. This allows the browser to send those cookies in **cross-site requests**, which can lead to **Cross-Site Request Forgery (CSRF)** and session hijacking risks.

Example of risky cookie setting:

`Set-Cookie: session_id=abc123; SameSite=None`


####  Business Impact:

If a user is authenticated and visits a malicious site, that site may trigger cross-site requests to the application with valid session cookies. Without `SameSite=Lax` or `Strict`, the browser **will send the cookies**, making **CSRF attacks possible**.


####  Recommendation:

Update your application to set the `SameSite` attribute properly. Recommended settings:


`Set-Cookie: session_id=abc123; SameSite=Strict; Secure`

-   Use `SameSite=Lax` for most cases (e.g., Laravel sessions).

-   Use `SameSite=Strict` for highly sensitive operations (e.g., admin).

-   Always use `Secure` if cookies are transmitted over HTTPS.


####  OWASP Reference:

-   [https://owasp.org/www-community/controls/SameSite](https://owasp.org/www-community/controls/SameSite)


### Remediation in Laravel

Laravel handles session cookies via configuration in `config/session.php`.


#### Step 1: Configure `SameSite` in `config/session.php`

Set this:

`'samesite' => 'lax', // or 'strict' if needed`

Other related settings to check:

`'secure' => env('SESSION_SECURE_COOKIE', true),`

This ensures cookies are sent only via HTTPS.


#### Step 2: Set in `.env`

`SESSION_SECURE_COOKIE=true`

> This makes sure the `Secure` flag is always added to the session cookie.

#### Result:

Laravel will now send cookies like this:

`Set-Cookie: laravel_session=abc123; path=/; HttpOnly; Secure; SameSite=Lax`

This helps **mitigate CSRF** by restricting cross-origin cookie sending.

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

