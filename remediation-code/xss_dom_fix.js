/**
 * FINDING 5: DOM-based Cross-Site Scripting — Remediation
 * Original vulnerable logic: vulnerabilities/xss_d (client-side JavaScript)
 *
 * VULNERABLE (BEFORE):
 * ---------------------
 *   if (document.location.href.indexOf("default=") >= 0) {
 *       var lang = document.location.href.substring(
 *           document.location.href.indexOf("default=") + 8
 *       );
 *       document.write("<option value='" + lang + "'>" + lang + "</option>");
 *   }
 *
 * PROBLEM:
 * This vulnerability is entirely client-side — the server response is
 * never "poisoned." The page's own JavaScript reads the 'default' URL
 * parameter (fully attacker-controllable) and inserts it directly into
 * the page as raw HTML via document.write(), with zero encoding. The
 * browser's HTML parser then treats any <script> tags in that string as
 * real, executable markup.
 *
 * This is why DOM XSS is not caught by server-side defenses (input
 * validation, WAF rules inspecting the request) — the malicious payload
 * never needs to be processed by server logic at all.
 *
 * FIX: Build the DOM element programmatically and use .textContent,
 * which ALWAYS treats its value as plain text — never as markup to be
 * parsed, no matter what characters it contains.
 */

if (document.location.href.indexOf("default=") >= 0) {
    var lang = document.location.href.substring(
        document.location.href.indexOf("default=") + 8
    );
    lang = decodeURIComponent(lang);

    // FIXED — createElement + textContent instead of document.write()
    // with a raw HTML string.
    var option = document.createElement("option");
    option.value = lang;         // treated as a plain attribute value
    option.textContent = lang;   // ALWAYS rendered as literal text,
                                  // never parsed as HTML/JS — this is
                                  // the client-side equivalent of
                                  // htmlspecialchars() on the server.

    document.getElementById("langSelect").appendChild(option);
}

/**
 * KEY TAKEAWAY:
 * innerHTML / document.write() interpret their argument as HTML markup.
 * textContent interprets its argument as plain text, unconditionally.
 * Any time untrusted data is inserted into the DOM, textContent (or an
 * equivalent safe API) should be used unless there is a specific,
 * carefully-sanitized reason to insert HTML.
 */
