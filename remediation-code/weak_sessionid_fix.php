<?php
/**
 * FINDING 7: Predictable Session Identifiers — Remediation
 * Original vulnerable logic: vulnerabilities/weak_id/source/low.php
 *
 * VULNERABLE (BEFORE):
 * ---------------------
 *   $cookie_value = $last_session_id + 1;   // simple increment
 *   setcookie('dvwaSession', $cookie_value);
 *
 * PROBLEM:
 * The session token is a plain sequential integer (observed sequence:
 * 1, 3, 4). There is no cryptographic randomness involved — any single
 * observed value trivially reveals the entire pattern of past and
 * future values. An attacker can enumerate tokens (try 1, 2, 3, 4, 5...)
 * and potentially land on a value currently assigned to a real user,
 * hijacking their session without ever needing their password.
 *
 * Contrast with DVWA's own PHPSESSID cookie, which IS correctly
 * implemented as a long, random alphanumeric string — proving the
 * correct pattern already exists elsewhere in the same application.
 *
 * FIX: Use a cryptographically secure random source instead.
 */

// FIXED — cryptographically secure random token generation.
//
// random_bytes() draws from the operating system's secure entropy
// source (unlike PHP's older rand()/mt_rand(), which are NOT
// cryptographically secure and can be predicted).
//
// 16 random bytes = 128 bits of entropy = 2^128 possible values.
// This is computationally infeasible to guess or enumerate, unlike the
// original "current value + 1" scheme, where guessing the NEXT valid
// token required zero effort.
$cookie_value = bin2hex(random_bytes(16));

setcookie('dvwaSession', $cookie_value);

/**
 * KEY TAKEAWAY:
 * Any token used for security purposes (session IDs, password reset
 * tokens, API keys, CSRF tokens) must be generated with a
 * cryptographically secure random function. PHP provides random_bytes()
 * and random_int() for exactly this purpose — never use rand(),
 * mt_rand(), or a predictable counter for anything security-relevant.
 */
?>
