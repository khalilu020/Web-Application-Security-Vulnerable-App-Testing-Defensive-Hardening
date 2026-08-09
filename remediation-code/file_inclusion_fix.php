<?php
/**
 * FINDING 8: Local File Inclusion (LFI) — Remediation
 * Original vulnerable file: vulnerabilities/fi/source/low.php
 *
 * VULNERABLE (BEFORE):
 * ---------------------
 *   $file = $_GET[ 'page' ];
 *   // ... later passed directly to include($file) in the module's
 *   // shared index.php, with zero validation ...
 *
 * PROBLEM:
 * The 'page' parameter is taken directly from user input with no
 * restriction on what characters or paths are allowed. Directory
 * traversal sequences (../) let an attacker "escape" the intended
 * directory entirely and reach arbitrary filesystem paths, e.g.:
 *
 *   ?page=../../../../../../etc/passwd
 *
 * In this assessment, this specific technique was used to read
 * /etc/passwd, which — due to this lab's co-located target/SIEM
 * architecture — incidentally also revealed the presence of Wazuh
 * service accounts on the same host. See LAB_ARCHITECTURE.md.
 *
 * FIX: Allow-list of explicitly permitted values, below.
 */

// FIXED — allow-list (whitelist) of the ONLY values this parameter is
// ever legitimately allowed to hold. This is a stronger pattern than
// trying to detect and block malicious input (blacklisting), because
// it doesn't require anticipating every possible bypass technique
// (encoded traversal sequences, absolute paths, null bytes, alternate
// separators, etc.) — anything not explicitly on the list is rejected,
// full stop.
$allowed_pages = array( 'include.php', 'file1.php', 'file2.php', 'file3.php' );

$file = $_GET[ 'page' ];

if( !in_array( $file, $allowed_pages, true ) ) {
    // Reject anything not explicitly permitted; fall back to a safe
    // default rather than attempting to "clean" the malicious input.
    $file = 'include.php';
}

// $file is now guaranteed to be one of the four known-safe values
// before it is ever passed to include().

/**
 * KEY TAKEAWAY:
 * Whitelisting vs. blacklisting is a general security design principle,
 * not specific to file inclusion. Wherever user input controls a file
 * path, an include/require target, a redirect destination, or similar
 * sensitive operation, prefer "only allow known-good values" over
 * "try to block known-bad patterns."
 */
?>
