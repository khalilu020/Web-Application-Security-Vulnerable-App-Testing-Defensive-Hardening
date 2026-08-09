<?php
/**
 * FINDING 4: Stored Cross-Site Scripting — Remediation
 * Original vulnerable file: vulnerabilities/xss_s/source/low.php
 *
 * VULNERABLE (BEFORE):
 * ---------------------
 *   $message = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $message );
 *   $name    = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $name );
 *   $query   = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
 *
 * PROBLEM:
 * mysqli_real_escape_string() only protects against SQL injection — it
 * escapes characters like single quotes that matter to SQL syntax. It
 * does NOTHING to protect against XSS, because HTML-dangerous characters
 * like < and > are irrelevant to SQL and pass through untouched.
 *
 * The Name field's stored value was later rendered without any HTML
 * output encoding, while (in this DVWA build) the Message field
 * happened to be output-encoded elsewhere — an inconsistent, accidental
 * protection rather than a deliberate policy.
 *
 * FIX: Apply htmlspecialchars() to BOTH fields at OUTPUT/RENDER time.
 * This is a distinct step from the SQL-escaping already applied at
 * input/storage time — the two protect against different things.
 */

// --- Storage (input time) — SQL-injection protection, unchanged ---
if( isset( $_POST[ 'btnSign' ] ) ) {
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    $message = stripslashes( $message );
    $message = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $message );
    $name    = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $name );

    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query );
}

/**
 * FIXED — Rendering (output time) — XSS protection, added.
 * This is the part of the code that was missing/inconsistent. Wherever
 * guestbook entries are looped and displayed (typically in the module's
 * index.php), both fields must be HTML-encoded at the point of output:
 */
function render_guestbook_entry($row) {
    $safe_name    = htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
    $safe_comment = htmlspecialchars($row['comment'], ENT_QUOTES, 'UTF-8');
    echo "<p><strong>{$safe_name}</strong>: {$safe_comment}</p>";
}

/**
 * KEY TAKEAWAY:
 * SQL-injection sanitization (mysqli_real_escape_string) and XSS output
 * encoding (htmlspecialchars) solve two completely different problems,
 * applied at two different points in the data flow (input/storage vs.
 * output/render). Neither is a substitute for the other.
 */
?>
