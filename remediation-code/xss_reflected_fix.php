<?php
/**
 * FINDING 3: Reflected Cross-Site Scripting — Remediation
 * Original vulnerable file: vulnerabilities/xss_r/source/low.php
 *
 * VULNERABLE (BEFORE):
 * ---------------------
 *   if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
 *       echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
 *   }
 *
 * PROBLEM:
 * The 'name' parameter is echoed directly into the page's HTML with zero
 * encoding. Whatever the user submits becomes literal HTML in the
 * response — including <script> tags, which the browser will parse and
 * execute as real markup, not display as text.
 *
 * FIX: htmlspecialchars() below.
 */

header ("X-XSS-Protection: 0");

if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {

    // FIXED — htmlspecialchars() converts HTML-significant characters
    // into their harmless entity equivalents before insertion:
    //   <  ->  &lt;
    //   >  ->  &gt;
    //   "  ->  &quot;
    //   '  ->  &#039;   (because ENT_QUOTES is passed)
    //
    // The browser then displays the submitted value as literal visible
    // text (e.g. the user sees the characters "<script>..." on screen)
    // instead of parsing it as an executable <script> tag.
    echo '<pre>Hello ' . htmlspecialchars( $_GET[ 'name' ], ENT_QUOTES, 'UTF-8' ) . '</pre>';
}
?>
