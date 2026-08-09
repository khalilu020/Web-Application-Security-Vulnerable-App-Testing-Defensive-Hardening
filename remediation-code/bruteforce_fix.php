<?php
/**
 * FINDING 6: No Brute-Force Protection — Remediation
 * Original vulnerable file: vulnerabilities/brute/source/low.php
 *
 * VULNERABLE (BEFORE):
 * ---------------------
 *   $user = $_GET[ 'username' ];
 *   $pass = md5( $_GET[ 'password' ] );
 *   $query = "SELECT * FROM users WHERE user = '$user' AND password = '$pass';";
 *   $result = mysqli_query($GLOBALS["___mysqli_ston"], $query );
 *   if( mysqli_num_rows( $result ) == 1 ) { ... success ... }
 *   else { ... "Username and/or password incorrect." ... }
 *
 * PROBLEMS (two distinct issues in the same file):
 *   1. Same SQL Injection flaw as Finding 1 — $user and $pass are
 *      concatenated directly into the query.
 *   2. No attempt-limiting logic whatsoever. Every request is evaluated
 *      completely independently — nothing tracks how many times a
 *      given session has failed, so unlimited password guessing is
 *      possible with zero resistance.
 *
 * FIX: Parameterized query (same technique as Finding 1) PLUS
 * session-based attempt tracking with a temporary lockout.
 */

if( isset( $_GET[ 'Login' ] ) ) {

    $user = stripslashes( $_GET[ 'username' ] );
    $pass = md5( stripslashes( $_GET[ 'password' ] ) );

    // FIXED — brute-force protection: track failed attempts per session
    if( !isset( $_SESSION['login_attempts'] ) ) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['lockout_time']   = 0;
    }

    // Check if currently locked out from a previous burst of failures
    if( $_SESSION['login_attempts'] >= 3 && time() < $_SESSION['lockout_time'] ) {
        $wait = $_SESSION['lockout_time'] - time();
        echo "<pre>Too many failed attempts. Try again in {$wait} seconds.</pre>";
        exit;
    }

    // FIXED — parameterized query (same technique as sqli_fix.php)
    $stmt = mysqli_prepare(
        $GLOBALS["___mysqli_ston"],
        "SELECT * FROM users WHERE user = ? AND password = ?"
    );
    mysqli_stmt_bind_param($stmt, "ss", $user, $pass);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Successful login — reset the failure counter
        $_SESSION['login_attempts'] = 0;

        $row    = mysqli_fetch_assoc( $result );
        $avatar = $row["avatar"];
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    } else {
        // Failed login — increment the counter and lock out after 3
        $_SESSION['login_attempts']++;
        if( $_SESSION['login_attempts'] >= 3 ) {
            $_SESSION['lockout_time'] = time() + 30; // 30-second lockout
            echo "<pre>Too many failed attempts. Account locked for 30 seconds.</pre>";
        } else {
            echo "<pre><br>Username and/or password incorrect.</pre>";
        }
    }
}

/**
 * PRODUCTION NOTE:
 * A production system would typically extend this with: tracking by
 * IP address in addition to session, exponential backoff (doubling
 * lockout duration on repeated triggers), and a CAPTCHA challenge after
 * N attempts. The implementation above demonstrates the core mechanism
 * — persisting and reacting to failure state across requests — which
 * the original code lacked entirely.
 */
?>
