<?php
/**
 * FINDING 1: SQL Injection — Remediation
 * Original vulnerable file: vulnerabilities/sqli/source/low.php
 *
 * VULNERABLE (BEFORE):
 * ---------------------
 *   $id = $_REQUEST[ 'id' ];
 *   $query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
 *   $result = mysqli_query($GLOBALS["___mysqli_ston"], $query );
 *
 * PROBLEM:
 * User input is concatenated directly into the SQL query string. The
 * database cannot distinguish "this is a value to search for" from
 * "this is part of the query's structure" — an attacker can close the
 * intended string early and inject arbitrary SQL syntax
 * (e.g. `1' UNION SELECT user, password FROM users-- -`).
 *
 * FIX: Parameterized queries (prepared statements) below.
 */

if( isset( $_REQUEST[ 'Submit' ] ) ) {

    $id = $_REQUEST[ 'id' ];

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:

            // FIXED — prepare the query with a placeholder (?) instead
            // of embedding $id directly into the query string. The
            // database parses the query STRUCTURE first, before any
            // user-supplied value is attached — so nothing the user
            // sends can alter that structure.
            $stmt = mysqli_prepare(
                $GLOBALS["___mysqli_ston"],
                "SELECT first_name, last_name FROM users WHERE user_id = ?"
            );

            // Bind $id as a STRING parameter ("s"). MySQL will treat the
            // entire value as literal data, never as executable SQL —
            // even if it contains quotes, UNION, SELECT, or comment
            // sequences.
            mysqli_stmt_bind_param($stmt, "s", $id);

            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);

            while( $row = mysqli_fetch_assoc( $result ) ) {
                $first = $row["first_name"];
                $last  = $row["last_name"];
                $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }

            mysqli_stmt_close($stmt);
            mysqli_close($GLOBALS["___mysqli_ston"]);
            break;

        // SQLITE branch intentionally left unmodified — not used in this
        // assessment's configuration (backend was MySQL/MariaDB).
    }
}
?>
