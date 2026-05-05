<?php
echo "<h1>Victim Server 2 - Database Portal</h1>";
echo "<p>Server Status: Online</p>";
echo "<p>PostgreSQL Honeypot Running on port 5432</p>";
echo "<p>System: " . php_uname() . "</p>";
if (isset($_GET["query"])) {
    echo "<div style='background:#f0f0f0;padding:10px;margin:10px 0'>";
    echo "<h3>SQL Query Input (Demo)</h3>";
    echo "<pre>" . htmlspecialchars($_GET["query"]) . "</pre>";
    echo "</div>";
}
?>
<form method="GET">
    <textarea name="query" rows="5" cols="50" placeholder="Enter SQL query..."></textarea><br>
    <input type="submit" value="Execute">
</form>
<p><small>Note: This is a honeypot. All interactions are logged.</small></p>
