<?php
echo "<h1>Victim Server 3 - Cache Server</h1>";
echo "<p>Server Status: Online</p>";
echo "<p>Redis Honeypot Running on port 6379</p>";
echo "<p>System: " . php_uname() . "</p>";
?>
<div style="border:1px solid #ccc;padding:10px;margin:10px 0">
    <h3>Redis Info</h3>
    <p>Host: victim3</p>
    <p>Port: 6379</p>
    <p>Protected Mode: Disabled (honeypot)</p>
    <p><small>All Redis commands are logged for analysis</small></p>
</div>
<div style="background:#fffacd;padding:10px;margin:10px 0">
    <h3>Common Redis Commands</h3>
    <pre>
redis-cli -h victim3
INFO
KEYS *
GET key
SET key value
    </pre>
</div>
