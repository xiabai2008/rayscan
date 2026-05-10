<?php
$fp = @fsockopen("172.19.0.2", 3306, $errno, $errstr, 3);
if ($fp) {
    echo "Connected to 172.19.0.2:3306\n";
    fclose($fp);
} else {
    echo "Failed: $errstr ($errno)\n";
}
?>
