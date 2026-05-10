<?php
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
ini_set('default_socket_timeout', 3);

try {
    $conn = mysqli_connect('172.19.0.2', 'root', '', 'pikachu', 3306);
    echo "OK\n";
    var_dump(mysqli_query($conn, "SHOW TABLES"));
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
