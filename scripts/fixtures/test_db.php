<?php
$conn = @mysqli_connect('172.19.0.2', 'root', '', 'pikachu');
echo $conn ? "OK\n" : mysqli_connect_error() . "\n";
?>
