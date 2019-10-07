<?php

include "dbConn.php";

$sql = "select * from logcases order by dateUploaded desc";
$result = $conn->query($sql);
$numOfCase = $result->num_rows;


?>