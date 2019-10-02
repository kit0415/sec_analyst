<?php
include "dbConn.php";

if (isset($_POST['submit'])) {

  $mysql = "INSERT INTO logcases (CaseDescription, pcapLog, accessLog, auditLog)
  VALUES (?,?,?,?)";




  $target_dir = "logs/";
  $caseID = $_POST['caseID'];
  $pcap = $target_dir . basename($_FILES['pcapUpload']['name']);
  $access = $target_dir . basename($_FILES['accessUpload']['name']);
  $audit = $target_dir . basename($_FILES['auditUpload']['name']);
  $cDesc = $_POST['caseDesc'];
  $date = date("Y-m-d H:i:s");
}