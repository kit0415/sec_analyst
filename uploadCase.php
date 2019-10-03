<?php
include "dbConn.php";

if (isset($_POST['submit'])) {

  $mysql = "INSERT INTO logcases (CaseDescription, pcapLog, accessLog, auditLog)
  VALUES (?,?,?,?)";

  $caseID = $_POST['caseID'];
  $cDesc = $_POST['caseDesc'];
  $date = date("Y-m-d H:i:s");
  $countfiles = count($_FILES['file']['name']);

 // Looping all files
 for($i=0;$i<$countfiles;$i++){
  $filename = $_FILES['file']['name'][$i]; 
  // Upload file
  move_uploaded_file($_FILES['file']['tmp_name'][$i],'data/'.$filename); 
 }

exec("unzip data/".$filename." -d data/");
exec("rm data/".$filename);
$files = scandir("data/");
for ($i=2;$i<count($files)-2;$i++){
    $fileExt = pathinfo($files[$i]);
    switch ($fileExt["extension"]){
        case "pcapng":
            echo "command is python LogAnalysis.py";
            $command = "python command/LogAnalysis.py ".$fileExt["extension"]." ".$fileExt["filename"].".".$fileExt["extension"]." 1 'TCP'";
            echo $command;
            shell_exec($command);
            break;
        case "log":
            if ($fileExt["filename"] == "access"){
                echo "access log";
                $command = "python command/analyse.py data/".$fileExt["filename"];
                shell_exec($command);
            }
            else{
                echo "audit log";  
            }
            break;
        default:
            echo "Error Occur";
        
    }
}
}