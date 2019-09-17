<?php
session_start();


if(empty($_SESSION))
{
	header("Location: login.php");
	exit();
}else{

	$name = $_SESSION['name'];
}



$host = "localhost";
$user = "root";
$pass = "";
$db = "vulndb";
$error = "Username or Password Wrong.";

$dbconn = new mysqli($host, $user, $pass, $db);

$sql2 = "SELECT id FROM users WHERE name='".$name."'";
$result2 = mysqli_query($dbconn, $sql2);
$row2 = mysqli_fetch_assoc($result2);

$userid = $row2['id'];




$target_dir = "uploads/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));
// Check if image file is a actual image or fake image
if(isset($_POST["submit"])) {
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if($check !== false) {
        echo "File is an image - " . $check["mime"] . ".";
        $uploadOk = 1;
    } else {
        echo "File is not an image.";
        $uploadOk = 1;
    }
}
// Check if file already exists
if (file_exists($target_file)) {
	echo "Sorry, file already exists.";
	echo $target_file;
    $uploadOk = 0;
}
// Check file size
if ($_FILES["fileToUpload"]["size"] > 50000000) {
    echo "Sorry, your file is too large.";
    $uploadOk = 0;
}

// Check if $uploadOk is set to 0 by an error
if ($uploadOk == 0) {
    echo "Sorry, your file was not uploaded.";
// if everything is ok, try to upload file
} else {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "The file ". basename( $_FILES["fileToUpload"]["name"]). " has been uploaded.";
    } else {
        echo "Sorry, there was an error uploading your file.";
    }
}

$query = $dbconn -> prepare("INSERT INTO image (filepath) VALUES (?)");
$query -> bind_param("s",$target_file);
$query -> execute();
$query -> store_result();
header("Location: home.php");
?>