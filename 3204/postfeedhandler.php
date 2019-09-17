<?php
session_start();


if(empty($_SESSION))
{
	header("Location: loginpage.php");
	exit();
}else{

	$name = $_SESSION['name'];
}

if (empty($_GET)){
	header("Location: loginpage.php");
	exit();
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

$query = $dbconn -> prepare("INSERT INTO feed (body, userid) VALUES (?,?)");
$query -> bind_param("ss", $_GET['feedbody'], $userid);
$query -> execute();
$query -> store_result();
header("Location: home.php");
?>