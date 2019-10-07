<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
  <title>
    Security Analytics
  </title>
  <meta content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0, shrink-to-fit=no' name='viewport' />
  <!--     Fonts and icons     -->
  <link href="https://fonts.googleapis.com/css?family=Montserrat:400,700,200" rel="stylesheet" />
  <link href="https://maxcdn.bootstrapcdn.com/font-awesome/latest/css/font-awesome.min.css" rel="stylesheet">
  <!-- CSS Files -->
  <link href="css/bootstrap.min.css" rel="stylesheet"/>
  <link href="css/frame.css" rel="stylesheet"/>
</head>
<script type="text/javascript">
function openCity(evt, cityName) {
  // Declare all variables
  var i, tabcontent, tablinks;

  // Get all elements with class="tabcontent" and hide them
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }

  // Get all elements with class="tablinks" and remove the class "active"
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }

  // Show the current tab, and add an "active" class to the button that opened the tab
  document.getElementById(cityName).style.display = "block";
  evt.currentTarget.className += " active";
}
</script>
<body class="">
  <div class="wrapper ">
    <div class="sidebar" data-color="white" data-active-color="danger">
      <!--
        Tip 1: You can change the color of the sidebar using: data-color="blue | green | orange | red | yellow"
    -->
    <div class="logo">
        <a href="http://www.creative-tim.com" class="simple-text logo-mini">
          <div class="logo-image-small">
            <img src="../assets/img/logo-small.png">
          </div>
        </a>
        <a href="http://www.creative-tim.com" class="simple-text logo-normal">
        Protein
          <!-- <div class="logo-image-big">
            <img src="../assets/img/logo-big.png">
          </div> -->
        </a>
      </div>
      <div class="sidebar-wrapper">
        <ul class="nav">
          <li class="active ">
            <a href="./index.php">
              <i class="nc-icon nc-bank"></i>
              <p>Dashboard</p>
            </a>
          </li>
          <li>
            <a href="./CreateCase.php">
              <i class="nc-icon nc-diamond"></i>
              <p>Create Case</p>
            </a>
          </li>
          <li>
            <a href="./ViewCase.php">
              <i class="nc-icon nc-pin-3"></i>
              <p>View Case</p>
            </a>
          </li>
        </ul>
      </div>
    </div>
    <div class="main-panel">
      <!-- Navbar -->
      <nav class="navbar navbar-expand-lg navbar-absolute fixed-top navbar-transparent">
        <div class="container-fluid">
          <div class="navbar-wrapper">
            <div class="navbar-toggle">
              <button type="button" class="navbar-toggler">
                <span class="navbar-toggler-bar bar1"></span>
                <span class="navbar-toggler-bar bar2"></span>
                <span class="navbar-toggler-bar bar3"></span>
              </button>
            </div>
            <a class="navbar-brand">ICT3204 - Security Analytics</a>
          </div>
          
        </div>
      </nav>
      <!-- End Navbar -->
      <!-- <div class="panel-header panel-header-lg">

  <canvas id="bigDashboardChart"></canvas>


</div> -->
      <div class="content">
        <div class="row">
          <div class="col-lg-3 col-md-6 col-sm-6">
            <div class="card card-stats">
              <div class="card-body ">
                <div class="row">
                  <div class="col-5 col-md-4">
                    <div class="icon-big text-center icon-warning">
                      <i class="nc-icon nc-globe text-warning"></i>
                    </div>
                  </div>
                  <div class="col-7 col-md-8">
                    <div class="numbers">
                      <p class="card-category">Action Detected</p>
                      <p class="card-title">?
                        <p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div class="col-lg-3 col-md-6 col-sm-6">
            <div class="card card-stats">
              <div class="card-body ">
                <div class="row">
                  <div class="col-5 col-md-4">
                    <div class="icon-big text-center icon-warning">
                      <i class="nc-icon nc-money-coins text-success"></i>
                    </div>
                  </div>
                  <div class="col-7 col-md-8">
                    <div class="numbers">
                      <p class="card-category">Predicted Attack</p>
                      <p class="card-title">????
                        <p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div class="col-lg-3 col-md-6 col-sm-6">
            <div class="card card-stats">
              <div class="card-body ">
                <div class="row">
                  <div class="col-5 col-md-4">
                    <div class="icon-big text-center icon-warning">
                      <i class="nc-icon nc-vector text-danger"></i>
                    </div>
                  </div>
                  <div class="col-7 col-md-8">
                    <div class="numbers">
                      <p class="card-category">Attack Duration</p>
                      <p class="card-title">
                        <p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
         
        </div>
        <div class="nav nav-tabs">
            <button class="btn btn-primary btn-round">Summary</button>
            <button class="btn btn-primary btn-round" onclick="openCity(event, 'Scanning')">Scanning Attempts</button>
            <button class="btn btn-primary btn-round" onclick="openCity(event, 'Brute')">Brute Force Attempts</button>
            <button class="btn btn-primary btn-round" onclick="openCity(event, 'Login')">Successful Logins by Bruteforcers</button>
            <button class="btn btn-primary btn-round" onclick="openCity(event, 'Shell')">Shell Upload</button>
            <button class="btn btn-primary btn-round" onclick="openCity(event, 'Defacement')">Web Defacement</button>
        </div>
        <div id="Scanning" class="tabcontent">
            <h1>Wireshark network capture:</h1>
            TABLE HERE
            <h1>Interesting findings:</h1>
            FINDINGS HERE
        </div>
        <div id="Brute" class="tabcontent">
            <h1>Bruteforce capture:</h1>
            TABLE HERE
            <h1>Interesting findings:</h1>
            FINDINGS HERE
        </div>
        <div id="Login" class="tabcontent">
            <h1>Login capture:</h1>
            TABLE HERE
            <h1>Interesting findings:</h1>
            FINDINGS HERE
        </div>
        <div id="Shell" class="tabcontent">
            <h1>Shell capture:</h1>
            TABLE HERE
            <h1>Interesting findings:</h1>
            FINDINGS HERE
        </div>
        <div id="Defacement" class="tabcontent">
            <h1>Audit Log:</h1>
            TABLE HERE
            <h1>Apache Access Log:</h1>
            TABLE HERE
            <h1>Interesting findings:</h1>
            FINDINGS HERE
        </div>
      </div>
    </div>
  </div>
  
</body>

</html>
