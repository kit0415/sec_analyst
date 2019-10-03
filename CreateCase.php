<!DOCTYPE html>
<html lang="en">

  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <title>
      Security Analytics
    </title>
    <meta content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0, shrink-to-fit=no'
      name='viewport' />
    <!--     Fonts and icons     -->
    <link href="https://fonts.googleapis.com/css?family=Montserrat:400,700,200" rel="stylesheet" />
    <link href="https://maxcdn.bootstrapcdn.com/font-awesome/latest/css/font-awesome.min.css" rel="stylesheet">
    <!-- CSS Files -->
    <link href="css/bootstrap.min.css" rel="stylesheet" />
    <link href="css/frame.css" rel="stylesheet" />
  </head>

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
            <li>
              <a href="./index.php">
                <i class="nc-icon nc-bank"></i>
                <p>Dashboard</p>
              </a>
            </li>
            <li class="active ">
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
            <li>
              <a href="./CreateCommand.php">
                <i class="nc-icon nc-bell-55"></i>
                <p>Create Command</p>
              </a>
            </li>
            <li>
              <a href="./ViewCommand.php">
                <i class="nc-icon nc-single-02"></i>
                <p>View Command</p>
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
          <div class="col-md-8">
            <div class="card card-user">
              <div class="card-header">
                <h5 class="card-title">Opening a New Case</h5>
              </div>
              <div class="card-body">
                <form action="uploadCase.php" method="post" enctype="multipart/form-data">
                  <div class="row">
                    <div class="col-md-5 pr-1">
                      <div class="form-group">
                        <label>Case ID</label>
                        <input type="text" name="caseID" class="form-control">
                      </div>
                    </div>
                  </div>
                  <div class="row">
                    <div class="col-md-4 pr-2">
                      <label>Select Files to upload:</label>
                      <input type="file" name="file[]">
                    </div>
                  </div>
                  <br>
                  <div class="row">
                    <div class="col-md-12">
                      <div class="form-group">
                        <label>Comments</label>
                        <textarea class="form-control textarea" name="caseDesc"></textarea>
                      </div>
                    </div>
                  </div>
                  <div class="row">
                    <div class="update ml-auto mr-auto">
                      <button type="submit" class="btn btn-primary btn-round" name="submit">Upload Case</button>
                    </div>
                  </div>
                </form>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>

  </body>

</html>