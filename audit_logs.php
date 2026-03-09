<?php 
  session_start(); 

  if (!isset($_SESSION['username'])) {
  	$_SESSION['msg'] = "You must log in first";
  	header('location: login.php');
    exit();
  }
  if (isset($_GET['logout'])) {
      require_once 'config.php';
      if (isset($_SESSION['username'])) {
          logAuthAction($conn, $_SESSION['username'], 'Logout');
      }
  	session_destroy();
  	unset($_SESSION['username']);
  	header("location: login.php");
    exit();
  }

  include 'config.php';
  
  if (isset($_SESSION['user_id'])) {
      $_SESSION['roles'] = getUserRoles($conn, $_SESSION['user_id']);
      $_SESSION['privileges'] = getUserPrivileges($conn, $_SESSION['user_id']);
  }

  $user_roles = $_SESSION['roles'] ?? [];
  $user_privs = $_SESSION['privileges'] ?? [];

  // Security check: Only Admins can access Audit Logs
  if (!in_array('admin', $user_roles)) {
      $_SESSION['error'] = "Unauthorized access to Audit Logs.";
      header('location: index.php');
      exit();
  }

  // Handle Export to CSV
  if (isset($_POST['export_csv'])) {
      $where_clauses = [];
      $params = [];
      $param_idx = 1;

      if (!empty($_POST['filter_username'])) {
          $where_clauses[] = "username ILIKE $" . $param_idx;
          $params[] = '%' . $_POST['filter_username'] . '%';
          $param_idx++;
      }
      if (!empty($_POST['filter_action'])) {
          $where_clauses[] = "action ILIKE $" . $param_idx;
          $params[] = '%' . $_POST['filter_action'] . '%';
          $param_idx++;
      }
      if (!empty($_POST['filter_date_from'])) {
          $where_clauses[] = "log_date >= $" . $param_idx;
          $params[] = $_POST['filter_date_from'];
          $param_idx++;
      }
      if (!empty($_POST['filter_date_to'])) {
          $where_clauses[] = "log_date <= $" . $param_idx;
          $params[] = $_POST['filter_date_to'];
          $param_idx++;
      }

      $where_sql = "";
      if (count($where_clauses) > 0) {
          $where_sql = "WHERE " . implode(" AND ", $where_clauses);
      }

      $query = "SELECT log_date, log_time, username, action FROM audit_log $where_sql ORDER BY log_date DESC, log_time DESC";
      $result = pg_query_params($conn, $query, $params);

      header('Content-Type: text/csv; charset=utf-8');
      header('Content-Disposition: attachment; filename=audit_report_' . date('Y-m-d') . '.csv');
      
      $output = fopen('php://output', 'w');
      fputcsv($output, array('Date', 'Time', 'Username', 'Action'), ',', '"', "\\");

      if ($result) {
          while ($row = pg_fetch_assoc($result)) {
              fputcsv($output, $row, ',', '"', "\\");
          }
      }
      fclose($output);
      exit();
  }

  // Handle Filtering for Display
  $filter_username = $_GET['username'] ?? '';
  $filter_action = $_GET['action'] ?? '';
  $filter_date_from = $_GET['date_from'] ?? '';
  $filter_date_to = $_GET['date_to'] ?? '';

  $where_clauses = [];
  $params = [];
  $param_idx = 1;

  if (!empty($filter_username)) {
      $where_clauses[] = "username ILIKE $" . $param_idx;
      $params[] = '%' . $filter_username . '%';
      $param_idx++;
  }
  if (!empty($filter_action)) {
      $where_clauses[] = "action ILIKE $" . $param_idx;
      $params[] = '%' . $filter_action . '%';
      $param_idx++;
  }
  if (!empty($filter_date_from)) {
      $where_clauses[] = "log_date >= $" . $param_idx;
      $params[] = $filter_date_from;
      $param_idx++;
  }
  if (!empty($filter_date_to)) {
      $where_clauses[] = "log_date <= $" . $param_idx;
      $params[] = $filter_date_to;
      $param_idx++;
  }

  $where_sql = "";
  if (count($where_clauses) > 0) {
      $where_sql = "WHERE " . implode(" AND ", $where_clauses);
  }

  $query = "SELECT id, log_date, log_time, username, action FROM audit_log $where_sql ORDER BY log_date DESC, log_time DESC LIMIT 500";
  $result = pg_query_params($conn, $query, $params);

  // --- CHART DATA QUERIES ---
  
  // 1. Action Distribution (Pie/Doughnut Chart)
  // Simplifying actions into categories for better visualization
  $chart_where_sql = count($where_clauses) > 0 ? "WHERE " . implode(" AND ", $where_clauses) : "";
  $action_dist_query = "
      SELECT 
          CASE 
              WHEN action ILIKE '%Added user%' THEN 'Create User'
              WHEN action ILIKE '%Deleted user%' THEN 'Delete User'
              WHEN action ILIKE '%Updated user%' THEN 'Update User'
              WHEN action ILIKE '%Assigned role%' OR action ILIKE '%Removed role%' THEN 'Role Assignment'
              WHEN action ILIKE '%Assigned privilege%' OR action ILIKE '%Removed privilege%' OR action ILIKE '%Updated privileges%' THEN 'Privilege Assignment'
              WHEN action ILIKE '%Created role%' THEN 'Manage Roles'
              WHEN action ILIKE '%View%' THEN 'View Pages'
              ELSE 'Other'
          END as category,
          COUNT(*) as count
      FROM audit_log
      $chart_where_sql
      GROUP BY category
      ORDER BY count DESC
  ";
  $action_dist_result = pg_query_params($conn, $action_dist_query, $params);
  $action_labels = [];
  $action_counts = [];
  if ($action_dist_result) {
      while($row = pg_fetch_assoc($action_dist_result)) {
          $action_labels[] = $row['category'];
          $action_counts[] = $row['count'];
      }
  }

  // 2. Activity Over Time - Last 7 Days (Bar/Line Chart)
  $date_trend_query = "
      SELECT log_date, COUNT(*) as count 
      FROM audit_log 
      $chart_where_sql
      GROUP BY log_date 
      ORDER BY log_date ASC 
      LIMIT 14
  ";
  $date_trend_result = pg_query_params($conn, $date_trend_query, $params);
  $date_labels = [];
  $date_counts = [];
  if ($date_trend_result) {
      while($row = pg_fetch_assoc($date_trend_result)) {
          $date_labels[] = $row['log_date'];
          $date_counts[] = $row['count'];
      }
  }
?>
<!DOCTYPE html>
<html>
<head>
    <title>Audit Logs & Reports</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .filter-form {
            background: #fff;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            margin-bottom: 24px;
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            align-items: flex-end;
        }
        .filter-group {
            display: flex;
            flex-direction: column;
            flex: 1;
            min-width: 150px;
        }
        .filter-group label {
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 6px;
            color: var(--text-secondary);
        }
        .filter-group input {
            padding: 10px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            outline: none;
            font-family: 'Inter', sans-serif;
        }
    </style>
</head>
<body>
    <div class="container container-large">
        <div class="header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1>Audit Logs & Reports</h1>
                    <p style="margin-top: 4px;">Welcome, <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong></p>
                </div>
                <div style="display: flex; gap: 12px; align-items: center;">
                    <a href="index.php" class="btn btn-secondary" style="background: var(--primary-gradient); padding: 10px 20px;">
                        User Register
                    </a>
                    <a href="roles.php" class="btn btn-secondary" style="background: var(--info); padding: 10px 20px;">
                        Role Management
                    </a>
                    <a href="profile.php" class="btn btn-info">My Profile</a> 
                    <a href="audit_logs.php?logout='1'" class="btn btn-outline">Logout</a>
                </div>
            </div>
        </div>

        <div class="content">
            <!-- Filter Form -->
            <form method="GET" action="audit_logs.php" class="filter-form">
                <div class="filter-group">
                    <label>Username</label>
                    <input type="text" name="username" value="<?php echo htmlspecialchars($filter_username); ?>" placeholder="Search user...">
                </div>
                <div class="filter-group">
                    <label>Action</label>
                    <input type="text" name="action" value="<?php echo htmlspecialchars($filter_action); ?>" placeholder="Search action...">
                </div>
                <div class="filter-group">
                    <label>From Date</label>
                    <input type="date" name="date_from" value="<?php echo htmlspecialchars($filter_date_from); ?>">
                </div>
                <div class="filter-group">
                    <label>To Date</label>
                    <input type="date" name="date_to" value="<?php echo htmlspecialchars($filter_date_to); ?>">
                </div>
                <div style="display: flex; gap: 8px;">
                    <button type="submit" class="btn btn-primary" style="padding: 10px 20px;">Filter Logs</button>
                    <a href="audit_logs.php" class="btn btn-outline" style="padding: 10px 20px;">Clear</a>
                </div>
            </form>

            <div class="charts-container" style="display: grid; grid-template-columns: 1fr 2fr; gap: 24px; margin-bottom: 24px;">
                <!-- Pie Chart: Action Distribution -->
                <div class="form-card" style="padding: 20px; text-align: center;">
                    <h3 style="color: var(--text-primary); margin-bottom: 16px; font-size: 16px;">Action Distribution</h3>
                    <div style="position: relative; height: 250px; width: 100%;">
                        <canvas id="actionPieChart"></canvas>
                    </div>
                </div>
                
                <!-- Bar Chart: Activity Over Time -->
                <div class="form-card" style="padding: 20px;">
                    <h3 style="color: var(--text-primary); margin-bottom: 16px; font-size: 16px;">Activity Over Time (Last 14 Days)</h3>
                    <div style="position: relative; height: 250px; width: 100%;">
                        <canvas id="activityBarChart"></canvas>
                    </div>
                </div>
            </div>

            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                <h3 style="color: var(--text-primary);">Log Results</h3>
                <form method="POST" action="audit_logs.php" style="margin: 0;">
                    <input type="hidden" name="filter_username" value="<?php echo htmlspecialchars($filter_username); ?>">
                    <input type="hidden" name="filter_action" value="<?php echo htmlspecialchars($filter_action); ?>">
                    <input type="hidden" name="filter_date_from" value="<?php echo htmlspecialchars($filter_date_from); ?>">
                    <input type="hidden" name="filter_date_to" value="<?php echo htmlspecialchars($filter_date_to); ?>">
                    <button type="submit" name="export_csv" class="btn btn-secondary" style="background: #10b981;">
                        <svg style="width:16px;height:16px;vertical-align:middle;margin-right:4px" viewBox="0 0 24 24"><path fill="currentColor" d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M12,19L8,15H10.5V12H13.5V15H16L12,19M13,9V3.5L18.5,9H13Z" /></svg>
                        Download CSV Report
                    </button>
                </form>
            </div>

            <?php if ($result && pg_num_rows($result) > 0): ?>
                <table class="user-table">
                    <thead>
                        <tr>
                            <th>Date & Time</th>
                            <th>Username</th>
                            <th>Action Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = pg_fetch_assoc($result)): ?>
                            <tr>
                                <td>
                                    <div style="font-weight: 500; color: var(--text-primary);"><?php echo htmlspecialchars($row['log_date']); ?></div>
                                    <div style="font-size: 12px; color: var(--text-secondary);"><?php echo htmlspecialchars($row['log_time']); ?></div>
                                </td>
                                <td>
                                    <span class="role-badge" style="background: #f1f5f9; color: #475569;">
                                        <?php echo htmlspecialchars($row['username']); ?>
                                    </span>
                                </td>
                                <td style="line-height: 1.5; color: var(--text-secondary);">
                                    <?php echo htmlspecialchars($row['action']); ?>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
                <div style="text-align: center; margin-top: 16px; font-size: 13px; color: var(--text-secondary);">
                    Showing up to 500 recent logs matching the filters.
                </div>
            <?php else: ?>
                <div class="form-card" style="text-align: center; color: var(--text-secondary);">
                    <p>No audit logs found matching the given filters.</p>
                </div>
            <?php endif; ?>
        </div>
    </div>
    <script>
        // Data injected from PHP
        const actionLabels = <?php echo json_encode($action_labels); ?>;
        const actionCounts = <?php echo json_encode($action_counts); ?>;
        const dateLabels = <?php echo json_encode($date_labels); ?>;
        const dateCounts = <?php echo json_encode($date_counts); ?>;

        // Custom colors for the charts
        const colors = [
            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', 
            '#8b5cf6', '#ec4899', '#06b6d4', '#64748b'
        ];

        // 1. Action Distribution Pie Chart
        const ctxPie = document.getElementById('actionPieChart').getContext('2d');
        new Chart(ctxPie, {
            type: 'doughnut',
            data: {
                labels: actionLabels,
                datasets: [{
                    data: actionCounts,
                    backgroundColor: colors,
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { boxWidth: 12, font: { family: 'Inter', size: 11 } }
                    }
                },
                cutout: '70%'
            }
        });

        // 2. Activity Bar Chart
        const ctxBar = document.getElementById('activityBarChart').getContext('2d');
        new Chart(ctxBar, {
            type: 'bar',
            data: {
                labels: dateLabels,
                datasets: [{
                    label: 'Audit Events',
                    data: dateCounts,
                    backgroundColor: '#8b5cf6',
                    borderRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1, font: { family: 'Inter', size: 11 } },
                        grid: { borderDash: [4, 4], color: '#e2e8f0' }
                    },
                    x: {
                        ticks: { font: { family: 'Inter', size: 11 } },
                        grid: { display: false }
                    }
                }
            }
        });
    </script>
</body>
</html>
<?php pg_close($conn); ?>
