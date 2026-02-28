<?php

require_once __DIR__ . '/vendor/autoload.php';

// Load credentials from secrets.php
$secretsFile = __DIR__ . '/secrets.php';
if (!file_exists($secretsFile)) {
    die("FATAL ERROR: secrets.php file not found. Please create it in the project root.\n");
}
$secrets = require $secretsFile;

// Populate $_ENV, but only putenv for non-arrays to avoid warnings
foreach ($secrets as $key => $value) {
    $_ENV[$key] = $value;
    if (!is_array($value)) {
        putenv("$key=$value");
    }
}

use App\Database;
use App\Mailer;

$db = Database::getInstance();
$mailer = new Mailer();

echo "Starting weekly digest generation...\n";

// Fetch all distinct users seen in the last 7 days (either from detections or successful logins)
$stmt = $db->query("SELECT DISTINCT user_principal_name FROM login_logs WHERE login_time >= NOW() - INTERVAL 7 DAY AND (status = 'Success' OR is_impossible_travel = 1 OR is_region_change = 1)");
$logUsers = $stmt->fetchAll(PDO::FETCH_COLUMN);

$stmt = $db->query("SELECT DISTINCT user_principal_name FROM auth_device_changes WHERE change_time >= NOW() - INTERVAL 7 DAY");
$deviceUsers = $stmt->fetchAll(PDO::FETCH_COLUMN);

// Merge and deduplicate the user lists to avoid collation mix errors from SQL UNION
$users = array_values(array_unique(array_merge($logUsers, $deviceUsers)));

if (empty($users)) {
    echo "No relevant user activity found in the last 7 days. Exiting.\n";
    exit(0);
}

$digestData = [];

foreach ($users as $upn) {
    $userData = [
        'upn' => $upn,
        'impossible_travel_count' => 0,
        'region_change_count' => 0,
        'device_change_count' => 0,
        'current_regions' => [], // Region => Count (Last 7 days)
        'prior_regions' => []    // Regions (Days 8-14 ago)
    ];

    // Count Impossible Travel (Last 7 days)
    $stmt = $db->prepare("SELECT COUNT(*) FROM login_logs WHERE user_principal_name = ? AND login_time >= NOW() - INTERVAL 7 DAY AND is_impossible_travel = 1");
    $stmt->execute([$upn]);
    $userData['impossible_travel_count'] = $stmt->fetchColumn();

    // Count Region Change (Last 7 days)
    $stmt = $db->prepare("SELECT COUNT(*) FROM login_logs WHERE user_principal_name = ? AND login_time >= NOW() - INTERVAL 7 DAY AND is_region_change = 1");
    $stmt->execute([$upn]);
    $userData['region_change_count'] = $stmt->fetchColumn();

    // Count Device Changes (Last 7 days)
    $stmt = $db->prepare("SELECT COUNT(*) FROM auth_device_changes WHERE user_principal_name = ? AND change_time >= NOW() - INTERVAL 7 DAY");
    $stmt->execute([$upn]);
    $userData['device_change_count'] = $stmt->fetchColumn();

    // Get successful login regions and counts (Last 7 days)
    $stmt = $db->prepare("
        SELECT CONCAT(region, ', ', country) AS location, COUNT(*) as count 
        FROM login_logs 
        WHERE user_principal_name = ? AND login_time >= NOW() - INTERVAL 7 DAY AND status = 'Success'
        GROUP BY location
    ");
    $stmt->execute([$upn]);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        if ($row['location'] != ', ') {
             $userData['current_regions'][$row['location']] = $row['count'];
        }
    }

    // Get successful login regions (Prior 7 days: 8 to 14 days ago)
    $stmt = $db->prepare("
        SELECT DISTINCT CONCAT(region, ', ', country) AS location
        FROM login_logs 
        WHERE user_principal_name = ? 
        AND login_time >= NOW() - INTERVAL 14 DAY 
        AND login_time < NOW() - INTERVAL 7 DAY 
        AND status = 'Success'
    ");
    $stmt->execute([$upn]);
    $userData['prior_regions'] = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $userData['prior_regions'] = array_filter($userData['prior_regions'], function($val) { return $val != ', '; });

    // Determine if there are any new regions
    $hasNewRegions = false;
    foreach (array_keys($userData['current_regions']) as $currentRegion) {
        if (!in_array($currentRegion, $userData['prior_regions'])) {
            $hasNewRegions = true;
            break;
        }
    }

    // Only add to digest if there are detections OR new regions
    if ($userData['impossible_travel_count'] > 0 || 
        $userData['region_change_count'] > 0 || 
        $userData['device_change_count'] > 0 || 
        $hasNewRegions) {
        
        $digestData[] = $userData;
    }
}

if (empty($digestData)) {
     echo "No data to report in digest. Exiting.\n";
     exit(0);
}

// Build Email HTML
$htmlBody = "<div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; padding: 20px; color: #1e293b; line-height: 1.5;\">";
$htmlBody .= "<div style=\"max-width: 1000px; margin: 0 auto; background-color: #ffffff; border-top: 5px solid #0f2027; box-shadow: 0 2px 4px rgba(0,0,0,0.05);\">";

// Header
$htmlBody .= "<div style=\"padding: 20px; border-bottom: 2px solid #e2e8f0; background-color: #0f2027; color: #ffffff;\">";
$htmlBody .= "<h2 style=\"margin: 0; font-size: 24px; text-transform: uppercase; letter-spacing: 0.5px;\">Weekly Entra User Activity Digest</h2>";
$htmlBody .= "</div>";

$htmlBody .= "<div style=\"padding: 20px;\">";
$htmlBody .= "<p style=\"margin-top: 0; margin-bottom: 20px; font-size: 16px;\">Consolidated overview of detections and successful logins per user for the last 7 days.</p>";

$htmlBody .= "<table width=\"100%\" cellpadding=\"15\" style=\"border-collapse: collapse; font-size: 14px;\">";
$htmlBody .= "<thead>";
$htmlBody .= "<tr>";
$htmlBody .= "<th style=\"background-color: #0f2027; color: white; border: 1px solid #cbd5e1; text-align: left; text-transform: uppercase; font-size: 12px;\">User</th>";
$htmlBody .= "<th style=\"background-color: #0f2027; color: white; border: 1px solid #cbd5e1; text-align: left; text-transform: uppercase; font-size: 12px;\">Detections (Last 7 Days)</th>";
$htmlBody .= "<th style=\"background-color: #0f2027; color: white; border: 1px solid #cbd5e1; text-align: left; text-transform: uppercase; font-size: 12px;\">Successful Logins (Last 7 Days)</th>";
$htmlBody .= "<th style=\"background-color: #0f2027; color: white; border: 1px solid #cbd5e1; text-align: left; text-transform: uppercase; font-size: 12px;\">Prior Successful Logins (Days 8-14 Ago)</th>";
$htmlBody .= "</tr>";
$htmlBody .= "</thead>";
$htmlBody .= "<tbody>";

foreach ($digestData as $index => $user) {
    $bgClass = ($index % 2 === 0) ? '#ffffff' : '#f8fafc';
    $htmlBody .= "<tr style=\"background-color: " . $bgClass . ";\">";
    
    // User
    $htmlBody .= "<td style=\"border: 1px solid #cbd5e1; vertical-align: top;\"><strong style=\"color: #0f2027;\">" . htmlspecialchars($user['upn']) . "</strong></td>";
    
    // Detections
    $htmlBody .= "<td style=\"border: 1px solid #cbd5e1; vertical-align: top;\">";
    $htmlBody .= "<div style=\"margin-bottom: 5px;\">Impossible Travel: <strong style=\"color: " . ($user['impossible_travel_count'] > 0 ? '#e63946' : '#64748b') . ";\">" . $user['impossible_travel_count'] . "</strong></div>";
    $htmlBody .= "<div style=\"margin-bottom: 5px;\">Region Changes: <strong style=\"color: " . ($user['region_change_count'] > 0 ? '#0284c7' : '#64748b') . ";\">" . $user['region_change_count'] . "</strong></div>";
    $htmlBody .= "<div>Device Changes: <strong style=\"color: " . ($user['device_change_count'] > 0 ? '#8b5cf6' : '#64748b') . ";\">" . $user['device_change_count'] . "</strong></div>";
    $htmlBody .= "</td>";
    
    // Current Regions
    $htmlBody .= "<td style=\"border: 1px solid #cbd5e1; vertical-align: top;\">";
    if (empty($user['current_regions'])) {
        $htmlBody .= "<em style=\"color: #94a3b8;\">None detected</em>";
    } else {
        $htmlBody .= "<ul style=\"margin: 0; padding-left: 20px;\">";
        foreach ($user['current_regions'] as $region => $count) {
            $htmlBody .= "<li style=\"margin-bottom: 4px;\">" . htmlspecialchars($region) . " <span style=\"color: #059669; font-weight: bold;\">(" . $count . " logins)</span></li>";
        }
        $htmlBody .= "</ul>";
    }
    $htmlBody .= "</td>";

    // Prior Regions
    $htmlBody .= "<td style=\"border: 1px solid #cbd5e1; vertical-align: top;\">";
    if (empty($user['prior_regions'])) {
        $htmlBody .= "<em style=\"color: #94a3b8;\">None detected</em>";
    } else {
        $htmlBody .= "<ul style=\"margin: 0; padding-left: 20px; color: #64748b;\">";
        foreach ($user['prior_regions'] as $region) {
            $htmlBody .= "<li style=\"margin-bottom: 4px;\">" . htmlspecialchars($region) . "</li>";
        }
        $htmlBody .= "</ul>";
    }
    $htmlBody .= "</td>";

    $htmlBody .= "</tr>";
}

$htmlBody .= "</tbody>";
$htmlBody .= "</table>";
$htmlBody .= "</div>"; // End padding div

// Footer
$htmlBody .= "<div style=\"padding: 20px; text-align: center; color: #64748b; font-size: 12px; border-top: 2px solid #e2e8f0;\">";
$htmlBody .= "This is an automated message from your Entra Monitor instance.";
$htmlBody .= "</div>";

$htmlBody .= "</div>"; // End max-width wrapper
$htmlBody .= "</div>"; // End background wrapper

// Send Email
$subject = "Weekly Entra Activity Digest - " . date('Y-m-d');
$recipient = $_ENV['ADMIN_ALERT_EMAIL'] ?? '';
$ccRecipients = isset($_ENV['MAILER_CC_RECIPIENTS']) ? explode(',', $_ENV['MAILER_CC_RECIPIENTS']) : [];

if (empty($recipient)) {
     echo "Error: ADMIN_ALERT_EMAIL is not configured in secrets.php.\n";
     exit(1);
}

try {
    $mailer->sendHtmlEmail($recipient, $subject, $htmlBody, $ccRecipients);
    echo "Successfully sent weekly digest to $recipient.\n";
} catch (Exception $e) {
    echo "Failed to send weekly digest: " . $e->getMessage() . "\n";
}

