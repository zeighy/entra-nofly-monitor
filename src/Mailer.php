<?php
namespace App;

use PDO;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class Mailer {
    /**
     * Sends a single consolidated email and logs the alert to the database.
     * @param array $incidents
     * @param PDO $db The database connection
     */
    public static function sendConsolidatedAlert(array $incidents, PDO $db): void {
        if (empty($incidents)) {
            return;
        }

        $mail = new PHPMailer(true);
        try {
            // Server settings
            $mail->isSMTP();
            $mail->Host       = $_ENV['SMTP_HOST'];
            $mail->SMTPAuth   = true;
            $mail->Username   = $_ENV['SMTP_USERNAME'];
            $mail->Password   = $_ENV['SMTP_PASSWORD'];
            $mail->SMTPSecure = $_ENV['SMTP_SECURE'];
            $mail->Port       = $_ENV['SMTP_PORT'];

            // Recipients
            $mail->setFrom($_ENV['SMTP_FROM_EMAIL'], $_ENV['SMTP_FROM_NAME']);
            $mail->addAddress($_ENV['ADMIN_ALERT_EMAIL']);

            if (!empty($_ENV['MAILER_CC_RECIPIENTS'])) {
                $ccEmails = explode(',', $_ENV['MAILER_CC_RECIPIENTS']);
                foreach ($ccEmails as $email) {
                    $trimmedEmail = trim($email);
                    if (filter_var($trimmedEmail, FILTER_VALIDATE_EMAIL)) {
                        $mail->addCC($trimmedEmail);
                    }
                }
            }

            // --- Separate incidents by type ---
            $travelRegionIncidents = [];
            $deviceChangeIncidents = [];
            foreach ($incidents as $incident) {
                if ($incident['type'] === 'auth_device_change') {
                    $deviceChangeIncidents[] = $incident;
                } else {
                    $travelRegionIncidents[] = $incident;
                }
            }

            // Group device changes by user for consolidation
            $groupedDeviceChanges = [];
            foreach ($deviceChangeIncidents as $incident) {
                $user = $incident['user'];
                $change = $incident['change']; // 'Added' or 'Removed'
                $device = $incident['device'];
                if (!isset($groupedDeviceChanges[$user])) {
                    $groupedDeviceChanges[$user] = ['Added' => [], 'Removed' => []];
                }
                $groupedDeviceChanges[$user][$change][] = $device;
            }

            // --- Build the Consolidated Email Body ---
            $totalIncidents = count($incidents);
            $uniqueUsers = count(array_unique(array_column(array_column($incidents, 'current_log'), 'user_principal_name')));
            $incidentTypes = array_column($incidents, 'type');
            $impossibleTravelCount = array_count_values($incidentTypes)['impossible_travel'] ?? 0;
            $regionChangeCount = array_count_values($incidentTypes)['region_change'] ?? 0;
            $deviceChangeCount = count($deviceChangeIncidents);
            
            $body = "<h2>Consolidated Security Alert</h2>";
            $body .= "<p>A recent scan detected the following notable events:</p>";
            $body .= "<ul>";
            $body .= "<li><strong>Total Incidents:</strong> " . $totalIncidents . "</li>";
            $body .= "<li><strong>Unique Users Affected:</strong> " . $uniqueUsers . "</li>";
            $body .= "<li><strong>Impossible Travel Events:</strong> " . $impossibleTravelCount . "</li>";
            $body .= "<li><strong>Region Change Events:</strong> " . $regionChangeCount . "</li>";
            $body .= "<li><strong>Auth Device Changes:</strong> " . $deviceChangeCount . "</li>";
            $body .= "</ul>";
            $body .= "<p><i><b>Note:</b> A single recent sign-in may generate multiple incidents if it is anomalous when compared against several different logins from the past 24 hours.</i></p>";
            $body .= "<h2>Incident Details</h2>";

            // --- Display Travel and Region incidents first ---
            foreach ($travelRegionIncidents as $index => $incident) {
                $currentLog = $incident['current_log'];
                $previousLog = $incident['previous_log'];

                if ($incident['type'] === 'impossible_travel') {
                    $speed = $incident['speed'];
                    $body .= "<hr><h3>Incident #" . ($index + 1) . ": Impossible Travel</h3>";
                    $body .= "<p><strong>User:</strong> " . htmlspecialchars($currentLog['user_principal_name']) . "</p>";
                    $body .= "<p><strong>Calculated Speed:</strong> " . round($speed) . " km/h</p>";
                } elseif ($incident['type'] === 'region_change') {
                    $body .= "<hr><h3>Incident #" . ($index + 1) . ": Region Change</h3>";
                    $body .= "<p><strong>User:</strong> " . htmlspecialchars($currentLog['user_principal_name']) . "</p>";
                }

                $body .= "<h4>Previous Login (From):</h4>";
                $body .= "<p><strong>Time:</strong> " . $previousLog['login_time'] . " UTC<br><strong>Location:</strong> " . htmlspecialchars(($previousLog['city'] ?? 'N/A') . ', ' . ($previousLog['region'] ?? 'N/A') . ', ' . ($previousLog['country'] ?? 'N/A')) . "<br><strong>IP Address:</strong> " . htmlspecialchars($previousLog['ip_address']) . "</p>";
                $body .= "<h4>Current Login (To):</h4>";
                $body .= "<p><strong>Time:</strong> " . $currentLog['login_time'] . " UTC<br><strong>Location:</strong> " . htmlspecialchars(($currentLog['city'] ?? 'N/A') . ', ' . ($currentLog['region'] ?? 'N/A') . ', ' . ($currentLog['country'] ?? 'N/A')) . "<br><strong>IP Address:</strong> " . htmlspecialchars($currentLog['ip_address']) . "</p>";

                $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                $logStmt->execute([$currentLog['id'], $previousLog['id'], $incident['type']]);
            }

            // --- Display consolidated device changes at the bottom ---
            if (!empty($groupedDeviceChanges)) {
                $body .= "<hr><h3>Authentication Device Changes</h3>";
                foreach($groupedDeviceChanges as $user => $changes) {
                    $body .= "<p><strong>User:</strong> " . htmlspecialchars($user) . "</p><ul>";
                    if (!empty($changes['Added'])) {
                        $body .= "<li><strong>Devices Added:</strong> " . htmlspecialchars(implode(', ', $changes['Added'])) . "</li>";
                    }
                    if (!empty($changes['Removed'])) {
                        $body .= "<li><strong>Devices Removed:</strong> " . htmlspecialchars(implode(', ', $changes['Removed'])) . "</li>";
                    }
                    $body .= "</ul>";
                }
            }

            // Content
            $mail->isHTML(true);
            $mail->Subject = "Security Alert: " . $totalIncidents . " notable incident(s) detected";
            $mail->Body    = $body;

            $mail->send();
        } catch (Exception $e) {
            error_log("Mailer Error: {$mail->ErrorInfo}");
        }
    }

    public static function sendUserAlert(string $userEmail, string $alertType, array $incidentData, PDO $db): void {
        if (empty($userEmail) || !filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
            error_log("Invalid user email provided for alert: $userEmail");
            return;
        }

        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host       = $_ENV['SMTP_HOST'];
            $mail->SMTPAuth   = true;
            $mail->Username   = $_ENV['SMTP_USERNAME'];
            $mail->Password   = $_ENV['SMTP_PASSWORD'];
            $mail->SMTPSecure = $_ENV['SMTP_SECURE'];
            $mail->Port       = $_ENV['SMTP_PORT'];

            $mail->setFrom($_ENV['SMTP_FROM_EMAIL'], $_ENV['SMTP_FROM_NAME']);
            $mail->addAddress($userEmail);

            $mail->isHTML(true);
            $subject = '';
            $body = '';

            switch ($alertType) {
                case 'impossible_travel':
                    $subject = 'Security Alert: Impossible Travel Detected on Your Account';
                    $currentLog = $incidentData['current_log'];
                    $previousLog = $incidentData['previous_log'];
                    $body = "<h2>Security Alert: Impossible Travel Detected</h2>";
                    $body .= "<p>We have detected a login to your account from a location that is considered impossible to reach in the time elapsed since your last login.</p>";
                    $body .= "<h4>Previous Login:</h4>";
                    $body .= "<p><strong>Time:</strong> " . $previousLog['login_time'] . " UTC<br><strong>Location:</strong> " . htmlspecialchars(($previousLog['city'] ?? 'N/A') . ', ' . ($previousLog['region'] ?? 'N/A') . ', ' . ($previousLog['country'] ?? 'N/A')) . "<br><strong>IP Address:</strong> " . htmlspecialchars($previousLog['ip_address']) . "</p>";
                    $body .= "<h4>Anomalous Login:</h4>";
                    $body .= "<p><strong>Time:</strong> " . $currentLog['login_time'] . " UTC<br><strong>Location:</strong> " . htmlspecialchars(($currentLog['city'] ?? 'N/A') . ', ' . ($currentLog['region'] ?? 'N/A') . ', ' . ($currentLog['country'] ?? 'N/A')) . "<br><strong>IP Address:</strong> " . htmlspecialchars($currentLog['ip_address']) . "</p>";
                    $body .= "<p>If this was not you, please contact your IT administrator immediately.</p>";
                    $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                    $logStmt->execute([$currentLog['id'], $previousLog['id'], 'user_impossible_travel']);
                    break;

                case 'region_change':
                    $subject = 'Security Alert: New Sign-in From a Different Region';
                    $currentLog = $incidentData['current_log'];
                    $previousLog = $incidentData['previous_log'];
                    $body = "<h2>Security Alert: Sign-in from New Region</h2>";
                    $body .= "<p>We have detected a login to your account from a different region than your usual activity.</p>";
                    $body .= "<h4>Previous Login Location:</h4>";
                    $body .= "<p><strong>Location:</strong> " . htmlspecialchars(($previousLog['region'] ?? 'N/A') . ', ' . ($previousLog['country'] ?? 'N/A')) . "</p>";
                    $body .= "<h4>New Login Location:</h4>";
                    $body .= "<p><strong>Time:</strong> " . $currentLog['login_time'] . " UTC<br><strong>Location:</strong> " . htmlspecialchars(($currentLog['region'] ?? 'N/A') . ', ' . ($currentLog['country'] ?? 'N/A')) . "<br><strong>IP Address:</strong> " . htmlspecialchars($currentLog['ip_address']) . "</p>";
                    $body .= "<p>If this was not you, please contact your IT administrator immediately.</p>";
                    $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                    $logStmt->execute([$currentLog['id'], $previousLog['id'], 'user_region_change']);
                    break;

                case 'auth_device_change':
                    $subject = 'Security Alert: Authentication Method Changed on Your Account';
                    $change = $incidentData['change'];
                    $device = $incidentData['device'];
                    $body = "<h2>Security Alert: Authentication Method Change</h2>";
                    $body .= "<p>An authentication method was recently <strong>" . strtolower($change) . "</strong> for your account.</p>";
                    $body .= "<p><strong>Device/Method:</strong> " . htmlspecialchars($device) . "</p>";
                    $body .= "<p>If you did not make this change, please contact your IT administrator immediately.</p>";
                    $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                    $logStmt->execute([0, 0, 'user_auth_device_change']);
                    break;

                case 'account_locked':
                    $subject = 'Security Alert: Your Account Has Been Locked';
                    $log = $incidentData['current_log'];
                    $body = "<h2>Security Alert: Account Locked</h2>";
                    $body .= "<p>Your account has been locked due to multiple failed sign-in attempts.</p>";
                    $body .= "<p><strong>Time of last attempt:</strong> " . $log['login_time'] . " UTC<br><strong>IP Address:</strong> " . htmlspecialchars($log['ip_address']) . "</p>";
                    $body .= "<p>Please contact your IT administrator to unlock your account.</p>";
                    $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                    $logStmt->execute([$log['id'], 0, 'user_account_locked']);
                    break;
            }

            $mail->Subject = $subject;
            $mail->Body = $body;
            $mail->send();

        } catch (Exception $e) {
            error_log("User Mailer Error for $userEmail: {$mail->ErrorInfo}");
        }
    }
}
