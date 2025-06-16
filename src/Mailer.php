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

            // --- Build the Consolidated Email Body ---
            $totalIncidents = count($incidents);
            $uniqueUsers = count(array_unique(array_column(array_column($incidents, 'current_log'), 'user_principal_name')));
            $incidentTypes = array_column($incidents, 'type');
            $impossibleTravelCount = array_count_values($incidentTypes)['impossible_travel'] ?? 0;
            $regionChangeCount = array_count_values($incidentTypes)['region_change'] ?? 0;
            
            $body = "<h2>Consolidated Security Alert</h2>";
            $body .= "<p>A recent scan detected the following notable events:</p>";
            $body .= "<ul>";
            $body .= "<li><strong>Total Incidents:</strong> " . $totalIncidents . "</li>";
            $body .= "<li><strong>Unique Users Affected:</strong> " . $uniqueUsers . "</li>";
            $body .= "<li><strong>Impossible Travel Events:</strong> " . $impossibleTravelCount . "</li>";
            $body .= "<li><strong>Region Change Events:</strong> " . $regionChangeCount . "</li>";
            $body .= "</ul>";
            $body .= "<p><i><b>Note:</b> A single recent sign-in may generate multiple incidents if it is anomalous when compared against several different logins from the past 24 hours.</i></p>";
            $body .= "<h2>Incident Details</h2>";

            foreach ($incidents as $index => $incident) {
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

                // --- Log this specific alert to the database ---
                $logStmt = $db->prepare(
                    "INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)"
                );
                $logStmt->execute([
                    $currentLog['id'],
                    $previousLog['id'],
                    $incident['type']
                ]);
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
}
