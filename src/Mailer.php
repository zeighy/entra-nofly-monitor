<?php
namespace App;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class Mailer {
    public static function sendConsolidatedAlert(array $incidents): void {
        if (empty($incidents)) {
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

            $incidentCount = count($incidents);
            $body = "<h2>Consolidated Security Alert</h2>";
            $body .= "<p>Found <strong>" . $incidentCount . "</strong> notable incident(s) during the last scan.</p>";

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
                $body .= "<p>
                            <strong>Time:</strong> " . $previousLog['login_time'] . " UTC<br>
                            <strong>Location:</strong> " . htmlspecialchars(($previousLog['city'] ?? 'N/A') . ', ' . ($previousLog['region'] ?? 'N/A') . ', ' . ($previousLog['country'] ?? 'N/A')) . "<br>
                            <strong>IP Address:</strong> " . htmlspecialchars($previousLog['ip_address']) . "
                         </p>";

                $body .= "<h4>Current Login (To):</h4>";
                $body .= "<p>
                            <strong>Time:</strong> " . $currentLog['login_time'] . " UTC<br>
                            <strong>Location:</strong> " . htmlspecialchars(($currentLog['city'] ?? 'N/A') . ', ' . ($currentLog['region'] ?? 'N/A') . ', ' . ($currentLog['country'] ?? 'N/A')) . "<br>
                            <strong>IP Address:</strong> " . htmlspecialchars($currentLog['ip_address']) . "
                         </p>";
            }

            $mail->isHTML(true);
            $mail->Subject = "Security Alert: " . $incidentCount . " incident(s) detected";
            $mail->Body    = $body;

            $mail->send();
        } catch (Exception $e) {
            error_log("Mailer Error: {$mail->ErrorInfo}");
        }
    }
}
