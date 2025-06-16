<?php
namespace App;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class Mailer {
    /**
     * Sends a single consolidated email with all impossible travel incidents from a run.
     * @param array $incidents
     */
    public static function sendConsolidatedAlert(array $incidents): void {
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
            $incidentCount = count($incidents);
            $body = "<h2>Consolidated Impossible Travel Alert</h2>";
            $body .= "<p>Found <strong>" . $incidentCount . "</strong> impossible travel incident(s) during the last scan.</p>";

            foreach ($incidents as $index => $incident) {
                $currentLog = $incident['current_log'];
                $previousLog = $incident['previous_log'];
                $speed = $incident['speed'];

                $body .= "<hr><h3>Incident #" . ($index + 1) . ": " . htmlspecialchars($currentLog['user_principal_name']) . "</h3>";
                $body .= "<p><strong>Calculated Speed:</strong> " . round($speed) . " km/h</p>";
                
                $body .= "<h4>Previous Login (From):</h4>";
                $body .= "<p>
                            <strong>Time:</strong> " . $previousLog['login_time'] . " UTC<br>
                            <strong>IP Address:</strong> " . htmlspecialchars($previousLog['ip_address']) . "<br>
                            <strong>Location:</strong> " . htmlspecialchars($previousLog['city'] ?? 'N/A') . ", " . htmlspecialchars($previousLog['country'] ?? 'N/A') . "
                         </p>";

                $body .= "<h4>Current Login (To):</h4>";
                $body .= "<p>
                            <strong>Time:</strong> " . $currentLog['login_time'] . " UTC<br>
                            <strong>IP Address:</strong> " . htmlspecialchars($currentLog['ip_address']) . "<br>
                            <strong>Location:</strong> " . htmlspecialchars($currentLog['city'] ?? 'N/A') . ", " . htmlspecialchars($currentLog['country'] ?? 'N/A') . "
                         </p>";
            }

            // Content
            $mail->isHTML(true);
            $mail->Subject = "Impossible Travel Alert: " . $incidentCount . " incident(s) detected";
            $mail->Body    = $body;

            $mail->send();
        } catch (Exception $e) {
            error_log("Mailer Error: {$mail->ErrorInfo}");
        }
    }
}