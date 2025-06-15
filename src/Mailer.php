<?php
namespace App;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class Mailer {
    public static function sendImpossibleTravelAlert(array $currentLog, array $previousLog, float $speed): void {
        $mail = new PHPMailer(true);
        try {
            // Server settings, pulled from secrets
            $mail->isSMTP();
            $mail->Host       = $_ENV['SMTP_HOST'];
            $mail->SMTPAuth   = true;
            $mail->Username   = $_ENV['SMTP_USERNAME'];
            $mail->Password   = $_ENV['SMTP_PASSWORD'];
            $mail->SMTPSecure = $_ENV['SMTP_SECURE'];
            $mail->Port       = $_ENV['SMTP_PORT'];

            // Recipients
            $mail->setFrom($_ENV['SMTP_FROM_EMAIL'], $_ENV['SMTP_FROM_NAME']);
            $mail->addAddress($_ENV['ADMIN_ALERT_EMAIL']); // Main recipient
            if (!empty($_ENV['MAILER_CC_RECIPIENTS'])) {
                // Split the comma-separated string into an array of emails
                $ccEmails = explode(',', $_ENV['MAILER_CC_RECIPIENTS']);
                
                foreach ($ccEmails as $email) {
                    // Trim whitespace and check if it's a valid email format
                    $trimmedEmail = trim($email);
                    if (filter_var($trimmedEmail, FILTER_VALIDATE_EMAIL)) {
                        $mail->addCC($trimmedEmail);
                    }
                }
            }

            // Content
            $mail->isHTML(true);
            $mail->Subject = 'Impossible Travel Alert: ' . htmlspecialchars($currentLog['user_principal_name']);
            $mail->Body    = self::formatEmailBody($currentLog, $previousLog, $speed);

            $mail->send();
        } catch (Exception $e) {
            error_log("Mailer Error: {$mail->ErrorInfo}");
        }
    }

    private static function formatEmailBody(array $currentLog, array $previousLog, float $speed): string {
        $body = "<h2>Impossible Travel Detected</h2>
                 <p>User <strong>" . htmlspecialchars($currentLog['user_principal_name']) . "</strong> has <u>successfully</u> logged in from two locations at a speed that suggests impossible travel.</p>
                 <p><strong>Calculated Speed:</strong> " . round($speed) . " km/h</p>
                 <hr>
                 <h3>Most Recent Login:</h3>
                 <p>
                    <strong>Time:</strong> " . $currentLog['login_time'] . " UTC<br>
                    <strong>IP Address:</strong> " . htmlspecialchars($currentLog['ip_address']) . "<br>
                    <strong>Location:</strong> " . htmlspecialchars($currentLog['city'] ?? 'N/A') . ", " . htmlspecialchars($currentLog['country'] ?? 'N/A') . "
                 </p>
                 <h3>Previous Login:</h3>
                 <p>
                    <strong>Time:</strong> " . $previousLog['login_time'] . " UTC<br>
                    <strong>IP Address:</strong> " . htmlspecialchars($previousLog['ip_address']) . "<br>
                    <strong>Location:</strong> " . htmlspecialchars($previousLog['city'] ?? 'N/A') . ", " . htmlspecialchars($previousLog['country'] ?? 'N/A') . "
                 </p>";
        return $body;
    }
}