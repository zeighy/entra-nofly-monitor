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
            
            $body = "<div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; padding: 20px; color: #1e293b; line-height: 1.5;\">";
            $body .= "<div style=\"max-width: 800px; margin: 0 auto; background-color: #ffffff; border-top: 5px solid #0f2027; box-shadow: 0 2px 4px rgba(0,0,0,0.05);\">";
            
            // Header
            $body .= "<div style=\"padding: 20px; border-bottom: 2px solid #e2e8f0; background-color: #0f2027; color: #ffffff;\">";
            $body .= "<h2 style=\"margin: 0; font-size: 24px; text-transform: uppercase; letter-spacing: 0.5px;\">Consolidated Security Alert</h2>";
            $body .= "</div>";

            // Summary Section
            $body .= "<div style=\"padding: 20px;\">";
            $body .= "<p style=\"margin-top: 0; font-size: 16px;\">A recent scan detected the following notable events:</p>";
            $body .= "<table width=\"100%\" cellpadding=\"10\" style=\"border-collapse: collapse; background-color: #f8fafc; border: 1px solid #cbd5e1; margin-bottom: 20px;\">";
            $body .= "<tr><td width=\"50%\" style=\"border-bottom: 1px solid #cbd5e1; border-right: 1px solid #cbd5e1;\"><strong>Total Incidents:</strong></td><td style=\"border-bottom: 1px solid #cbd5e1;\"><span style=\"font-size: 18px; font-weight: bold; color: #e63946;\">" . $totalIncidents . "</span></td></tr>";
            $body .= "<tr><td width=\"50%\" style=\"border-bottom: 1px solid #cbd5e1; border-right: 1px solid #cbd5e1;\"><strong>Unique Users Affected:</strong></td><td style=\"border-bottom: 1px solid #cbd5e1;\">" . $uniqueUsers . "</td></tr>";
            $body .= "<tr><td width=\"50%\" style=\"border-bottom: 1px solid #cbd5e1; border-right: 1px solid #cbd5e1;\"><strong>Impossible Travel Events:</strong></td><td style=\"border-bottom: 1px solid #cbd5e1;\">" . $impossibleTravelCount . "</td></tr>";
            $body .= "<tr><td width=\"50%\" style=\"border-bottom: 1px solid #cbd5e1; border-right: 1px solid #cbd5e1;\"><strong>Region Change Events:</strong></td><td style=\"border-bottom: 1px solid #cbd5e1;\">" . $regionChangeCount . "</td></tr>";
            $body .= "<tr><td width=\"50%\" style=\"border-right: 1px solid #cbd5e1;\"><strong>Auth Device Changes:</strong></td><td>" . $deviceChangeCount . "</td></tr>";
            $body .= "</table>";
            $body .= "<div style=\"background-color: #e0f2fe; border-left: 4px solid #0284c7; padding: 10px 15px; font-size: 13px; color: #0369a1;\"><strong>Note:</strong> A single recent sign-in may generate multiple incidents if it is anomalous when compared against several different logins from the past 24 hours.</div>";
            $body .= "</div>";

            // Incidents Section
            $body .= "<div style=\"padding: 20px; border-top: 2px solid #e2e8f0;\">";
            $body .= "<h2 style=\"margin-top: 0; color: #0f2027; text-transform: uppercase; font-size: 18px; border-bottom: 2px solid #f0f2f5; padding-bottom: 10px;\">Incident Details</h2>";

            // --- Display Travel and Region incidents first ---
            foreach ($travelRegionIncidents as $index => $incident) {
                $currentLog = $incident['current_log'];
                $previousLog = $incident['previous_log'];

                $body .= "<div style=\"margin-bottom: 30px; border: 1px solid #cbd5e1;\">";
                
                if ($incident['type'] === 'impossible_travel') {
                    $speed = $incident['speed'];
                    $body .= "<div style=\"background-color: #fff1f2; border-bottom: 1px solid #cbd5e1; padding: 10px 15px; border-left: 4px solid #e63946;\">";
                    $body .= "<h3 style=\"margin: 0; color: #b91c1c; font-size: 16px;\">#" . ($index + 1) . " - Impossible Travel Detected</h3>";
                    $body .= "</div>";
                    $body .= "<div style=\"padding: 15px;\">";
                    $body .= "<div style=\"margin-bottom: 15px;\"><strong>User:</strong> <span style=\"font-weight: bold; color: #0f2027; font-size: 16px;\">" . htmlspecialchars($currentLog['user_principal_name']) . "</span></div>";
                    $body .= "<div style=\"margin-bottom: 15px;\"><strong>Calculated Speed:</strong> <span style=\"background-color: #fee2e2; color: #b91c1c; padding: 3px 8px; font-weight: bold; font-size: 16px;\">" . round($speed) . " km/h</span></div>";
                } elseif ($incident['type'] === 'region_change') {
                    $body .= "<div style=\"background-color: #f0f9ff; border-bottom: 1px solid #cbd5e1; padding: 10px 15px; border-left: 4px solid #0284c7;\">";
                    $body .= "<h3 style=\"margin: 0; color: #0369a1; font-size: 16px;\">#" . ($index + 1) . " - Region Change Detected</h3>";
                    $body .= "</div>";
                    $body .= "<div style=\"padding: 15px;\">";
                    $body .= "<div style=\"margin-bottom: 15px;\"><strong>User:</strong> <span style=\"font-weight: bold; color: #0f2027; font-size: 16px;\">" . htmlspecialchars($currentLog['user_principal_name']) . "</span></div>";
                }

                $body .= "<table width=\"100%\" cellpadding=\"10\" style=\"border-collapse: collapse; font-size: 14px;\">";
                $body .= "<tr>";
                $body .= "<td width=\"50%\" style=\"background-color: #f8fafc; border: 1px solid #cbd5e1; vertical-align: top;\">";
                $body .= "<div style=\"font-weight: bold; color: #64748b; margin-bottom: 5px; text-transform: uppercase; font-size: 12px;\">Previous Login (From)</div>";
                $body .= "<div style=\"margin-bottom: 5px;\"><strong>" . htmlspecialchars(($previousLog['city'] ?? 'N/A') . ', ' . ($previousLog['region'] ?? 'N/A') . ', ' . ($previousLog['country'] ?? 'N/A')) . "</strong></div>";
                $body .= "<div style=\"color: #64748b; font-family: monospace;\">" . htmlspecialchars($previousLog['ip_address']) . "</div>";
                $body .= "<div style=\"color: #64748b; font-size: 12px; margin-top: 5px;\">" . $previousLog['login_time'] . " UTC</div>";
                $body .= "</td>";
                $body .= "<td width=\"50%\" style=\"background-color: #ffffff; border: 1px solid #cbd5e1; vertical-align: top;\">";
                $body .= "<div style=\"font-weight: bold; color: #0f2027; margin-bottom: 5px; text-transform: uppercase; font-size: 12px;\">Current Login (To)</div>";
                $body .= "<div style=\"margin-bottom: 5px;\"><strong>" . htmlspecialchars(($currentLog['city'] ?? 'N/A') . ', ' . ($currentLog['region'] ?? 'N/A') . ', ' . ($currentLog['country'] ?? 'N/A')) . "</strong></div>";
                $body .= "<div style=\"color: #0f2027; font-family: monospace; font-weight: bold;\">" . htmlspecialchars($currentLog['ip_address']) . "</div>";
                $body .= "<div style=\"color: #64748b; font-size: 12px; margin-top: 5px;\">" . $currentLog['login_time'] . " UTC</div>";
                $body .= "</td>";
                $body .= "</tr>";
                $body .= "</table>";
                $body .= "</div>"; // End padding div
                $body .= "</div>"; // End incident border div

                $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                $logStmt->execute([$currentLog['id'], $previousLog['id'], $incident['type']]);
            }

            // --- Display consolidated device changes at the bottom ---
            if (!empty($groupedDeviceChanges)) {
                $body .= "<div style=\"margin-top: 40px;\">";
                $body .= "<h2 style=\"margin-top: 0; color: #0f2027; text-transform: uppercase; font-size: 18px; border-bottom: 2px solid #f0f2f5; padding-bottom: 10px;\">Authentication Device Changes</h2>";
                
                foreach($groupedDeviceChanges as $user => $changes) {
                    $body .= "<div style=\"margin-bottom: 20px; border: 1px solid #cbd5e1; background-color: #ffffff;\">";
                    $body .= "<div style=\"padding: 10px 15px; background-color: #f8fafc; border-bottom: 1px solid #cbd5e1;\"><strong>User:</strong> <span style=\"font-weight: bold; color: #0f2027; font-size: 16px;\">" . htmlspecialchars($user) . "</span></div>";
                    $body .= "<div style=\"padding: 15px;\">";
                    
                    if (!empty($changes['Added'])) {
                        $body .= "<div style=\"margin-bottom: 10px;\"><strong style=\"color: #16a34a;\">Devices Added:</strong> " . htmlspecialchars(implode(', ', $changes['Added'])) . "</div>";
                    }
                    if (!empty($changes['Removed'])) {
                        $body .= "<div><strong style=\"color: #dc2626;\">Devices Removed:</strong> " . htmlspecialchars(implode(', ', $changes['Removed'])) . "</div>";
                    }
                    $body .= "</div></div>";
                }
                $body .= "</div>";
            }
            
            $body .= "</div>"; // End incidents section
            
            // Footer
            $body .= "<div style=\"padding: 20px; text-align: center; color: #64748b; font-size: 12px; border-top: 2px solid #e2e8f0;\">";
            $body .= "This is an automated message from your Entra Monitor instance.";
            $body .= "</div>";
            
            $body .= "</div>"; // End max-width wrapper
            $body .= "</div>"; // End background wrapper

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
        // Global switch to disable all user alerts
        if ($_ENV['DISABLE_ALL_USER_ALERTS'] ?? false) {
            return;
        }

        if (empty($userEmail) || !filter_var($userEmail, FILTER_VALIDATE_EMAIL)) {
            error_log("Invalid user email provided for alert: $userEmail");
            return;
        }

        // Check if user alerts are disabled for this email address
        $disabledUsers = $_ENV['DISABLED_USER_ALERTS'] ?? [];
        if (in_array($userEmail, $disabledUsers)) {
            return; // Do not send email
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

            $locationDisclaimer = "<div style=\"background-color: #f8fafc; border: 1px solid #cbd5e1; padding: 15px; margin-top: 20px; font-size: 13px; color: #64748b;\"><strong>Note on Location Accuracy:</strong> The location is determined based on the IP address of the successful login as recorded by Microsoft and may not be perfectly accurate. Connecting or disconnecting from a VPN service can also trigger these alerts. <strong style=\"color: #0f2027;\">As long as you are aware of this recent login, no further action is required.</strong></div>";

            $body = "<div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f0f2f5; padding: 20px; color: #1e293b; line-height: 1.5;\">";
            $body .= "<div style=\"max-width: 600px; margin: 0 auto; background-color: #ffffff; border-top: 5px solid #e63946; box-shadow: 0 2px 4px rgba(0,0,0,0.05);\">";

            switch ($alertType) {
                case 'impossible_travel':
                    $subject = 'Security Alert: Irregular Travel Speed Detected on Your Account';
                    $currentLog = $incidentData['current_log'];
                    $previousLog = $incidentData['previous_log'];
                    
                    $body .= "<div style=\"padding: 20px; border-bottom: 2px solid #e2e8f0; background-color: #fff1f2;\">";
                    $body .= "<h2 style=\"margin: 0; font-size: 20px; color: #b91c1c; text-transform: uppercase;\">Irregular Travel Detected</h2>";
                    $body .= "</div>";
                    $body .= "<div style=\"padding: 20px;\">";
                    $body .= "<p style=\"margin-top: 0; font-size: 16px;\">We have detected a login to your account from a location that is considered impossible or irregular to reach in the time elapsed when compared to other logins in the last 24 hours.</p>";
                    
                    $body .= "<table width=\"100%\" cellpadding=\"15\" style=\"border-collapse: collapse; font-size: 14px; margin-bottom: 20px; border: 1px solid #cbd5e1;\">";
                    $body .= "<tr><td style=\"background-color: #f8fafc; border-bottom: 1px solid #cbd5e1;\">";
                    $body .= "<div style=\"font-weight: bold; color: #64748b; margin-bottom: 5px; text-transform: uppercase; font-size: 12px;\">Previous Login Location</div>";
                    $body .= "<div style=\"margin-bottom: 5px;\"><strong>" . htmlspecialchars(($previousLog['city'] ?? 'N/A') . ', ' . ($previousLog['region'] ?? 'N/A') . ', ' . ($previousLog['country'] ?? 'N/A')) . "</strong></div>";
                    $body .= "<div style=\"color: #64748b; font-family: monospace;\">" . htmlspecialchars($previousLog['ip_address']) . "</div>";
                    $body .= "<div style=\"color: #64748b; font-size: 12px; margin-top: 5px;\">" . $previousLog['login_time'] . " UTC</div>";
                    $body .= "</td></tr>";
                    $body .= "<tr><td style=\"background-color: #ffffff;\">";
                    $body .= "<div style=\"font-weight: bold; color: #b91c1c; margin-bottom: 5px; text-transform: uppercase; font-size: 12px;\">Anomalous Login Location</div>";
                    $body .= "<div style=\"margin-bottom: 5px;\"><strong>" . htmlspecialchars(($currentLog['city'] ?? 'N/A') . ', ' . ($currentLog['region'] ?? 'N/A') . ', ' . ($currentLog['country'] ?? 'N/A')) . "</strong></div>";
                    $body .= "<div style=\"color: #0f2027; font-family: monospace; font-weight: bold;\">" . htmlspecialchars($currentLog['ip_address']) . "</div>";
                    $body .= "<div style=\"color: #64748b; font-size: 12px; margin-top: 5px;\">" . $currentLog['login_time'] . " UTC</div>";
                    $body .= "</td></tr>";
                    $body .= "</table>";
                    
                    $body .= "<div style=\"background-color: #fef2f2; border-left: 4px solid #e63946; padding: 15px; color: #b91c1c; font-weight: bold;\">If this was not you or you do not recognize this location change, please contact your IT support immediately.</div>";
                    $body .= $locationDisclaimer;
                    $body .= "<div style=\"margin-top: 20px; font-size: 12px; color: #94a3b8;\"><i>Note: A single recent sign-in may generate multiple detections if it is anomalous when compared against several different logins from the past 24 hours.</i></div>";
                    $body .= "</div>"; // End padding div
                    
                    $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                    $logStmt->execute([$currentLog['id'], $previousLog['id'], 'user_impossible_travel']);
                    break;

                case 'region_change':
                    $subject = 'Security Alert: New Sign-in From a Different Region';
                    $currentLog = $incidentData['current_log'];
                    $previousLog = $incidentData['previous_log'];
                    
                    $body .= "<div style=\"padding: 20px; border-bottom: 2px solid #e2e8f0; background-color: #f0f9ff;\">";
                    $body .= "<h2 style=\"margin: 0; font-size: 20px; color: #0369a1; text-transform: uppercase;\">Sign-in from New Region</h2>";
                    $body .= "</div>";
                    $body .= "<div style=\"padding: 20px;\">";
                    $body .= "<p style=\"margin-top: 0; font-size: 16px;\">We have detected a login to your account from a different region than your usual activity from the last 24 hours.</p>";
                    
                    $body .= "<table width=\"100%\" cellpadding=\"15\" style=\"border-collapse: collapse; font-size: 14px; margin-bottom: 20px; border: 1px solid #cbd5e1;\">";
                    $body .= "<tr><td style=\"background-color: #f8fafc; border-bottom: 1px solid #cbd5e1;\">";
                    $body .= "<div style=\"font-weight: bold; color: #64748b; margin-bottom: 5px; text-transform: uppercase; font-size: 12px;\">Previous Login Location</div>";
                    $body .= "<div style=\"margin-bottom: 5px;\"><strong>" . htmlspecialchars(($previousLog['region'] ?? 'N/A') . ', ' . ($previousLog['country'] ?? 'N/A')) . "</strong></div>";
                    $body .= "</td></tr>";
                    $body .= "<tr><td style=\"background-color: #ffffff;\">";
                    $body .= "<div style=\"font-weight: bold; color: #0369a1; margin-bottom: 5px; text-transform: uppercase; font-size: 12px;\">New Login Location</div>";
                    $body .= "<div style=\"margin-bottom: 5px;\"><strong>" . htmlspecialchars(($currentLog['region'] ?? 'N/A') . ', ' . ($currentLog['country'] ?? 'N/A')) . "</strong></div>";
                    $body .= "<div style=\"color: #0f2027; font-family: monospace; font-weight: bold;\">" . htmlspecialchars($currentLog['ip_address']) . "</div>";
                    $body .= "<div style=\"color: #64748b; font-size: 12px; margin-top: 5px;\">" . $currentLog['login_time'] . " UTC</div>";
                    $body .= "</td></tr>";
                    $body .= "</table>";
                    
                    $body .= "<div style=\"background-color: #fef2f2; border-left: 4px solid #e63946; padding: 15px; color: #b91c1c; font-weight: bold;\">If this was not you or you do not recognize this location change, please contact your IT support immediately.</div>";
                    $body .= $locationDisclaimer;
                    $body .= "<div style=\"margin-top: 20px; font-size: 12px; color: #94a3b8;\"><i>Note: A single recent sign-in may generate multiple detections if it is anomalous when compared against several different logins from the past 24 hours.</i></div>";
                    $body .= "</div>"; // End padding div
                    
                    $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                    $logStmt->execute([$currentLog['id'], $previousLog['id'], 'user_region_change']);
                    break;

                case 'auth_device_change':
                    $subject = 'Security Alert: Authentication Device Changed on Your Account';
                    $change = $incidentData['change'];
                    $device = $incidentData['device'];
                    $color = strtolower($change) === 'added' ? '#16a34a' : '#dc2626';
                    $bgColor = strtolower($change) === 'added' ? '#f0fdf4' : '#fef2f2';
                    
                    $body .= "<div style=\"padding: 20px; border-bottom: 2px solid #e2e8f0; background-color: #0f2027; color: white;\">";
                    $body .= "<h2 style=\"margin: 0; font-size: 20px; text-transform: uppercase;\">Authentication Device Change</h2>";
                    $body .= "</div>";
                    $body .= "<div style=\"padding: 20px;\">";
                    $body .= "<p style=\"margin-top: 0; font-size: 16px;\">An authentication method was recently <strong style=\"color: " . $color . ";\">" . strtoupper($change) . "</strong> for your account.</p>";
                    
                    $body .= "<div style=\"margin: 20px 0; padding: 20px; background-color: " . $bgColor . "; border: 1px solid #cbd5e1; border-left: 4px solid " . $color . "; font-size: 18px;\">";
                    $body .= "<strong>Device/Method:</strong> " . htmlspecialchars($device);
                    $body .= "</div>";
                    
                    $body .= "<div style=\"background-color: #fef2f2; border-left: 4px solid #e63946; padding: 15px; color: #b91c1c; font-weight: bold;\">If this was not you or you do not recognize this device change, please contact your IT support immediately.</div>";
                    $body .= "<p style=\"font-size: 13px; color: #64748b; margin-top: 15px;\">Note that selecting 'remember sign-in' or 'trust device/browser' may trigger a new added device on your account, which are automatically removed after a few days.</p>";
                    $body .= "</div>"; // End padding div
                    
                    $logStmt = $db->prepare("INSERT INTO email_alerts (alert_log_id, compared_log_id, alert_type) VALUES (?, ?, ?)");
                    $logStmt->execute([0, 0, 'user_auth_device_change']);
                    break;
            }

            $body .= "<div style=\"padding: 20px; text-align: center; color: #94a3b8; font-size: 12px; border-top: 2px solid #e2e8f0;\">";
            $body .= "This is an automated security notification.";
            $body .= "</div>";
            
            $body .= "</div>"; // End max-width wrapper
            $body .= "</div>"; // End background wrapper

            $mail->Subject = $subject;
            $mail->Body = $body;
            $mail->send();

        } catch (Exception $e) {
            error_log("User Mailer Error for $userEmail: {$mail->ErrorInfo}");
        }
    }

    /**
     * Sends a generic HTML email.
     * 
     * @param string $to Recipient email address
     * @param string $subject Email subject
     * @param string $htmlBody HTML content of the email
     * @param array $ccRecipients Optional list of CC email addresses
     */
    public function sendHtmlEmail(string $to, string $subject, string $htmlBody, array $ccRecipients = []): void {
        if (empty($to) || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
            error_log("Invalid recipient email provided: $to");
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
            $mail->addAddress($to);

            if (!empty($ccRecipients)) {
                foreach ($ccRecipients as $email) {
                    $trimmedEmail = trim($email);
                    if (filter_var($trimmedEmail, FILTER_VALIDATE_EMAIL)) {
                        $mail->addCC($trimmedEmail);
                    }
                }
            }

            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $htmlBody;

            $mail->send();
        } catch (Exception $e) {
            error_log("Generic Mailer Error: {$mail->ErrorInfo}");
            throw $e;
        }
    }
}
