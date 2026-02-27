# Entra Impossible Travel & Anomaly Monitor

![Security Shield](https://img.shields.io/badge/Security-Monitoring-blue)
![PHP](https://img.shields.io/badge/PHP-8.x-purple)
![Database](https://img.shields.io/badge/Database-MySQL%2FMariaDB-orange)

A standalone PHP application to monitor Microsoft Entra (Azure AD) sign-in logs for suspicious activity. It automatically flags impossible travel events and cross-region logins, sends consolidated email alerts for critical incidents, and provides a simple web UI for reviewing all activity.

---

## Features

-   **Impossible Travel Detection**: Flags events that exceed a configurable speed threshold. The UI will show all such events, but an email alert is only sent if both compared logins were successful and the IP is not whitelisted.
-   **Region Change Alerts**: Detects when a user has successful logins in two different states/provinces. The UI will display all such changes, but an email alert is only sent if the distance between the locations is greater than a configurable threshold and the IP is not whitelisted.
-   **Authentication Device Monitoring**: Tracks when users add or remove Multi-Factor Authentication (MFA) devices (like Authenticator Apps or Security Keys) and includes these changes in the UI and email alerts.
-   **IP Whitelisting**: A manageable list in the UI to add trusted IP addresses (like corporate VPNs or offices). Whitelisted IPs will still have their anomalies logged but will be suppressed from email alerts to reduce noise.
-   **Consolidated Email Alerts**: Sends a single digest email per run, summarizing all detected incidents with a breakdown by type and user count to prevent inbox spam.
-   **Web UI for Review**: A secure, login-protected dashboard to review all impossible travel alerts, region change alerts, and a filterable history of all recent sign-ins. It also indicates which specific alerts triggered an email notification.
-   **User IP Report**: A dedicated web page to search for any user and review a list of all IP addresses they have successfully logged in from over the last 30 days.
-   **Weekly Email Digest**: An independent script to generate a weekly consolidated summary showing every user's detection counts and successful login locations compared to the prior week.
-   **Automated & Manual Processing**: Includes scripts for automated cron job execution, manual on-demand syncs, historical data reprocessing, and data cleanup.
-   **Flexible Data Exports**: A consolidated dropdown menu in the UI allows for exporting alerts or sign-in logs from various timeframes (24 hours, 7 days, 30 days, or all time) to CSV.

---

## How It Works

The application operates in two main parts: a background processor and a web UI.

### 1. The Background Processor (`run_background_task.php`)

This script is designed to be run by a cron job at regular intervals (e.g., every 10-15 minutes). On each run, it performs the following steps:
1.  **Fetches Logs**: Connects to the Microsoft Graph API and retrieves the latest sign-in logs.
2.  **Processes Each Log**: For each new sign-in log, it:
    * Retrieves the IP address geolocation (using a local cache to minimize external lookups).
    * Compares the current login against all other logins for that same user in the last 24 hours.
    * **Flags Impossible Travel**: Flags any event exceeding the speed threshold for the UI.
    * **Flags Region Change**: Flags any change in state/province between two successful logins for the UI.
    * **Checks for Device Changes**: For each unique user in the log batch, it compares their current MFA devices in Entra against a saved snapshot in the local database. Any added or removed devices are flagged as incidents.
3.  **Builds Email Digest**: It collects all incidents that meet the stricter criteria for email alerts (e.g., not whitelisted, region change distance exceeded) into a single list.
4.  **Sends Email**: If any email-worthy incidents were found, it sends one single, consolidated email digest to all configured recipients and logs the sent alerts in the `email_alerts` table.
5.  **Prunes Old Data**: Automatically deletes logs from the `login_logs` table that are older than 180 days.

### 2. The Web UI (`public/index.php`)

The web UI provides a convenient way to visualize and manage the data collected by the background processor.
-   It is protected by a local username and password stored in the `admins` database table.
-   It includes a **IP Whitelist Management** section to add and remove trusted IPs.
-   It includes a **Authentication Device Changes** section to display recent MFA updates.
-   It displays separate tables for **Impossible Travel Alerts** and **Region Change Alerts**, each with an "Email Sent" column indicating if a notification was generated.
-   The main log view is now conveniently filtered to the **last 24 hours**.
-   It includes buttons to **Manually Trigger Sync** and to **Reprocess All Logs** (with a confirmation warning).
-   A new expandable **Help Section** explains the application logic and features.

---

## Requirements

-   A web server (Nginx is recommended)
-   PHP 8.x (with `pdo_mysql` and `guzzle` support)
-   MySQL or MariaDB Database
-   An SMTP server for sending email alerts
-   [Composer](https://getcomposer.org/) for managing PHP dependencies

---

## Setup Guide

### 1. Initial Setup
- Run `composer install` in the project's root directory.
- Create two empty directories in the project root: `sessions` and a log folder (e.g., `logs-6Tnx-HLFW`). Ensure the web server user has write permissions to both.

### 2. Database Setup
- Connect to your MySQL/MariaDB server and create a new database.
- Run the SQL commands in the `dbsetup.txt` file to create all the necessary tables (`admins`, `login_logs`, `ip_geolocation_cache`, `email_alerts`, `ip_whitelist`).
- **Security Note**: The setup script creates a default user `admin` with the password `password`. Please change this to something else, preferably a different username as well. The password is stored as a bcrypt hash.

### 3. Microsoft Entra App Registration
Register an application in your Microsoft Entra ID tenant to grant this script permission to read the sign-in logs.

1.  Navigate to the **Microsoft Entra admin center**.
2.  Go to **Identity > Applications > App registrations** and click **+ New registration**.
3.  Give the app a descriptive name (e.g., `365 Login Monitor`).
4.  Select "Accounts in this organizational directory only."
5.  Click **Register**.
6.  Copy the **Application (client) ID** and the **Directory (tenant) ID**.
7.  Go to **Certificates & secrets**, click **+ New client secret**, and **immediately copy the secret's "Value"**.
8.  Go to **API permissions**, click **+ Add a permission**, select **Microsoft Graph**, and choose **Application permissions**.
9.  Search for and add `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, and `User.Read.All`.
10. Click the **"Grant admin consent for [Your Tenant]"** button.

### 4. Application Configuration
- Rename the `generic_secrets.php` file to `secrets.php`.
- Open `secrets.php` and fill in all the required values for your database, Entra application, and SMTP server.
- Adjust the `IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD` and `REGION_CHANGE_IGNORE_KM` values to fit your organization's needs.

### 5. Web Server Configuration (Nginx Example)
A front controller pattern is used, where all requests are routed through `/nofly-monitor/public/index.php`. The following Nginx configuration is recommended for security and proper routing.

```nginx
server {
    listen 80;
    server_name your-domain.com;

    root /var/www/html; # Path to the directory containing 'nofly-monitor'
    index index.php;

    location /nofly-monitor {
        try_files $uri $uri/ /nofly-monitor/public/index.php?$query_string;
    }

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php-fpm.sock; # Or your PHP-FPM socket/address
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    # Deny direct browser access to all sensitive files and directories
    location ~ /nofly-monitor/(src|vendor|sessions|logs-6Tnx-HLFW)/ { deny all; }
    location ~* /nofly-monitor/(secrets.php|run_background_task.php|reprocess_logs.php|fix_regions.php|composer.*)$ { deny all; }
}
```

### 6. Cron Job Setup
- Set up a cron job on your host server to run the background task automatically. Running it every 10-15 minutes is a good starting point.
- Open your crontab for editing: `crontab -e`
- Add the following lines, making sure to use the correct full paths for your server.

```bash
# Run the Entra log sync every 10 minutes and log output to a timestamped file
*/10 * * * * /usr/bin/php /path/to/your/project/nofly-monitor/run_background_task.php >> /var/log/nofly-monitor/cron_$(date +\%Y\%m\%d-\%H\%M\%S).log 2>&1

# Generate a weekly digest email of all user activity every Sunday at 8 AM
0 8 * * 0 /usr/bin/php /path/to/your/project/nofly-monitor/generate_weekly_digest.php >> /var/log/nofly-monitor/weekly_digest.log 2>&1

# Prune the cron log files older than 14 days, runs once a day at midnight
0 0 * * * find /var/log/nofly-monitor/ -type f -name '*.log' -mtime +14 -delete
```

---

## Configuration Options

All configuration is handled in the `secrets.php` file.

-   `IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD`: The maximum speed in km/h that a user can "travel" between logins before an alert is generated. A value of `800` is a good starting point, as it's difficult to achieve this speed with commercial air travel when factoring in time to get to/from airports.
-   `ADMIN_ALERT_EMAIL`: The primary email address that receives the alert digests.
-   `MAILER_CC_RECIPIENTS`: A comma-separated list of additional email addresses to CC on the alerts.
-   `REGION_CHANGE_IGNORE_KM`: Do not send an email for a region change if the distance between the two locations is less than this value (in km). This is useful for users who live near state/province borders.

---

## Security Considerations

-   **File Permissions**: Ensure that your web server user (e.g., `www-data`, `nobody`) has write permissions for the `/sessions` directory. All other application files should be read-only for the web server user.
-   **Web UI Access**: The web UI is protected by the local application login. For enhanced security, consider placing it behind an IP whitelist, a VPN, or a Zero Trust solution like Cloudflare Access.
-   **Headless Operation**: The application can run perfectly well without the Web UI. If you do not need it, you can block all web access to the `/nofly-monitor` directory in your server configuration for maximum security.

## Upgrading from a Previous Version

If you are upgrading from a version that did not include authentication device monitoring, follow these steps:

**Update Database**: Run the following SQL commands on your database to add the new tables required for this feature.

```sql
CREATE TABLE `user_auth_devices` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` VARCHAR(255) NOT NULL,
  `device_id` VARCHAR(255) NOT NULL,
  `display_name` VARCHAR(255) NULL,
  `device_type` VARCHAR(255) NULL,
  `last_seen` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `user_device_unique` (`user_id`, `device_id`)
);

CREATE TABLE `auth_device_changes` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` VARCHAR(255) NOT NULL,
  `user_principal_name` VARCHAR(255) NOT NULL,
  `device_display_name` VARCHAR(255) NULL,
  `change_type` VARCHAR(50) NOT NULL,
  `change_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `user_id_idx` (`user_id`),
  INDEX `change_time_idx` (`change_time`)
);
```

**Update App Permissions**: In the Microsoft Entra admin center, navigate to your app registration's API permissions and add the `UserAuthenticationMethod.Read.All` permission. Remember to Grant admin consent.

**Update Application Files**: Replace your old application files with the latest versions, paying special attention to:

`src/GraphHelper.php`

`src/LogProcessor.php`

`src/Mailer.php`

`public/index.php`

`public/style.css`

**Populate Initial Device Data**: To establish a baseline of current devices, run the new helper script from your host machine's command line. This is a crucial one-time step.

```bash
/path/to/php /path/to/your/project/nofly-watch/populate_devices.php
```

This will populate the `user_auth_devices` table. From this point on, the main `run_background_task.php` script will automatically detect any changes from this baseline. You can delete the `populate_devices.php` file afterwards as it is no longer needed, or you may want to block public web access to it.
