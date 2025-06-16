# Entra Impossible Travel & Anomaly Monitor

![Security Shield](https://img.shields.io/badge/Security-Monitoring-blue)
![PHP](https://img.shields.io/badge/PHP-8.x-purple)
![Database](https://img.shields.io/badge/Database-MySQL%2FMariaDB-orange)

A standalone PHP application to monitor Microsoft Entra (Azure AD) sign-in logs for suspicious activity. It automatically flags impossible travel events and cross-region logins, sends consolidated email alerts for critical incidents, and provides a simple web UI for reviewing all activity.

---

## Features

-   **Impossible Travel Detection**: Calculates the speed of travel between login locations. Flags events that exceed a configurable speed threshold for UI review, but only sends an email alert if both compared logins were successful.
-   **Region Change Alerts**: Detects when a user logs in from a different state or province within a 24-hour window. An alert is only generated if both logins being compared were successful.
-   **Consolidated Email Alerts**: Sends a single digest email per run, summarizing all detected incidents with a breakdown by type and user count to prevent inbox spam.
-   **Intelligent Alerting**: Email alerts for critical incidents are only sent when there is a high confidence of anomalous activity (e.g., successful logins).
-   **Web UI for Review**: A secure, login-protected dashboard to review all impossible travel alerts, region change alerts, and a history of all recent sign-ins. It also indicates which alerts triggered an email notification.
-   **Automated & Manual Processing**: A cron job runs the monitoring script at a configurable interval, and a button in the UI allows for immediate, on-demand syncs.
-   **Secure by Design**: Uses a `secrets.php` file (not committed to version control) to store all credentials and has a secure-by-default file structure.

---

## How It Works

The application operates in two main parts: a background processor and a web UI.

### 1. The Background Processor (`run_background_task.php`)

This script is designed to be run by a cron job at regular intervals (e.g., every 10-15 minutes). On each run, it performs the following steps:
1.  **Fetches Logs**: Connects to the Microsoft Graph API and retrieves the latest 500 sign-in logs.
2.  **Processes Each Log**: For each new sign-in log, it:
    * Retrieves the IP address geolocation (using a local cache to minimize external lookups).
    * Compares the current login against all other logins for that same user in the last 24 hours.
    * **Flags Impossible Travel**: Flags any event exceeding the speed threshold for UI review. An incident is added to the email digest only if both the current and compared logins were successful.
    * **Flags Region Change**: Flags any event where a user logs in from a different state/province. An alert is only generated for the UI and email if both the current and compared logins were successful.
3.  **Consolidates & Sends Email**: It collects all qualifying incidents, builds a summary digest with statistics, and sends a single email to all configured recipients. For each alert sent, a record is created in the `email_alerts` table.
4.  **Prunes Old Data**: Automatically deletes logs from the `login_logs` table that are older than 180 days.

### 2. The Web UI (`public/index.php`)

The web UI provides a convenient way to visualize the data collected by the background processor.
-   It is protected by a local username and password stored in the `admins` database table.
-   It displays separate tables for **Impossible Travel Alerts** and **Region Change Alerts**, each with a new "Email Sent" column indicating if a notification was generated and when.
-   It includes buttons to manually trigger a background sync and to export various logs to CSV files.

---

## Requirements

-   A web server (Nginx is recommended)
-   PHP 8.x (with `pdo_mysql` and `curl` or `guzzle` support)
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
- Run the SQL commands in the `dbsetup.txt` file to create all the necessary tables.
- **Security Note**: The setup script creates a default user `admin` with the password `password`. Please change this immediately.

### 3. Microsoft Entra App Registration
Register an application in your Microsoft Entra ID tenant to grant this script permission to read the sign-in logs.

1.  Navigate to the **Microsoft Entra admin center**.
2.  Go to **Identity > Applications > App registrations** and click **+ New registration**.
3.  Give the app a descriptive name (e.g., `Impossible Travel Monitor`).
4.  Select "Accounts in this organizational directory only."
5.  Click **Register**.
6.  Copy the **Application (client) ID** and the **Directory (tenant) ID** from the "Overview" page.
7.  Go to **Certificates & secrets**, click **+ New client secret**, and **immediately copy the secret's "Value"**.
8.  Go to **API permissions**, click **+ Add a permission**, select **Microsoft Graph**, and choose **Application permissions**.
9.  Search for and add `AuditLog.Read.All` and `User.Read.All`.
10. Click the **"Grant admin consent for [Your Tenant]"** button.

### 4. Application Configuration
- Rename the `generic_secrets.php` file to `secrets.php`.
- Open `secrets.php` and fill in all the required values:
  - Your database credentials.
  - The three Microsoft Entra values you just copied (Tenant ID, Client ID, and Client Secret).
  - Your SMTP server details for sending email alerts.
  - Update the value for `IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD` if you want a different sensitivity

### 5. Web Server Configuration (Nginx Example)
For security, your web server's document root should point to the project's main directory, and access to sensitive files should be blocked. A front controller pattern is used, where all requests are routed through `/nofly-monitor/public/index.php`.

Here is a sample Nginx configuration block:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    root /var/www/html/; # Path to the directory containing 'nofly-monitor'
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

    # Deny direct browser access to sensitive files
    location ~ /nofly-monitor/(src|vendor|sessions|logs-6Tnx-HLFW)/ { deny all; }
    location = /nofly-monitor/(secrets.php|run_background_task.php|reprocess_logs.php|fix_regions.php|composer.json|composer.lock|composer.phar) { deny all; }
}
```

### 6. Cron Job Setup
- Set up a cron job on your host server to run the background task automatically. Running it every 10-15 minutes is a good starting point.
- Open your crontab for editing: `crontab -e`
- Add the following line, making sure to use the correct full paths for your server.

```bash
# Run the Entra log sync every 10 minutes and log output to a timestamped file
*/10 * * * * /usr/bin/php /path/to/your/project/nofly-monitor/run_background_task.php >> /var/log/nofly-monitor/cron_$(date +\%Y\%m\%d-\%H\%M\%S).log 2>&1

# Prune the cron log files older than 14 days, runs once a day at midnight
0 0 * * * find /var/log/nofly-monitor/ -type f -name '*.log' -mtime +14 -delete
```

---

## Configuration Options

All configuration is handled in the `secrets.php` file.

-   `IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD`: The maximum speed in km/h that a user can "travel" between logins before an alert is generated. A value of `800` is a good starting point, as it's difficult to achieve this speed with commercial air travel when factoring in time to get to/from airports.
-   `ADMIN_ALERT_EMAIL`: The primary email address that receives the alert digests.
-   `MAILER_CC_RECIPIENTS`: A comma-separated list of additional email addresses to CC on the alerts.

---
