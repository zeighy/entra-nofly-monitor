# Entra Impossible Travel Monitor

![Security Shield](https://img.shields.io/badge/Security-Monitoring-blue)
![PHP](https://img.shields.io/badge/PHP-8.x-purple)
![Database](https://img.shields.io/badge/Database-MySQL%2FMariaDB-orange)

A standalone PHP application to monitor Microsoft Entra (Azure AD) sign-in logs for suspicious activity. It automatically flags impossible travel events and cross-region logins, sends consolidated email alerts for critical incidents, and provides a simple web UI for reviewing all activity.

---

## Features

-   **Impossible Travel Detection**: Calculates the speed of travel between login locations and flags any that exceed a configurable speed threshold.
-   **Region Change Alerts**: Detects when a user logs in from a different state or province within a 24-hour window.
-   **Consolidated Email Alerts**: Sends a single digest email per run, summarizing all detected incidents to prevent inbox spam.
-   **Intelligent Alerting**: Email alerts are only sent for incidents involving successful logins, reducing noise from failed attempts.
-   **Web UI for Review**: A secure, login-protected dashboard to review all impossible travel alerts, region change alerts, and a history of all recent sign-ins.
-   **Automated Background Processing**: A simple cron job runs the monitoring script at a configurable interval.
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
    * **Flags Impossible Travel**: If the calculated speed between the current login and any previous login exceeds the `IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD`, it flags the event.
    * **Flags Region Change**: If the state/province of the current login is different from any previous login in the last 24 hours, it flags the event.
3.  **Consolidates Alerts**: It collects all incidents that should trigger an email (successful impossible travel logins and successful region changes) into a single list.
4.  **Sends Email**: If any incidents were found, it sends one single, consolidated email digest to the administrator and any CC recipients.
5.  **Prunes Old Data**: Automatically deletes logs from the database that are older than 180 days to conserve space.

### 2. The Web UI (`public/index.php`)

The web UI provides a convenient way to visualize the data collected by the background processor.
-   It is protected by a local username and password stored in the `admins` database table.
-   It displays separate tables for high-priority **Impossible Travel Alerts**, medium-priority **Region Change Alerts**, and a comprehensive log of all recent sign-ins.
-   It includes buttons to manually trigger a background sync and to export alert data to CSV files for reporting.

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
- Run `composer install` in the project's root directory to download the required PHP libraries.
- Create an empty directory named `sessions` in the project root (`/nofly-monitor/sessions`). The application will use this to store session data.

### 2. Database Setup
- Connect to your MySQL/MariaDB server.
- Create a new database for the application.
- Run the SQL commands in the `dbsetup.txt` file to create all the necessary tables (`admins`, `login_logs`, `ip_geolocation_cache`).
- **Security Note**: The setup script creates a default user `admin` with the password `password`. It is highly recommended that you change this password (its in Bcrypt hash) and use a different username from `admin`.

### 3. Microsoft Entra App Registration
You need to register an application in your Microsoft Entra ID tenant to grant this script permission to read the sign-in logs.

 1. Navigate to the **Microsoft Entra admin center**.
 2. Go to **Identity > Applications > App registrations** and click **+ New registration**.
 3. Give your app a descriptive name (e.g., `Microsoft 365 Login Monitor`).
 4. For "Supported account types," select "Accounts in this organizational directory only."
 5. Click **Register**.
 6. On the app's "Overview" page, copy the **Application (client) ID** and the **Directory (tenant) ID**.
 7. Go to the **Certificates & secrets** tab, click **+ New client secret**, give it a description, and set an expiry. **Immediately copy the secret's "Value"**. You will not be able to see it again after you leave the page.
 8. Go to the **API permissions** tab, click **+ Add a permission**, and select **Microsoft Graph**.
 9. Choose **Application permissions**.
10. Search for and add the following permissions:
    * `AuditLog.Read.All`
    * `User.Read.All`
11. Click the **"Grant admin consent for [Your Tenant]"** button. The status for the permissions should change to "Granted".

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

    root /var/www/html; # Path to the directory containing 'nofly-monitor'
    index index.php;

    location /nofly-monitor {
        try_files $uri $uri/ /nofly-monitor/index.php?$query_string;
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
    location ~ /nofly-monitor/(src|vendor|sessions)/ { deny all; }
    location = /nofly-monitor/secrets.php { deny all; }
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

## Security Considerations

-   **File Permissions**: Ensure that your web server user (e.g., `www-data`, `nobody`) has write permissions for the `/sessions` directory. All other application files should be read-only for the web server user.
-   **Web UI Access**: The web UI is protected by the local application login. For enhanced security, consider placing it behind an IP whitelist, a VPN, or a Zero Trust solution like Cloudflare Access.
-   **Headless Operation**: The application can run perfectly well without the Web UI. If you do not need it, you can block all web access to the `/nofly-monitor` directory in your server configuration for maximum security.

---
