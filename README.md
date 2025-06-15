# entra-nofly-monitor
Retrieve sign in logs from Entra and calculate travel time between them, send alerts for anomalous successful logins, log everything else

# Requirements
NGINX/Apache Webserver, PHP (with curl and PDO), MySQL/MariaDB, SMTP server to send email alerts

# Setup
1. composer install
2. create directory 'sessions'
3. block public access to the following: './sessions', './src', './[yourlogfolder]', './vendor', 'secrets.php', 'composer.phar', 'composer.json', 'composer.lock', '.env'
4. Update 'BASE_PATH' on public/index.php line 2 with the path where the publicly accessible index.php file will be. For example if needs to be accessed on https://example.com/nofly-monitor/public/index.php then your BASE_PATH is '/nofly-monitor/public/index.php'
5. Go to Microsoft Entra, Identity > Applications > App Registrations > + New Registration, give your app a name you can identify
6. Take note of your: Application (client) ID, and Directory (tenant) ID
7. Go to Certificate & Secrets, click on + New Client Secret, give it a name, done. Take note of the "Value" of this secret.
8. On MariaDB or MySQL create your table. Run the required setup. The commands are on the dbsetup.txt file. Make sure you update your admin password hash (it's in Bcrypt), feel free to use a different admin username.
9. Fill in the generic_secrets.php file with the required information. Rename the file to secrets.php
10. Setup cron to run php and trigger run_background_task.php. I recommend every 15 minutes, more or less frequent depending on how busy your org is. Just don't abuse it to avoid the wrath of the Microsoft gods. Feel free to pipe the output to a log file to help track changes or errors.
11. Also, the index.php has a manual trigger button for the background tasks. Make sure you update the log path on line 94 where you want to save the logs.

# Considerations
You may want to add captcha on the web ui login, or basic auth. You can also use zero trust to hide the web ui from public.

You can also use this without the web ui at all and block full public/webui access. It's provided for convenience.

You may also want to adjust the speed limit set on the secrets.php file. I find around 400km/h (roughly 250mph) to be adequeate to detect unusual travel. It's just under average time for short flights (including boarding and deplaning timing).

# Additional Notes on logic
It does check each login against all other logins for the same user in the last 24 hours. It may generate multiple alerts for one recent login against multiple older login times in the last 24 hours.
The email alert is only set to email for two anomalous successful logins. The web ui will present all anomalous logins regardless of successful login or not.

# Warranty
There is none. Good luck, have fun?
