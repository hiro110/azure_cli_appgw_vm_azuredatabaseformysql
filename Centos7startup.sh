#!/bin/bash

##############################################
#
# *** Disabled SELinux ***
# *** Set JST to SystemClock, HardwareClock ***
# *** Change Keyborad Layout ***
# *** Create Develop User ***
# *** Add Timestamp to History ***
# *** Create Swap File ***
# *** Change NTP Server ***
# *** Edit sshd_config ***
# *** Install Package ***
# **** apache, git, openssl, epel, php ****
# **** MySQL Client ****
# *** Add Auto Startup httpd service ***
# *** Edit virtual host config ***
# **** Create Server Name ****
# **** Create security.conf ****
# **** Create Production Environment httpd.conf ***
# **** Create Test Environment httpd.conf ***
# **** Change virtual host config owner ****
# **** Remove Unnneccesary files ****
# *** Edit php.ini ***
# *** Create Project Directory ***
# *** Create Dummy Index.html ***
# *** Create Synbolic Link ***
# *** Set Basic Authentication (Test Environment Only) ***
# *** Edit mackerel.conf ***
#
##############################################

VM_ADMIN_NAME="vm-admin"

PROD_HOST="example.jp"
TEST_HOST="test.example.jp"

DEVELOPER_NAME="developer"
DEVELOPER_PASSPHRESE="developer"

BASIC_AUTH_ID="test"
BASIC_AUTH_PASS="test"

# --------------------------------------------------------------
# *** Disabled SELinux ***
sudo setenforce 0
sudo cp -p /etc/selinux/config /etc/selinux/config.`date "+%Y%m%d_%H%M%S"`
sudo sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config

# *** Set JST to SystemClock, HardwareClock ***
sudo timedatectl set-timezone Asia/Tokyo
sudo timedatectl set-local-rtc 0

# *** Change Keyborad Layout ***
sudo localectl set-locale LANG=ja_JP.utf8
sudo localectl set-keymap jp106

# *** Create Develop User ***
sudo useradd ${DEVELOPER_NAME}

# *** Add Timestamp to History ***
sudo cp -p /home/${VM_ADMIN_NAME}/.bashrc /home/${VM_ADMIN_NAME}/.bashrc.org
sudo sed -i "$ a # show timestamp\nHISTTIMEFORMAT='%Y-%m-%d %T%z '" /home/${VM_ADMIN_NAME}/.bashrc
sudo cp -p /home/${DEVELOPER_NAME}/.bashrc /home/${DEVELOPER_NAME}/.bashrc.org
sudo sed -i "$ a # show timestamp\nHISTTIMEFORMAT='%Y-%m-%d %T%z '" /home/${DEVELOPER_NAME}/.bashrc

# *** Create Swap File ***
sudo cp -p /etc/waagent.conf /etc/waagent.conf.`date "+%Y%m%d_%H%M%S"`
sudo sed -i 's/ResourceDisk.EnableSwap=n/ResourceDisk.EnableSwap=y/' /etc/waagent.conf
sudo sed -i 's/ResourceDisk.SwapSizeMB=0/ResourceDisk.SwapSizeMB=7168/' /etc/waagent.conf

# *** Change NTP Server ***
sudo cp -p /etc/chrony.conf /etc/chrony.conf.`date "+%Y%m%d_%H%M%S"`
sudo sed -i -e "s/server 0.centos.pool.ntp.org iburst/#server 0.centos.pool.ntp.org iburst/g" /etc/chrony.conf
sudo sed -i -e "s/server 1.centos.pool.ntp.org iburst/#server 1.centos.pool.ntp.org iburst/g" /etc/chrony.conf
sudo sed -i -e "s/server 2.centos.pool.ntp.org iburst/#server 2.centos.pool.ntp.org iburst/g" /etc/chrony.conf
sudo sed -i -e "s/server 3.centos.pool.ntp.org iburst/#server 3.centos.pool.ntp.org iburst/g" /etc/chrony.conf
sudo sed -i '1s/^/server 3.jp.pool.ntp.org iburst\n/' /etc/chrony.conf
sudo sed -i '1s/^/server 2.jp.pool.ntp.org iburst\n/' /etc/chrony.conf
sudo sed -i '1s/^/server 1.jp.pool.ntp.org iburst\n/' /etc/chrony.conf
sudo sed -i '1s/^/server 0.jp.pool.ntp.org iburst\n/' /etc/chrony.conf
sudo sed -i '1s/^/# NTP POOL PROJECT\n/' /etc/chrony.conf

# *** Edit sshd_config ***
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.org
sudo sed -i -e 's/#Port 22/Port 10022/g' /etc/ssh/sshd_config
sudo sed -i -e 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config

# *** Install Package ***
# **** apache, git, openssl, epel, php ****
sudo yum -y install httpd mod_ssl openssl git epel-release
sudo yum -y install php php-devel php-mbstring php-pdo php-gd php-xml php-mcrypt php-dba php-mysql php-odbc php-pdo php-pear
#sudo rpm -Uvh http://rpms.famillecollet.com/enterprise/remi-release-7.rpm
#sudo yum -y install --enablerepo=remi,remi-php56 php php-devel php-mbstring php-pdo php-gd php-xml php-mcrypt php-dba php-mysql php-odbc php-pdo php-pear
#sudo curl -fsSL https://mackerel.io/file/script/setup-all-yum-v2.sh | MACKEREL_APIKEY=${MACKEREL_APIKEY} sh
#sudo yum -y install mackerel-agent-plugins mackerel-check-plugins

# **** MySQL Client ****
sudo yum -y localinstall https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm
sudo yum -y install mysql-community-client

# *** Add Auto Startup httpd service, mackerel-agent service ***
sudo systemctl enable httpd.service
sudo systemctl enable mackerel-agent.service

# *** Edit virtual host config ***
# **** Create Server Name ****
sudo cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.org
sudo sed -i -e "s/#ServerName www.example.com:80/ServerName ${PROD_HOST}:80/g" /etc/httpd/conf/httpd.conf

# **** Create security.conf ****
sudo cat << EOF > /etc/httpd/conf.d/security.conf
# Version Info Hiding
ServerTokens Prod
Header unset Server
Header always unset X-Powered-By

# Click Jacking Control
Header always append X-Frame-Options SAMEORIGIN

# XSS Control
Header always set X-XSS-Protection "1; mode=block"
Header set X-Content-Type-Options nosniff

# XST Control
TraceEnable Off

# Mackerel
ExtendedStatus On
<VirtualHost 127.0.0.1:1080>
    <Location /server-status>
        SetHandler server-status
        Order deny,allow
        Deny from all
        Allow from localhost
    </Location>
</VirtualHost>

HostNameLookups off
EOF

# **** Create Production Environment httpd.conf ***
sudo cat << EOF > /etc/httpd/conf.d/${PROD_HOST}.conf
<VirtualHost *:80>
    ServerName ${PROD_HOST}
    DirectoryIndex index.html index.htm index.php
    DocumentRoot /home/www/${PROD_HOST}/contents/htdocs

    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{X-Forwarded-For}i\"" combined-remote-ip
    CustomLog "|/usr/sbin/rotatelogs /home/www/${PROD_HOST}/logs/access_%Y%m%d.log 86400 540" combined-remote-ip
    ErrorLog "|/usr/sbin/rotatelogs /home/www/${PROD_HOST}/logs/error_%Y%m%d.log 86400 540"

    <Directory /home/www/${PROD_HOST}/contents/htdocs>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Require all granted
        Require method GET POST
    </Directory>

#    RewriteEngine on
#    RewriteCond %{HTTP_HOST} ^${PROD_HOST}$ [nc]
#    RewriteRule ^/(.*) https://${PROD_HOST}/ [R=301,L]
</VirtualHost>
<VirtualHost *:80>
    ServerName www.${PROD_HOST}
    RewriteEngine on
    RewriteCond %{HTTP_HOST} ^www.${PROD_HOST}$ [nc]
    RewriteRule ^/(.*) http://${PROD_HOST}/ [R=301,L]

#    RewriteCond %{HTTP_HOST} ^www.${PROD_HOST}$ [nc]
#    RewriteRule ^/(.*) https://${PROD_HOST}/ [R=301,L]
</VirtualHost>

#<VirtualHost *:443>
#    DirectoryIndex index.html index.htm index.php
#    DocumentRoot /home/www/${PROD_HOST}/contents/htdocs
#    ServerName ${PROD_HOST}
#
#    SSLEngine on
#    SSLCertificateChainFile /home/www/${PROD_HOST}/etc/cert/ca.crt
#    SSLCertificateFile /home/www/${PROD_HOST}/etc/cert/server.crt
#    SSLCertificateKeyFile /home/www/${PROD_HOST}/etc/cert/server.key
#    SSLProtocol all -SSLv2 -SSLv3 -TLSv1
#    SSLHonorCipherOrder ON
#    SSLCipherSuite  ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
#
#    CustomLog "|/usr/sbin/rotatelogs /home/www/${PROD_HOST}/logs/access_%Y%m%d.log 86400 540" combined-remote-ip
#    ErrorLog "|/usr/sbin/rotatelogs /home/www/${PROD_HOST}/logs/error_%Y%m%d.log 86400 540"
#
#    <Directory /home/www/${PROD_HOST}/contents/htdocs>
#        Options -Indexes +FollowSymLinks +MultiViews
#        AllowOverride All
#        Require all granted
#        Require method GET POST
#    </Directory>
#</VirtualHost>
#<VirtualHost *:443>
#    ServerName www.${PROD_HOST}
#    RewriteEngine on
#    RewriteCond %{HTTP_HOST} ^www.${PROD_HOST}$ [nc]
#    RewriteRule ^/(.*) https://${PROD_HOST}/ [R=301,L]
#</VirtualHost>
EOF
# **** Create Test Environment httpd.conf ***
sudo cat << EOF > /etc/httpd/conf.d/${TEST_HOST}.conf
<VirtualHost *:80>
    ServerName ${TEST_HOST}
    DirectoryIndex index.html index.htm index.php
    DocumentRoot /home/www/${TEST_HOST}/contents/htdocs

    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{X-Forwarded-For}i\"" combined-remote-ip
    CustomLog "|/usr/sbin/rotatelogs /home/www/${TEST_HOST}/logs/access_%Y%m%d.log 86400 540" combined-remote-ip
    ErrorLog "|/usr/sbin/rotatelogs /home/www/${TEST_HOST}/logs/error_%Y%m%d.log 86400 540"
    <Directory /home/www/${TEST_HOST}/contents/htdocs>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Require all granted
        Require method GET POST
    </Directory>

#    RewriteEngine on
#    RewriteCond %{HTTP_HOST} ^${TEST_HOST}$ [nc]
#    RewriteRule ^/(.*) https://${TEST_HOST}/ [R=301,L]
</VirtualHost>

#<VirtualHost *:443>
#    DirectoryIndex index.html index.htm index.php
#    DocumentRoot /home/www/${TEST_HOST}/contents/htdocs
#    ServerName ${TEST_HOST}
#
#    SSLEngine on
#    SSLCertificateChainFile /home/www/${TEST_HOST}/etc/cert/ca.crt
#    SSLCertificateFile /home/www/${TEST_HOST}/etc/cert/server.crt
#    SSLCertificateKeyFile /home/www/${TEST_HOST}/etc/cert/server.key
#    SSLProtocol all -SSLv2 -SSLv3 -TLSv1
#    SSLHonorCipherOrder ON
#    SSLCipherSuite  ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256
#
#    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{X-Forwarded-For}i\"" combined-remote-ip
#    CustomLog "|/usr/sbin/rotatelogs /home/www/${TEST_HOST}/logs/access_%Y%m%d.log 86400 540" combined-remote-ip
#    ErrorLog "|/usr/sbin/rotatelogs /home/www/${TEST_HOST}/logs/error_%Y%m%d.log 86400 540"
#
#    <Directory /home/www/${TEST_HOST}/contents/htdocs>
#        Options -Indexes +FollowSymLinks +MultiViews
#        AllowOverride All
#        Require all granted
#        Require method GET POST
#    </Directory>
#</VirtualHost>
EOF
# **** Change virtual host config owner ****
sudo chown root:root /etc/httpd/conf.d/security.conf
sudo chown root:root /etc/httpd/conf.d/${PROD_HOST}.conf
sudo chown root:root /etc/httpd/conf.d/${TEST_HOST}.conf
# **** Remove Unnneccesary files ****
sudo mv /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/autoindex.conf.bk
sudo mv /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/welcome.conf.bk

# *** Edit php.ini ***
sudo cp /etc/php.ini /etc/php.ini.org
sudo sed -i -e 's/^;default_charset = "UTF-8"/default_charset = "UTF-8"/g' /etc/php.ini
sudo sed -i -e 's/^;mbstring.language = Japanese/mbstring.language = Japanese/g' /etc/php.ini
sudo sed -i -e 's/^;mbstring.encoding_translation = Off/mbstring.encoding_translation = Off/g' /etc/php.ini
sudo sed -i -e 's/^;mbstring.detect_order = auto/mbstring.detect_order = UTF-8,SJIS,EUC-JP,JIS,ASCII/g' /etc/php.ini
sudo sed -i -e 's/^;mbstring.substitute_character = none;/mbstring.substitute_character = none/g' /etc/php.ini
sudo sed -i -e 's/^;date.timezone =;/date.timezone = Asia/Tokyo/g' /etc/php.ini
sudo sed -i -e 's/expose_php = On/expose_php = Off/g' /etc/php.ini
sudo sed -i -e 's/session.hash_function = 0/session.hash_function = 1/g' /etc/php.ini
sudo sed -i -e 's/;session.cookie_secure =/session.cookie_secure = On/g' /etc/php.ini
sudo sed -i -e 's/session.cookie_httponly =/session.cookie_httponly = On/g' /etc/php.ini

# **** PHP > ~5.6 ****
sudo sed -i -e 's/^;mbstring.internal_encoding =/mbstring.internal_encoding = UTF-8/g' /etc/php.ini
sudo sed -i -e 's/^;mbstring.http_input =/mbstring.http_input = pass/g' /etc/php.ini
sudo sed -i -e 's/^;mbstring.http_output =/mbstring.http_output = pass/g' /etc/php.ini

# *** Create Project Directory ***
sudo mkdir -pm 755 /home/www/${PROD_HOST}/{logs,data,etc,contents/htdocs,etc/cert,contents/htdocs/.well-known/pki-validation/}
sudo mkdir -pm 755 /home/www/${TEST_HOST}/{logs,data,etc,contents/htdocs,etc/cert,contents/htdocs/.well-known/pki-validation/}

# *** Create Dummy Index.html ***
sudo echo "${PROD_HOST}" > /home/www/${PROD_HOST}/contents/htdocs/index.html
sudo echo "${TEST_HOST}" > /home/www/${TEST_HOST}/contents/htdocs/index.html
sudo chown -R ${DEVELOPER_NAME}:${DEVELOPER_NAME} /home/www/${PROD_HOST}
sudo chown -R ${DEVELOPER_NAME}:${DEVELOPER_NAME} /home/www/${TEST_HOST}
sudo touch /home/www/${PROD_HOST}/contents/htdocs/.well-known/pki-validation/godaddy.html
sudo touch /home/www/${TEST_HOST}/contents/htdocs/.well-known/pki-validation/godaddy.html

# *** Create Synbolic Link ***
sudo ln -s /etc/httpd/conf.d/${PROD_HOST}.conf /home/www/${PROD_HOST}/etc/${PROD_HOST}.conf
sudo ln -s /etc/httpd/conf.d/${TEST_HOST}.conf /home/www/${TEST_HOST}/etc/${TEST_HOST}.conf

# *** Set Basic Authentication (Test Environment Only) ***
sudo htpasswd -c -b /home/www/${TEST_HOST}/etc/.htpasswd $BASIC_AUTH_ID $BASIC_AUTH_ID
sudo cat << EOF > /home/www/${TEST_HOST}/contents/htdocs/.htaccess
# from Application Gateway, Load Balancer Health Check Through
SetEnvIf X-Forwarded-For "^$" empty_ok
Order Deny,Allow
Deny from all
Allow from env=empty_ok

AuthUserfile /home/www/${TEST_HOST}/etc/.htpasswd
AuthGroupfile /dev/null
AuthName "Please enter your ID and password"
AuthType Basic
require valid-user
EOF
sudo chown -R ${DEVELOPER_NAME}:${DEVELOPER_NAME} /home/www/${TEST_HOST}/contents/htdocs/.htaccess

# *** Edit mackerel.conf ***
#sudo cp /etc/mackerel-agent/mackerel-agent.conf /etc/mackerel-agent/mackerel-agent.conf.org
#sudo cat << EOF >> /etc/mackerel-agent/mackerel-agent.conf
#
#[plugin.metrics.apache2]
#command = "/path/to/mackerel-plugin-apache2 -p 1080"
#type = "metric"
#
#[plugin.metrics.linux]
#command = "mackerel-plugin-linux"
#type="metric"
#
#[plugin.checks.check_httpd]
#command = "check-procs -p httpd -W 6 -C 3"
#
#[plugin.checks.check_crond]
#command = "check-procs -p crond -C 1"
#
#[plugin.checks.check_sshd]
#command = "check-procs -p sshd -C 1"
#
#[plugin.checks.secure_log]
#command = "check-log --file /var/log/secure --pattern Failed -w 3 -c 10"
#EOF
# --------------------------------------------------------------