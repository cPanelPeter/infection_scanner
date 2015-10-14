#!/bin/sh
# SCRIPT: install.sh
# PURPOSE: Install the infection_scanner plugin into cPanel
# AUTHOR: Peter Elsner <peter.elsner@cpanel.net>
#
clear
echo "Installing infection_scanner"

# Create the directory for the plugin
mkdir -p /usr/local/cpanel/base/frontend/paper_lantern/infection_scanner

# Get the plugin files from Github
curl -s https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/is_files.tar.gz > /root/is_files.tar.gz

# Uncompress the archive
tar xzf is_files.tar.gz

# Move files to /usr/local/cpanel/base/frontend/paper_lantern/infection_scanner directory
mv /root/infection_scanner.live.pl /usr/local/cpanel/base/frontend/paper_lantern/infection_scanner
mv /root/infection_scanner.tar.gz /usr/local/cpanel/base/frontend/paper_lantern/infection_scanner

# Install the plugin (which also places the png image in the proper location)
/usr/local/cpanel/scripts/install_plugin /usr/local/cpanel/base/frontend/paper_lantern/infection_scanner/infection_scanner.tar.gz

# Move dlinfections script to /etc/cron.weekly (and run it once)
mv /root/dlinfections /etc/cron.weekly
chmod 0755 /etc/cron.weekly/dlinfections 
/usr/local/cpanel/3rdparty/bin/perl /etc/cron.weekly/dlinfections

echo "Installation is complete!"

