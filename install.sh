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
curl -s https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/is_files.tar.gz > /usr/local/cpanel/base/frontend/paper_lantern/infection_scanner/is_files.tar.gz

# Uncompress the archive
tar xzf /usr/local/cpanel/base/frontend/paper_lantern/infection_scanner/is_files.tar.gz

# Install the plugin (which also places the png image in the proper location)
/usr/local/cpanel/scripts/install_plugin /usr/local/cpanel/base/frontend/paper_lantern/infection_scanner/infection_scanner.tar.gz

# Rebuild the sprites - NOT required on paper_lantern theme (only x3)
#/usr/local/cpanel/bin/rebuild_sprites

echo "Installation is complete!"

