#!/bin/sh
# SCRIPT: install.sh
# PURPOSE: Install the infection_scanner plugin into cPanel
# AUTHOR: Peter Elsner <peter.elsner@cpanel.net>
#
clear
echo "Installing infection_scanner"

# Create the directory for the plugin
mkdir /usr/local/cpanel/whostmgr/docroot/cgi/infection_scanner

# Get the plugin files from Github
curl -s https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/infection_scanner.tar.gz > /usr/local/cpanel/whostmgr/docroot/cgi/infection_scanner

# Uncompress the archive
tar xzf /usr/local/cpanel/whostmgr/docroot/cgi/infection_scanner/infection_scanner.tar.gz

# Register the plugin (which also places the png image in the proper location)
/usr/local/cpanel/bin/register_cpanelplugin /usr/local/cpanel/whostmgr/docroot/cgi/infection_scanner/register.tar.gz

# Rebuild the sprites
/usr/local/cpanel/bin/rebuild_sprites

echo "Installation is complete!"

