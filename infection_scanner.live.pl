#!/usr/local/cpanel/3rdparty/bin/perl

BEGIN {
    unshift @INC, '/usr/local/cpanel';
}

use Cpanel::LiveAPI ();
my $cpanel = Cpanel::LiveAPI->new();

# Turn off buffering
$| = 1;

my $USERPATH = $cpanel->cpanelprint('$homedir');
print "Content-type: text/html\r\n\r\n";
print <<END;
<!DOCTYPE html>
<html>
<head>
<title>
Simple Website Infection Scanner</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style type="text/css">
body {background-color:ffffff;background-repeat:no-repeat;background-position:top left;background-attachment:fixed;}
h3{font-family:Cursive;color:FFFFCC;background-color:3333CC;}
p {font-family:Cursive;font-size:14px;font-style:normal;font-weight:bold;color:000000;background-color:FFFFCC;}
</style>
</head>
<body>
<center><h3>Simple Infection Scanner</h3></center>
<p>This little infection scanner was purely designed to show how easy it is to create/install<br> 
plugins within cPanel.  It is in no way a comprehensive scanner and should not be solely relied<br>
upon.  This program will NOT remove nor quarantine anything.  All detections should be<br>
thoroughly and manually investigated.  

<p>
<font color="RED">
Please DO NOT contact your hosting provider nor cPanel, Inc. for support regarding this program. 
</font>
<p>
Quick Disclaimer: This free infection scanner is provided "AS IS". 100% detection rate does <br>
not exist and no vendor in the market can guarantee it. Neither your web hosting provider nor<c>
cPanel, Inc. claims any responsibility for the detection or failure to detect malicious code<br>
on your website or any other websites.  
</p>
<hr>
END

print "Now scanning $USERPATH...<P>\n";
require '/usr/local/cpanel/base/frontend/paper_lantern/infection_scanner/infections.txt';
my @SEARCHSTRING=sort(@DEFINITIONS);
my @FOUND=undef;
my $SOMETHING_FOUND=0;
my $SEARCHSTRING;
my $cntFound=0;
foreach $SEARCHSTRING(@SEARCHSTRING) {
   chomp($SEARCHSTRING);
   print ".\n";
   my $SCAN=qx[ grep -rIl --exclude-dir=www $SEARCHSTRING $USERPATH/* ];
   chomp($SCAN);
   if($SCAN) {
      $cntFound++;
      $SOMETHING_FOUND=1;
      push(@FOUND,"The phrase $SEARCHSTRING was found in file $SCAN");
   }
# UNCOMMENT THIS NEXT LINE TO PUT A .10 SECOND PAUSE (for drammatic effect).
#       select(undef, undef, undef, 0.10);
}
my $found;
if ($SOMETHING_FOUND > 0) {
   foreach $found(@FOUND) {
      chomp($found);
      print "$found<br>\n";
   }
}
else { 
   print "<p>Congratulations!  Nothing suspicious was found!\n";
}

print <<END;
</body>
</html>
END

