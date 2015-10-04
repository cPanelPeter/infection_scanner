#!/usr/local/cpanel/3rdparty/bin/perl
BEGIN {
    unshift @INC, '/usr/local/cpanel';
}

use Cpanel::LiveAPI ();
my $cpanel = Cpanel::LiveAPI->new();

$| = 1;

# First download the latest strings to search for.
system(" curl https://raw.githubusercontent.com/cPanelPeter/infection_scanner/master/infections.txt > infections.txt" );

my $USERPATH = $cpanel->cpanelprint('$homedir');
print "Content-type: text/html\r\n\r\n";

print "Now scanning $USERPATH...<P>\n";
require '/usr/local/cpanel/base/frontend/paper_lantern/integration_examples/infections.txt';
my @SEARCHSTRING=sort(@DEFINITIONS);
my @FOUND=undef;
my $SOMETHING_FOUND=0;
my $SEARCHSTRING;
my $cntFound=0;
foreach $SEARCHSTRING(@SEARCHSTRING) { 
	chomp($SEARCHSTRING);
	print ".\n";
	my $SCAN=qx[ grep -rIl $SEARCHSTRING $USERPATH/* ];
	chomp($SCAN);
	if($SCAN) { 
		$cntFound++;
		$SOMETHING_FOUND=1;
		push(@FOUND,"The phrase $SEARCHSTRING was found in file $SCAN");
	}
	select(undef, undef, undef, 0.25);
}
my $found;
if ($SOMETHING_FOUND > 0) {
	foreach $found(@FOUND) { 
		chomp($found);
		print "$found\n";
	}
}
