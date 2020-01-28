/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
    and open to any user or organization, as long as you use it under this license.

Last Updated: Tue Jan 28 15:51:01 CST 2020
*/
rule Rule_1_triggered {
	meta: description = "Rule # 1 Suspicious String $kola triggered"
	strings: $suspicious_string = "$kola"
	condition: $suspicious_string
}
rule Rule_2_triggered {
	meta: description = "Rule # 2 Suspicious String $payload_file triggered"
	strings: $suspicious_string = "$payload_file"
	condition: $suspicious_string
}
rule Rule_3_triggered {
	meta: description = "Rule # 3 Suspicious String $udborfbq=\"data\" triggered"
	strings: $suspicious_string = "$udborfbq=\"data\""
	condition: $suspicious_string
}
rule Rule_4_triggered {
	meta: description = "Rule # 4 Suspicious String (c)oded by 1dt.w0lf triggered"
	strings: $suspicious_string = "(c)oded by 1dt.w0lf"
	condition: $suspicious_string
}
rule Rule_5_triggered {
	meta: description = "Rule # 5 Suspicious String **(RooTTN)** triggered"
	strings: $suspicious_string = "**(RooTTN)**"
	condition: $suspicious_string
}
rule Rule_6_triggered {
	meta: description = "Rule # 6 Suspicious String ***We can read root's home directory! triggered"
	strings: $suspicious_string = "***We can read root's home directory!"
	condition: $suspicious_string
}
rule Rule_7_triggered {
	meta: description = "Rule # 7 Suspicious String ++====[ PayPal ]====++ triggered"
	strings: $suspicious_string = "++====[ PayPal ]====++"
	condition: $suspicious_string
}
rule Rule_8_triggered {
	meta: description = "Rule # 8 Suspicious String +Codewizard+ triggered"
	strings: $suspicious_string = "+Codewizard+"
	condition: $suspicious_string
}
rule Rule_9_triggered {
	meta: description = "Rule # 9 Suspicious String ---:||Wellsfargo||:--- triggered"
	strings: $suspicious_string = "---:||Wellsfargo||:---"
	condition: $suspicious_string
}
rule Rule_10_triggered {
	meta: description = "Rule # 10 Suspicious String -W3lc0me triggered"
	strings: $suspicious_string = "-W3lc0me"
	condition: $suspicious_string
}
rule Rule_11_triggered {
	meta: description = "Rule # 11 Suspicious String -risen- triggered"
	strings: $suspicious_string = "-risen-"
	condition: $suspicious_string
}
rule Rule_12_triggered {
	meta: description = "Rule # 12 Suspicious String /tmp/passwd.bak triggered"
	strings: $suspicious_string = "/tmp/passwd.bak"
	condition: $suspicious_string
}
rule Rule_13_triggered {
	meta: description = "Rule # 13 Suspicious String 04d92810.com triggered"
	strings: $suspicious_string = "04d92810.com"
	condition: $suspicious_string
}
rule Rule_14_triggered {
	meta: description = "Rule # 14 Suspicious String 07b0418e1119091a9281ac5614cb9d776a85f triggered"
	strings: $suspicious_string = "07b0418e1119091a9281ac5614cb9d776a85f"
	condition: $suspicious_string
}
rule Rule_15_triggered {
	meta: description = "Rule # 15 Suspicious String 088116101097 triggered"
	strings: $suspicious_string = "088116101097"
	condition: $suspicious_string
}
rule Rule_16_triggered {
	meta: description = "Rule # 16 Suspicious String 08zvd triggered"
	strings: $suspicious_string = "08zvd"
	condition: $suspicious_string
}
rule Rule_17_triggered {
	meta: description = "Rule # 17 Suspicious String 0D3S3CT0R URBANNED triggered"
	strings: $suspicious_string = "0D3S3CT0R URBANNED"
	condition: $suspicious_string
}
rule Rule_18_triggered {
	meta: description = "Rule # 18 Suspicious String 0tamega triggered"
	strings: $suspicious_string = "0tamega"
	condition: $suspicious_string
}
rule Rule_19_triggered {
	meta: description = "Rule # 19 Suspicious String 0xfans triggered"
	strings: $suspicious_string = "0xfans"
	condition: $suspicious_string
}
rule Rule_20_triggered {
	meta: description = "Rule # 20 Suspicious String 104.20.209.21 triggered"
	strings: $suspicious_string = "104.20.209.21"
	condition: $suspicious_string
}
rule Rule_21_triggered {
	meta: description = "Rule # 21 Suspicious String 107.181.160.197 triggered"
	strings: $suspicious_string = "107.181.160.197"
	condition: $suspicious_string
}
rule Rule_22_triggered {
	meta: description = "Rule # 22 Suspicious String 10f89b8c.com triggered"
	strings: $suspicious_string = "10f89b8c.com"
	condition: $suspicious_string
}
rule Rule_23_triggered {
	meta: description = "Rule # 23 Suspicious String 123.59.120.219 triggered"
	strings: $suspicious_string = "123.59.120.219"
	condition: $suspicious_string
}
rule Rule_24_triggered {
	meta: description = "Rule # 24 Suspicious String 13.113.240.221 triggered"
	strings: $suspicious_string = "13.113.240.221"
	condition: $suspicious_string
}
rule Rule_25_triggered {
	meta: description = "Rule # 25 Suspicious String 1337passkey triggered"
	strings: $suspicious_string = "1337passkey"
	condition: $suspicious_string
}
rule Rule_26_triggered {
	meta: description = "Rule # 26 Suspicious String 1337w0rm triggered"
	strings: $suspicious_string = "1337w0rm"
	condition: $suspicious_string
}
rule Rule_27_triggered {
	meta: description = "Rule # 27 Suspicious String 1639-7537-4662-1478 triggered"
	strings: $suspicious_string = "1639-7537-4662-1478"
	condition: $suspicious_string
}
rule Rule_28_triggered {
	meta: description = "Rule # 28 Suspicious String 17_PersonNotFound triggered"
	strings: $suspicious_string = "17_PersonNotFound"
	condition: $suspicious_string
}
rule Rule_29_triggered {
	meta: description = "Rule # 29 Suspicious String 191.101.30.254 triggered"
	strings: $suspicious_string = "191.101.30.254"
	condition: $suspicious_string
}
rule Rule_30_triggered {
	meta: description = "Rule # 30 Suspicious String 1dGlvbl90aW1l triggered"
	strings: $suspicious_string = "1dGlvbl90aW1l"
	condition: $suspicious_string
}
rule Rule_31_triggered {
	meta: description = "Rule # 31 Suspicious String 1gh.saveboston.today triggered"
	strings: $suspicious_string = "1gh.saveboston.today"
	condition: $suspicious_string
}
rule Rule_32_triggered {
	meta: description = "Rule # 32 Suspicious String 1ntr0ver7.id triggered"
	strings: $suspicious_string = "1ntr0ver7.id"
	condition: $suspicious_string
}
rule Rule_33_triggered {
	meta: description = "Rule # 33 Suspicious String 1ntr0ver7_Tersakiti triggered"
	strings: $suspicious_string = "1ntr0ver7_Tersakiti"
	condition: $suspicious_string
}
rule Rule_34_triggered {
	meta: description = "Rule # 34 Suspicious String 2015priv8bypass triggered"
	strings: $suspicious_string = "2015priv8bypass"
	condition: $suspicious_string
}
rule Rule_35_triggered {
	meta: description = "Rule # 35 Suspicious String 23.247.73.219 triggered"
	strings: $suspicious_string = "23.247.73.219"
	condition: $suspicious_string
}
rule Rule_36_triggered {
	meta: description = "Rule # 36 Suspicious String 2kb Shell triggered"
	strings: $suspicious_string = "2kb Shell"
	condition: $suspicious_string
}
rule Rule_37_triggered {
	meta: description = "Rule # 37 Suspicious String 31.184.192.250 triggered"
	strings: $suspicious_string = "31.184.192.250"
	condition: $suspicious_string
}
rule Rule_38_triggered {
	meta: description = "Rule # 38 Suspicious String 313.legend.rocks triggered"
	strings: $suspicious_string = "313.legend.rocks"
	condition: $suspicious_string
}
rule Rule_39_triggered {
	meta: description = "Rule # 39 Suspicious String 32f988f6.com triggered"
	strings: $suspicious_string = "32f988f6.com"
	condition: $suspicious_string
}
rule Rule_40_triggered {
	meta: description = "Rule # 40 Suspicious String 33db9538.com triggered"
	strings: $suspicious_string = "33db9538.com"
	condition: $suspicious_string
}
rule Rule_41_triggered {
	meta: description = "Rule # 41 Suspicious String 33db9538.com|31.184.192.173 triggered"
	strings: $suspicious_string = "33db9538.com|31.184.192.173"
	condition: $suspicious_string
}
rule Rule_42_triggered {
	meta: description = "Rule # 42 Suspicious String 3FT Hna Pour unzipi triggered"
	strings: $suspicious_string = "3FT Hna Pour unzipi"
	condition: $suspicious_string
}
rule Rule_43_triggered {
	meta: description = "Rule # 43 Suspicious String 3Turr ~ CPanel Cracker triggered"
	strings: $suspicious_string = "3Turr ~ CPanel Cracker"
	condition: $suspicious_string
}
rule Rule_44_triggered {
	meta: description = "Rule # 44 Suspicious String 3c856e8ca0030a3f8e7ca0cfaa5d74b6dd6db2f9 triggered"
	strings: $suspicious_string = "3c856e8ca0030a3f8e7ca0cfaa5d74b6dd6db2f9"
	condition: $suspicious_string
}
rule Rule_45_triggered {
	meta: description = "Rule # 45 Suspicious String 3xcr3w.php triggered"
	strings: $suspicious_string = "3xcr3w.php"
	condition: $suspicious_string
}
rule Rule_46_triggered {
	meta: description = "Rule # 46 Suspicious String 3xp1r3 triggered"
	strings: $suspicious_string = "3xp1r3"
	condition: $suspicious_string
}
rule Rule_47_triggered {
	meta: description = "Rule # 47 Suspicious String 3xp1r3 Cyber Army triggered"
	strings: $suspicious_string = "3xp1r3 Cyber Army"
	condition: $suspicious_string
}
rule Rule_48_triggered {
	meta: description = "Rule # 48 Suspicious String 40000 Emails This May Hack The Server triggered"
	strings: $suspicious_string = "40000 Emails This May Hack The Server"
	condition: $suspicious_string
}
rule Rule_49_triggered {
	meta: description = "Rule # 49 Suspicious String 404_NOT_FOUND  triggered"
	strings: $suspicious_string = "404_NOT_FOUND "
	condition: $suspicious_string
}
rule Rule_50_triggered {
	meta: description = "Rule # 50 Suspicious String 498296c9.com triggered"
	strings: $suspicious_string = "498296c9.com"
	condition: $suspicious_string
}
rule Rule_51_triggered {
	meta: description = "Rule # 51 Suspicious String 4Ri3 60ndr0n9 triggered"
	strings: $suspicious_string = "4Ri3 60ndr0n9"
	condition: $suspicious_string
}
rule Rule_52_triggered {
	meta: description = "Rule # 52 Suspicious String 54dfa1cb.com triggered"
	strings: $suspicious_string = "54dfa1cb.com"
	condition: $suspicious_string
}
rule Rule_53_triggered {
	meta: description = "Rule # 53 Suspicious String 5P!R!7 #UN73R triggered"
	strings: $suspicious_string = "5P!R!7 #UN73R"
	condition: $suspicious_string
}
rule Rule_54_triggered {
	meta: description = "Rule # 54 Suspicious String 5iNON!MOU23 triggered"
	strings: $suspicious_string = "5iNON!MOU23"
	condition: $suspicious_string
}
rule Rule_55_triggered {
	meta: description = "Rule # 55 Suspicious String 7547ec6af9d987359dd34c888224afb1 triggered"
	strings: $suspicious_string = "7547ec6af9d987359dd34c888224afb1"
	condition: $suspicious_string
}
rule Rule_56_triggered {
	meta: description = "Rule # 56 Suspicious String 7L14e+I40jD8uee65j9r2OySe triggered"
	strings: $suspicious_string = "7L14e+I40jD8uee65j9r2OySe"
	condition: $suspicious_string
}
rule Rule_57_triggered {
	meta: description = "Rule # 57 Suspicious String 7VdrT+NGFP1eqf9hiCIcKwHFj7ClIQ triggered"
	strings: $suspicious_string = "7VdrT+NGFP1eqf9hiCIcKwHFj7ClIQ"
	condition: $suspicious_string
}
rule Rule_58_triggered {
	meta: description = "Rule # 58 Suspicious String 7ca95 triggered"
	strings: $suspicious_string = "7ca95"
	condition: $suspicious_string
}
rule Rule_59_triggered {
	meta: description = "Rule # 59 Suspicious String 7iemH yb dekcah triggered"
	strings: $suspicious_string = "7iemH yb dekcah"
	condition: $suspicious_string
}
rule Rule_60_triggered {
	meta: description = "Rule # 60 Suspicious String 81140a9f1e58612c51ef8f30b62030aeedceac8f triggered"
	strings: $suspicious_string = "81140a9f1e58612c51ef8f30b62030aeedceac8f"
	condition: $suspicious_string
}
rule Rule_61_triggered {
	meta: description = "Rule # 61 Suspicious String 83.133.123.174 triggered"
	strings: $suspicious_string = "83.133.123.174"
	condition: $suspicious_string
}
rule Rule_62_triggered {
	meta: description = "Rule # 62 Suspicious String 8a4bf282852bf4c49e17f0951f645e72 triggered"
	strings: $suspicious_string = "8a4bf282852bf4c49e17f0951f645e72"
	condition: $suspicious_string
}
rule Rule_63_triggered {
	meta: description = "Rule # 63 Suspicious String 8b238dd6.com triggered"
	strings: $suspicious_string = "8b238dd6.com"
	condition: $suspicious_string
}
rule Rule_64_triggered {
	meta: description = "Rule # 64 Suspicious String 8m0slmesh triggered"
	strings: $suspicious_string = "8m0slmesh"
	condition: $suspicious_string
}
rule Rule_65_triggered {
	meta: description = "Rule # 65 Suspicious String 90sec triggered"
	strings: $suspicious_string = "90sec"
	condition: $suspicious_string
}
rule Rule_66_triggered {
	meta: description = "Rule # 66 Suspicious String 9507c4e8.com triggered"
	strings: $suspicious_string = "9507c4e8.com"
	condition: $suspicious_string
}
rule Rule_67_triggered {
	meta: description = "Rule # 67 Suspicious String 9507c4e8.com|31.184.192.163 triggered"
	strings: $suspicious_string = "9507c4e8.com|31.184.192.163"
	condition: $suspicious_string
}
rule Rule_68_triggered {
	meta: description = "Rule # 68 Suspicious String 9974-5263-1008-5189 triggered"
	strings: $suspicious_string = "9974-5263-1008-5189"
	condition: $suspicious_string
}
rule Rule_69_triggered {
	meta: description = "Rule # 69 Suspicious String 99754106633f94d350db34d548d6091a triggered"
	strings: $suspicious_string = "99754106633f94d350db34d548d6091a"
	condition: $suspicious_string
}
rule Rule_70_triggered {
	meta: description = "Rule # 70 Suspicious String 9aldo6r0y_p24m8e triggered"
	strings: $suspicious_string = "9aldo6r0y_p24m8e"
	condition: $suspicious_string
}
rule Rule_71_triggered {
	meta: description = "Rule # 71 Suspicious String 9dbb40d076c4df840899d7f16de0f206 triggered"
	strings: $suspicious_string = "9dbb40d076c4df840899d7f16de0f206"
	condition: $suspicious_string
}
rule Rule_72_triggered {
	meta: description = "Rule # 72 Suspicious String @NubzSec triggered"
	strings: $suspicious_string = "@NubzSec"
	condition: $suspicious_string
}
rule Rule_73_triggered {
	meta: description = "Rule # 73 Suspicious String @s3n4t00r triggered"
	strings: $suspicious_string = "@s3n4t00r"
	condition: $suspicious_string
}
rule Rule_74_triggered {
	meta: description = "Rule # 74 Suspicious String ADP MOBILE RESPONSE! triggered"
	strings: $suspicious_string = "ADP MOBILE RESPONSE!"
	condition: $suspicious_string
}
rule Rule_75_triggered {
	meta: description = "Rule # 75 Suspicious String AFK404 triggered"
	strings: $suspicious_string = "AFK404"
	condition: $suspicious_string
}
rule Rule_76_triggered {
	meta: description = "Rule # 76 Suspicious String AL-VRI triggered"
	strings: $suspicious_string = "AL-VRI"
	condition: $suspicious_string
}
rule Rule_77_triggered {
	meta: description = "Rule # 77 Suspicious String ALARENG?N triggered"
	strings: $suspicious_string = "ALARENG?N"
	condition: $suspicious_string
}
rule Rule_78_triggered {
	meta: description = "Rule # 78 Suspicious String ALFA TEaM triggered"
	strings: $suspicious_string = "ALFA TEaM"
	condition: $suspicious_string
}
rule Rule_79_triggered {
	meta: description = "Rule # 79 Suspicious String ASPX Shell by LT triggered"
	strings: $suspicious_string = "ASPX Shell by LT"
	condition: $suspicious_string
}
rule Rule_80_triggered {
	meta: description = "Rule # 80 Suspicious String AXA Banque ReZulT triggered"
	strings: $suspicious_string = "AXA Banque ReZulT"
	condition: $suspicious_string
}
rule Rule_81_triggered {
	meta: description = "Rule # 81 Suspicious String AZZATSSINS triggered"
	strings: $suspicious_string = "AZZATSSINS"
	condition: $suspicious_string
}
rule Rule_82_triggered {
	meta: description = "Rule # 82 Suspicious String Achon666ju5t triggered"
	strings: $suspicious_string = "Achon666ju5t"
	condition: $suspicious_string
}
rule Rule_83_triggered {
	meta: description = "Rule # 83 Suspicious String AdjieDotId triggered"
	strings: $suspicious_string = "AdjieDotId"
	condition: $suspicious_string
}
rule Rule_84_triggered {
	meta: description = "Rule # 84 Suspicious String Administrator@Guess_me triggered"
	strings: $suspicious_string = "Administrator@Guess_me"
	condition: $suspicious_string
}
rule Rule_85_triggered {
	meta: description = "Rule # 85 Suspicious String Afghan Cyber Army (ACA) triggered"
	strings: $suspicious_string = "Afghan Cyber Army (ACA)"
	condition: $suspicious_string
}
rule Rule_86_triggered {
	meta: description = "Rule # 86 Suspicious String Ahmdosa Hacker triggered"
	strings: $suspicious_string = "Ahmdosa Hacker"
	condition: $suspicious_string
}
rule Rule_87_triggered {
	meta: description = "Rule # 87 Suspicious String Ahmed Alarbi triggered"
	strings: $suspicious_string = "Ahmed Alarbi"
	condition: $suspicious_string
}
rule Rule_88_triggered {
	meta: description = "Rule # 88 Suspicious String Al3x M@rken triggered"
	strings: $suspicious_string = "Al3x M@rken"
	condition: $suspicious_string
}
rule Rule_89_triggered {
	meta: description = "Rule # 89 Suspicious String AlMajhool hacker triggered"
	strings: $suspicious_string = "AlMajhool hacker"
	condition: $suspicious_string
}
rule Rule_90_triggered {
	meta: description = "Rule # 90 Suspicious String AlZzAelm triggered"
	strings: $suspicious_string = "AlZzAelm"
	condition: $suspicious_string
}
rule Rule_91_triggered {
	meta: description = "Rule # 91 Suspicious String Alansary LY triggered"
	strings: $suspicious_string = "Alansary LY"
	condition: $suspicious_string
}
rule Rule_92_triggered {
	meta: description = "Rule # 92 Suspicious String Alfa_Protect_Shell triggered"
	strings: $suspicious_string = "Alfa_Protect_Shell"
	condition: $suspicious_string
}
rule Rule_93_triggered {
	meta: description = "Rule # 93 Suspicious String Alicks triggered"
	strings: $suspicious_string = "Alicks"
	condition: $suspicious_string
}
rule Rule_94_triggered {
	meta: description = "Rule # 94 Suspicious String All Bangladeshi Hackers triggered"
	strings: $suspicious_string = "All Bangladeshi Hackers"
	condition: $suspicious_string
}
rule Rule_95_triggered {
	meta: description = "Rule # 95 Suspicious String All Muslims Hackers triggered"
	strings: $suspicious_string = "All Muslims Hackers"
	condition: $suspicious_string
}
rule Rule_96_triggered {
	meta: description = "Rule # 96 Suspicious String All Pakistani Hackers Teams triggered"
	strings: $suspicious_string = "All Pakistani Hackers Teams"
	condition: $suspicious_string
}
rule Rule_97_triggered {
	meta: description = "Rule # 97 Suspicious String Alliance Rezult triggered"
	strings: $suspicious_string = "Alliance Rezult"
	condition: $suspicious_string
}
rule Rule_98_triggered {
	meta: description = "Rule # 98 Suspicious String Amin Safi triggered"
	strings: $suspicious_string = "Amin Safi"
	condition: $suspicious_string
}
rule Rule_99_triggered {
	meta: description = "Rule # 99 Suspicious String An0n 3xPloiTeR triggered"
	strings: $suspicious_string = "An0n 3xPloiTeR"
	condition: $suspicious_string
}
rule Rule_100_triggered {
	meta: description = "Rule # 100 Suspicious String Anas laribi triggered"
	strings: $suspicious_string = "Anas laribi"
	condition: $suspicious_string
}
rule Rule_101_triggered {
	meta: description = "Rule # 101 Suspicious String Andela1C3 Priv8 Webshell triggered"
	strings: $suspicious_string = "Andela1C3 Priv8 Webshell"
	condition: $suspicious_string
}
rule Rule_102_triggered {
	meta: description = "Rule # 102 Suspicious String Aneesh Dogra triggered"
	strings: $suspicious_string = "Aneesh Dogra"
	condition: $suspicious_string
}
rule Rule_103_triggered {
	meta: description = "Rule # 103 Suspicious String Angga    triggered"
	strings: $suspicious_string = "Angga   "
	condition: $suspicious_string
}
rule Rule_104_triggered {
	meta: description = "Rule # 104 Suspicious String Ani-Shell triggered"
	strings: $suspicious_string = "Ani-Shell"
	condition: $suspicious_string
}
rule Rule_105_triggered {
	meta: description = "Rule # 105 Suspicious String AnonGhost triggered"
	strings: $suspicious_string = "AnonGhost"
	condition: $suspicious_string
}
rule Rule_106_triggered {
	meta: description = "Rule # 106 Suspicious String Anonymous Cyber Team triggered"
	strings: $suspicious_string = "Anonymous Cyber Team"
	condition: $suspicious_string
}
rule Rule_107_triggered {
	meta: description = "Rule # 107 Suspicious String AnonyniX triggered"
	strings: $suspicious_string = "AnonyniX"
	condition: $suspicious_string
}
rule Rule_108_triggered {
	meta: description = "Rule # 108 Suspicious String Ashura triggered"
	strings: $suspicious_string = "Ashura"
	condition: $suspicious_string
}
rule Rule_109_triggered {
	meta: description = "Rule # 109 Suspicious String AsteriX triggered"
	strings: $suspicious_string = "AsteriX"
	condition: $suspicious_string
}
rule Rule_110_triggered {
	meta: description = "Rule # 110 Suspicious String Aswaja007 triggered"
	strings: $suspicious_string = "Aswaja007"
	condition: $suspicious_string
}
rule Rule_111_triggered {
	meta: description = "Rule # 111 Suspicious String Atul Dwivedi triggered"
	strings: $suspicious_string = "Atul Dwivedi"
	condition: $suspicious_string
}
rule Rule_112_triggered {
	meta: description = "Rule # 112 Suspicious String Aughost triggered"
	strings: $suspicious_string = "Aughost"
	condition: $suspicious_string
}
rule Rule_113_triggered {
	meta: description = "Rule # 113 Suspicious String Author Sole Sad & Invisible triggered"
	strings: $suspicious_string = "Author Sole Sad & Invisible"
	condition: $suspicious_string
}
rule Rule_114_triggered {
	meta: description = "Rule # 114 Suspicious String Auto Root Exploit triggered"
	strings: $suspicious_string = "Auto Root Exploit"
	condition: $suspicious_string
}
rule Rule_115_triggered {
	meta: description = "Rule # 115 Suspicious String Automatic cPanel Finder/Cracker triggered"
	strings: $suspicious_string = "Automatic cPanel Finder/Cracker"
	condition: $suspicious_string
}
rule Rule_116_triggered {
	meta: description = "Rule # 116 Suspicious String Awake | Offiice 365 triggered"
	strings: $suspicious_string = "Awake | Offiice 365"
	condition: $suspicious_string
}
rule Rule_117_triggered {
	meta: description = "Rule # 117 Suspicious String Awake | hotrnail triggered"
	strings: $suspicious_string = "Awake | hotrnail"
	condition: $suspicious_string
}
rule Rule_118_triggered {
	meta: description = "Rule # 118 Suspicious String Awake | otlher triggered"
	strings: $suspicious_string = "Awake | otlher"
	condition: $suspicious_string
}
rule Rule_119_triggered {
	meta: description = "Rule # 119 Suspicious String Awake| Company grnail triggered"
	strings: $suspicious_string = "Awake| Company grnail"
	condition: $suspicious_string
}
rule Rule_120_triggered {
	meta: description = "Rule # 120 Suspicious String Awake| a0l triggered"
	strings: $suspicious_string = "Awake| a0l"
	condition: $suspicious_string
}
rule Rule_121_triggered {
	meta: description = "Rule # 121 Suspicious String Awake| yah00 triggered"
	strings: $suspicious_string = "Awake| yah00"
	condition: $suspicious_string
}
rule Rule_122_triggered {
	meta: description = "Rule # 122 Suspicious String Aweu404 triggered"
	strings: $suspicious_string = "Aweu404"
	condition: $suspicious_string
}
rule Rule_123_triggered {
	meta: description = "Rule # 123 Suspicious String Ayaan CH triggered"
	strings: $suspicious_string = "Ayaan CH"
	condition: $suspicious_string
}
rule Rule_124_triggered {
	meta: description = "Rule # 124 Suspicious String Azzatssins triggered"
	strings: $suspicious_string = "Azzatssins"
	condition: $suspicious_string
}
rule Rule_125_triggered {
	meta: description = "Rule # 125 Suspicious String B.A.D TEAM triggered"
	strings: $suspicious_string = "B.A.D TEAM"
	condition: $suspicious_string
}
rule Rule_126_triggered {
	meta: description = "Rule # 126 Suspicious String B0c4H_Id30T triggered"
	strings: $suspicious_string = "B0c4H_Id30T"
	condition: $suspicious_string
}
rule Rule_127_triggered {
	meta: description = "Rule # 127 Suspicious String B0tchZ triggered"
	strings: $suspicious_string = "B0tchZ"
	condition: $suspicious_string
}
rule Rule_128_triggered {
	meta: description = "Rule # 128 Suspicious String BACK-CONNECT triggered"
	strings: $suspicious_string = "BACK-CONNECT"
	condition: $suspicious_string
}
rule Rule_129_triggered {
	meta: description = "Rule # 129 Suspicious String BACKDOOR triggered"
	strings: $suspicious_string = "BACKDOOR"
	condition: $suspicious_string
}
rule Rule_130_triggered {
	meta: description = "Rule # 130 Suspicious String BAHARI TROUBLE MAKER triggered"
	strings: $suspicious_string = "BAHARI TROUBLE MAKER"
	condition: $suspicious_string
}
rule Rule_131_triggered {
	meta: description = "Rule # 131 Suspicious String BANGLADESHI HACKER triggered"
	strings: $suspicious_string = "BANGLADESHI HACKER"
	condition: $suspicious_string
}
rule Rule_132_triggered {
	meta: description = "Rule # 132 Suspicious String BD BLACK HAT HACKERS triggered"
	strings: $suspicious_string = "BD BLACK HAT HACKERS"
	condition: $suspicious_string
}
rule Rule_133_triggered {
	meta: description = "Rule # 133 Suspicious String BHP.php triggered"
	strings: $suspicious_string = "BHP.php"
	condition: $suspicious_string
}
rule Rule_134_triggered {
	meta: description = "Rule # 134 Suspicious String BLACKMANSNOOP triggered"
	strings: $suspicious_string = "BLACKMANSNOOP"
	condition: $suspicious_string
}
rule Rule_135_triggered {
	meta: description = "Rule # 135 Suspicious String BLAZING HACKERS PAKISTAN triggered"
	strings: $suspicious_string = "BLAZING HACKERS PAKISTAN"
	condition: $suspicious_string
}
rule Rule_136_triggered {
	meta: description = "Rule # 136 Suspicious String BLESSED-HOTMAIL LOGINS triggered"
	strings: $suspicious_string = "BLESSED-HOTMAIL LOGINS"
	condition: $suspicious_string
}
rule Rule_137_triggered {
	meta: description = "Rule # 137 Suspicious String BY GENtLEMind triggered"
	strings: $suspicious_string = "BY GENtLEMind"
	condition: $suspicious_string
}
rule Rule_138_triggered {
	meta: description = "Rule # 138 Suspicious String BackBone triggered"
	strings: $suspicious_string = "BackBone"
	condition: $suspicious_string
}
rule Rule_139_triggered {
	meta: description = "Rule # 139 Suspicious String BackConnect Php By Con7ext triggered"
	strings: $suspicious_string = "BackConnect Php By Con7ext"
	condition: $suspicious_string
}
rule Rule_140_triggered {
	meta: description = "Rule # 140 Suspicious String Bahari Trouble Maker triggered"
	strings: $suspicious_string = "Bahari Trouble Maker"
	condition: $suspicious_string
}
rule Rule_141_triggered {
	meta: description = "Rule # 141 Suspicious String Bd Xtor triggered"
	strings: $suspicious_string = "Bd Xtor"
	condition: $suspicious_string
}
rule Rule_142_triggered {
	meta: description = "Rule # 142 Suspicious String Beep-Beep triggered"
	strings: $suspicious_string = "Beep-Beep"
	condition: $suspicious_string
}
rule Rule_143_triggered {
	meta: description = "Rule # 143 Suspicious String Bejo_Abk triggered"
	strings: $suspicious_string = "Bejo_Abk"
	condition: $suspicious_string
}
rule Rule_144_triggered {
	meta: description = "Rule # 144 Suspicious String Bella! triggered"
	strings: $suspicious_string = "Bella!"
	condition: $suspicious_string
}
rule Rule_145_triggered {
	meta: description = "Rule # 145 Suspicious String BerdendangC0de triggered"
	strings: $suspicious_string = "BerdendangC0de"
	condition: $suspicious_string
}
rule Rule_146_triggered {
	meta: description = "Rule # 146 Suspicious String Bhuppi triggered"
	strings: $suspicious_string = "Bhuppi"
	condition: $suspicious_string
}
rule Rule_147_triggered {
	meta: description = "Rule # 147 Suspicious String BigStar triggered"
	strings: $suspicious_string = "BigStar"
	condition: $suspicious_string
}
rule Rule_148_triggered {
	meta: description = "Rule # 148 Suspicious String Bksmile triggered"
	strings: $suspicious_string = "Bksmile"
	condition: $suspicious_string
}
rule Rule_149_triggered {
	meta: description = "Rule # 149 Suspicious String Bl@cK Ic3 triggered"
	strings: $suspicious_string = "Bl@cK Ic3"
	condition: $suspicious_string
}
rule Rule_150_triggered {
	meta: description = "Rule # 150 Suspicious String BlackBlood triggered"
	strings: $suspicious_string = "BlackBlood"
	condition: $suspicious_string
}
rule Rule_151_triggered {
	meta: description = "Rule # 151 Suspicious String BlackSHOP triggered"
	strings: $suspicious_string = "BlackSHOP"
	condition: $suspicious_string
}
rule Rule_152_triggered {
	meta: description = "Rule # 152 Suspicious String BlackSmith Hacker's Team triggered"
	strings: $suspicious_string = "BlackSmith Hacker's Team"
	condition: $suspicious_string
}
rule Rule_153_triggered {
	meta: description = "Rule # 153 Suspicious String BlackWeb triggered"
	strings: $suspicious_string = "BlackWeb"
	condition: $suspicious_string
}
rule Rule_154_triggered {
	meta: description = "Rule # 154 Suspicious String Blackportt triggered"
	strings: $suspicious_string = "Blackportt"
	condition: $suspicious_string
}
rule Rule_155_triggered {
	meta: description = "Rule # 155 Suspicious String Blazing Hackers Pakistan triggered"
	strings: $suspicious_string = "Blazing Hackers Pakistan"
	condition: $suspicious_string
}
rule Rule_156_triggered {
	meta: description = "Rule # 156 Suspicious String Bloc_Anon/404  triggered"
	strings: $suspicious_string = "Bloc_Anon/404 "
	condition: $suspicious_string
}
rule Rule_157_triggered {
	meta: description = "Rule # 157 Suspicious String Blood Tears No Team Squad triggered"
	strings: $suspicious_string = "Blood Tears No Team Squad"
	condition: $suspicious_string
}
rule Rule_158_triggered {
	meta: description = "Rule # 158 Suspicious String BoffMax triggered"
	strings: $suspicious_string = "BoffMax"
	condition: $suspicious_string
}
rule Rule_159_triggered {
	meta: description = "Rule # 159 Suspicious String Bogor BlackHat triggered"
	strings: $suspicious_string = "Bogor BlackHat"
	condition: $suspicious_string
}
rule Rule_160_triggered {
	meta: description = "Rule # 160 Suspicious String Bougaa DZ triggered"
	strings: $suspicious_string = "Bougaa DZ"
	condition: $suspicious_string
}
rule Rule_161_triggered {
	meta: description = "Rule # 161 Suspicious String Brian Kamikaze triggered"
	strings: $suspicious_string = "Brian Kamikaze"
	condition: $suspicious_string
}
rule Rule_162_triggered {
	meta: description = "Rule # 162 Suspicious String BrotherHood triggered"
	strings: $suspicious_string = "BrotherHood"
	condition: $suspicious_string
}
rule Rule_163_triggered {
	meta: description = "Rule # 163 Suspicious String Budhaoo triggered"
	strings: $suspicious_string = "Budhaoo"
	condition: $suspicious_string
}
rule Rule_164_triggered {
	meta: description = "Rule # 164 Suspicious String Bumi404 triggered"
	strings: $suspicious_string = "Bumi404"
	condition: $suspicious_string
}
rule Rule_165_triggered {
	meta: description = "Rule # 165 Suspicious String By  NaZZ triggered"
	strings: $suspicious_string = "By  NaZZ"
	condition: $suspicious_string
}
rule Rule_166_triggered {
	meta: description = "Rule # 166 Suspicious String By Alarg53 triggered"
	strings: $suspicious_string = "By Alarg53"
	condition: $suspicious_string
}
rule Rule_167_triggered {
	meta: description = "Rule # 167 Suspicious String By Hawleri_hacker triggered"
	strings: $suspicious_string = "By Hawleri_hacker"
	condition: $suspicious_string
}
rule Rule_168_triggered {
	meta: description = "Rule # 168 Suspicious String By NeT.Defacer triggered"
	strings: $suspicious_string = "By NeT.Defacer"
	condition: $suspicious_string
}
rule Rule_169_triggered {
	meta: description = "Rule # 169 Suspicious String By RxR triggered"
	strings: $suspicious_string = "By RxR"
	condition: $suspicious_string
}
rule Rule_170_triggered {
	meta: description = "Rule # 170 Suspicious String By The 1962 Script Coded By Akram Stelle triggered"
	strings: $suspicious_string = "By The 1962 Script Coded By Akram Stelle"
	condition: $suspicious_string
}
rule Rule_171_triggered {
	meta: description = "Rule # 171 Suspicious String By Toxica DZ triggered"
	strings: $suspicious_string = "By Toxica DZ"
	condition: $suspicious_string
}
rule Rule_172_triggered {
	meta: description = "Rule # 172 Suspicious String By: 3Turr triggered"
	strings: $suspicious_string = "By: 3Turr"
	condition: $suspicious_string
}
rule Rule_173_triggered {
	meta: description = "Rule # 173 Suspicious String ByAgeNT triggered"
	strings: $suspicious_string = "ByAgeNT"
	condition: $suspicious_string
}
rule Rule_174_triggered {
	meta: description = "Rule # 174 Suspicious String Byms_Cod triggered"
	strings: $suspicious_string = "Byms_Cod"
	condition: $suspicious_string
}
rule Rule_175_triggered {
	meta: description = "Rule # 175 Suspicious String Bypass Shell triggered"
	strings: $suspicious_string = "Bypass Shell"
	condition: $suspicious_string
}
rule Rule_176_triggered {
	meta: description = "Rule # 176 Suspicious String Bypass User With : triggered"
	strings: $suspicious_string = "Bypass User With :"
	condition: $suspicious_string
}
rule Rule_177_triggered {
	meta: description = "Rule # 177 Suspicious String Bypass etc/passw triggered"
	strings: $suspicious_string = "Bypass etc/passw"
	condition: $suspicious_string
}
rule Rule_178_triggered {
	meta: description = "Rule # 178 Suspicious String C0D3D triggered"
	strings: $suspicious_string = "C0D3D"
	condition: $suspicious_string
}
rule Rule_179_triggered {
	meta: description = "Rule # 179 Suspicious String C0d3d by kid brizy triggered"
	strings: $suspicious_string = "C0d3d by kid brizy"
	condition: $suspicious_string
}
rule Rule_180_triggered {
	meta: description = "Rule # 180 Suspicious String C0o5@yahoo.com triggered"
	strings: $suspicious_string = "C0o5@yahoo.com"
	condition: $suspicious_string
}
rule Rule_181_triggered {
	meta: description = "Rule # 181 Suspicious String C99 Modified By Psych0 triggered"
	strings: $suspicious_string = "C99 Modified By Psych0"
	condition: $suspicious_string
}
rule Rule_182_triggered {
	meta: description = "Rule # 182 Suspicious String CCOCOT triggered"
	strings: $suspicious_string = "CCOCOT"
	condition: $suspicious_string
}
rule Rule_183_triggered {
	meta: description = "Rule # 183 Suspicious String CGI-Telnet triggered"
	strings: $suspicious_string = "CGI-Telnet"
	condition: $suspicious_string
}
rule Rule_184_triggered {
	meta: description = "Rule # 184 Suspicious String CIA@MYWORK triggered"
	strings: $suspicious_string = "CIA@MYWORK"
	condition: $suspicious_string
}
rule Rule_185_triggered {
	meta: description = "Rule # 185 Suspicious String CODED BY RAB3OUN triggered"
	strings: $suspicious_string = "CODED BY RAB3OUN"
	condition: $suspicious_string
}
rule Rule_186_triggered {
	meta: description = "Rule # 186 Suspicious String COUNT DOMAIN USER Password .accesshash triggered"
	strings: $suspicious_string = "COUNT DOMAIN USER Password .accesshash"
	condition: $suspicious_string
}
rule Rule_187_triggered {
	meta: description = "Rule # 187 Suspicious String CP Bruter triggered"
	strings: $suspicious_string = "CP Bruter"
	condition: $suspicious_string
}
rule Rule_188_triggered {
	meta: description = "Rule # 188 Suspicious String CPanel Brut3r triggered"
	strings: $suspicious_string = "CPanel Brut3r"
	condition: $suspicious_string
}
rule Rule_189_triggered {
	meta: description = "Rule # 189 Suspicious String CPanel Bruteforce triggered"
	strings: $suspicious_string = "CPanel Bruteforce"
	condition: $suspicious_string
}
rule Rule_190_triggered {
	meta: description = "Rule # 190 Suspicious String CPanel Crack triggered"
	strings: $suspicious_string = "CPanel Crack"
	condition: $suspicious_string
}
rule Rule_191_triggered {
	meta: description = "Rule # 191 Suspicious String CPanel/FTP Auto Deface triggered"
	strings: $suspicious_string = "CPanel/FTP Auto Deface"
	condition: $suspicious_string
}
rule Rule_192_triggered {
	meta: description = "Rule # 192 Suspicious String CaZaNoVa163 triggered"
	strings: $suspicious_string = "CaZaNoVa163"
	condition: $suspicious_string
}
rule Rule_193_triggered {
	meta: description = "Rule # 193 Suspicious String Captain Crunch triggered"
	strings: $suspicious_string = "Captain Crunch"
	condition: $suspicious_string
}
rule Rule_194_triggered {
	meta: description = "Rule # 194 Suspicious String Cardiman Asooooh triggered"
	strings: $suspicious_string = "Cardiman Asooooh"
	condition: $suspicious_string
}
rule Rule_195_triggered {
	meta: description = "Rule # 195 Suspicious String Cardiman Asoooooooooh triggered"
	strings: $suspicious_string = "Cardiman Asoooooooooh"
	condition: $suspicious_string
}
rule Rule_196_triggered {
	meta: description = "Rule # 196 Suspicious String Casper_Cell triggered"
	strings: $suspicious_string = "Casper_Cell"
	condition: $suspicious_string
}
rule Rule_197_triggered {
	meta: description = "Rule # 197 Suspicious String Ccocot  triggered"
	strings: $suspicious_string = "Ccocot "
	condition: $suspicious_string
}
rule Rule_198_triggered {
	meta: description = "Rule # 198 Suspicious String Cgi WebShell ByPasser triggered"
	strings: $suspicious_string = "Cgi WebShell ByPasser"
	condition: $suspicious_string
}
rule Rule_199_triggered {
	meta: description = "Rule # 199 Suspicious String Ch3rn0by1 triggered"
	strings: $suspicious_string = "Ch3rn0by1"
	condition: $suspicious_string
}
rule Rule_200_triggered {
	meta: description = "Rule # 200 Suspicious String Chakus triggered"
	strings: $suspicious_string = "Chakus"
	condition: $suspicious_string
}
rule Rule_201_triggered {
	meta: description = "Rule # 201 Suspicious String Champion.hack triggered"
	strings: $suspicious_string = "Champion.hack"
	condition: $suspicious_string
}
rule Rule_202_triggered {
	meta: description = "Rule # 202 Suspicious String Changes every cPanel password on the server and stores the credentials triggered"
	strings: $suspicious_string = "Changes every cPanel password on the server and stores the credentials"
	condition: $suspicious_string
}
rule Rule_203_triggered {
	meta: description = "Rule # 203 Suspicious String Chase USA  triggered"
	strings: $suspicious_string = "Chase USA "
	condition: $suspicious_string
}
rule Rule_204_triggered {
	meta: description = "Rule # 204 Suspicious String Check  Mailling triggered"
	strings: $suspicious_string = "Check  Mailling"
	condition: $suspicious_string
}
rule Rule_205_triggered {
	meta: description = "Rule # 205 Suspicious String Check Mail Pass Login Access triggered"
	strings: $suspicious_string = "Check Mail Pass Login Access"
	condition: $suspicious_string
}
rule Rule_206_triggered {
	meta: description = "Rule # 206 Suspicious String ChickenLittle Shell triggered"
	strings: $suspicious_string = "ChickenLittle Shell"
	condition: $suspicious_string
}
rule Rule_207_triggered {
	meta: description = "Rule # 207 Suspicious String Chizzy triggered"
	strings: $suspicious_string = "Chizzy"
	condition: $suspicious_string
}
rule Rule_208_triggered {
	meta: description = "Rule # 208 Suspicious String Christian \"FireFart\" Mehlmauer triggered"
	strings: $suspicious_string = "Christian \"FireFart\" Mehlmauer"
	condition: $suspicious_string
}
rule Rule_209_triggered {
	meta: description = "Rule # 209 Suspicious String Cod3d by 3xp1r3 triggered"
	strings: $suspicious_string = "Cod3d by 3xp1r3"
	condition: $suspicious_string
}
rule Rule_210_triggered {
	meta: description = "Rule # 210 Suspicious String Cod3d by Haxor-Waha triggered"
	strings: $suspicious_string = "Cod3d by Haxor-Waha"
	condition: $suspicious_string
}
rule Rule_211_triggered {
	meta: description = "Rule # 211 Suspicious String Cod3d by Mr.Alsa3ek and Al-Swisre triggered"
	strings: $suspicious_string = "Cod3d by Mr.Alsa3ek and Al-Swisre"
	condition: $suspicious_string
}
rule Rule_212_triggered {
	meta: description = "Rule # 212 Suspicious String Code By Astra triggered"
	strings: $suspicious_string = "Code By Astra"
	condition: $suspicious_string
}
rule Rule_213_triggered {
	meta: description = "Rule # 213 Suspicious String Code by Mr.HaurgeulisX196 triggered"
	strings: $suspicious_string = "Code by Mr.HaurgeulisX196"
	condition: $suspicious_string
}
rule Rule_214_triggered {
	meta: description = "Rule # 214 Suspicious String Code for India,Hack for India,Die for India triggered"
	strings: $suspicious_string = "Code for India,Hack for India,Die for India"
	condition: $suspicious_string
}
rule Rule_215_triggered {
	meta: description = "Rule # 215 Suspicious String Coded By - SaMir InjectOr triggered"
	strings: $suspicious_string = "Coded By - SaMir InjectOr"
	condition: $suspicious_string
}
rule Rule_216_triggered {
	meta: description = "Rule # 216 Suspicious String Coded By GENERAL-IQ triggered"
	strings: $suspicious_string = "Coded By GENERAL-IQ"
	condition: $suspicious_string
}
rule Rule_217_triggered {
	meta: description = "Rule # 217 Suspicious String Coded By P4LTEAM triggered"
	strings: $suspicious_string = "Coded By P4LTEAM"
	condition: $suspicious_string
}
rule Rule_218_triggered {
	meta: description = "Rule # 218 Suspicious String Coded by Anonisma triggered"
	strings: $suspicious_string = "Coded by Anonisma"
	condition: $suspicious_string
}
rule Rule_219_triggered {
	meta: description = "Rule # 219 Suspicious String Coded by Miyachung triggered"
	strings: $suspicious_string = "Coded by Miyachung"
	condition: $suspicious_string
}
rule Rule_220_triggered {
	meta: description = "Rule # 220 Suspicious String Coded by van1lle @ Hackforums.net triggered"
	strings: $suspicious_string = "Coded by van1lle @ Hackforums.net"
	condition: $suspicious_string
}
rule Rule_221_triggered {
	meta: description = "Rule # 221 Suspicious String Codz by angel(4ngel) triggered"
	strings: $suspicious_string = "Codz by angel(4ngel)"
	condition: $suspicious_string
}
rule Rule_222_triggered {
	meta: description = "Rule # 222 Suspicious String CoinHive.User triggered"
	strings: $suspicious_string = "CoinHive.User"
	condition: $suspicious_string
}
rule Rule_223_triggered {
	meta: description = "Rule # 223 Suspicious String Con7ext  triggered"
	strings: $suspicious_string = "Con7ext "
	condition: $suspicious_string
}
rule Rule_224_triggered {
	meta: description = "Rule # 224 Suspicious String Config Fucker triggered"
	strings: $suspicious_string = "Config Fucker"
	condition: $suspicious_string
}
rule Rule_225_triggered {
	meta: description = "Rule # 225 Suspicious String Config Password Grabber triggered"
	strings: $suspicious_string = "Config Password Grabber"
	condition: $suspicious_string
}
rule Rule_226_triggered {
	meta: description = "Rule # 226 Suspicious String Config SHELL triggered"
	strings: $suspicious_string = "Config SHELL"
	condition: $suspicious_string
}
rule Rule_227_triggered {
	meta: description = "Rule # 227 Suspicious String Config Symlink Script V-3.0 triggered"
	strings: $suspicious_string = "Config Symlink Script V-3.0"
	condition: $suspicious_string
}
rule Rule_228_triggered {
	meta: description = "Rule # 228 Suspicious String Configs Grabber triggered"
	strings: $suspicious_string = "Configs Grabber"
	condition: $suspicious_string
}
rule Rule_229_triggered {
	meta: description = "Rule # 229 Suspicious String Configv2 SHELL triggered"
	strings: $suspicious_string = "Configv2 SHELL"
	condition: $suspicious_string
}
rule Rule_230_triggered {
	meta: description = "Rule # 230 Suspicious String Connecting email server on progress triggered"
	strings: $suspicious_string = "Connecting email server on progress"
	condition: $suspicious_string
}
rule Rule_231_triggered {
	meta: description = "Rule # 231 Suspicious String Coupdegrace triggered"
	strings: $suspicious_string = "Coupdegrace"
	condition: $suspicious_string
}
rule Rule_232_triggered {
	meta: description = "Rule # 232 Suspicious String CowoKerensTeam triggered"
	strings: $suspicious_string = "CowoKerensTeam"
	condition: $suspicious_string
}
rule Rule_233_triggered {
	meta: description = "Rule # 233 Suspicious String Cowok Kerens Team triggered"
	strings: $suspicious_string = "Cowok Kerens Team"
	condition: $suspicious_string
}
rule Rule_234_triggered {
	meta: description = "Rule # 234 Suspicious String Cowok Tersakiti Team triggered"
	strings: $suspicious_string = "Cowok Tersakiti Team"
	condition: $suspicious_string
}
rule Rule_235_triggered {
	meta: description = "Rule # 235 Suspicious String Crash & Burn triggered"
	strings: $suspicious_string = "Crash & Burn"
	condition: $suspicious_string
}
rule Rule_236_triggered {
	meta: description = "Rule # 236 Suspicious String Create User FOLDER SCAM triggered"
	strings: $suspicious_string = "Create User FOLDER SCAM"
	condition: $suspicious_string
}
rule Rule_237_triggered {
	meta: description = "Rule # 237 Suspicious String Created BY RF in 2018 (skype:RF) triggered"
	strings: $suspicious_string = "Created BY RF in 2018 (skype:RF)"
	condition: $suspicious_string
}
rule Rule_238_triggered {
	meta: description = "Rule # 238 Suspicious String Created BY TIKTAK 20 triggered"
	strings: $suspicious_string = "Created BY TIKTAK 20"
	condition: $suspicious_string
}
rule Rule_239_triggered {
	meta: description = "Rule # 239 Suspicious String Created By Hacker L3L3 triggered"
	strings: $suspicious_string = "Created By Hacker L3L3"
	condition: $suspicious_string
}
rule Rule_240_triggered {
	meta: description = "Rule # 240 Suspicious String Created By vi3nas ym triggered"
	strings: $suspicious_string = "Created By vi3nas ym"
	condition: $suspicious_string
}
rule Rule_241_triggered {
	meta: description = "Rule # 241 Suspicious String Cy3er C0mmand0s triggered"
	strings: $suspicious_string = "Cy3er C0mmand0s"
	condition: $suspicious_string
}
rule Rule_242_triggered {
	meta: description = "Rule # 242 Suspicious String Cyb er Hunter triggered"
	strings: $suspicious_string = "Cyb er Hunter"
	condition: $suspicious_string
}
rule Rule_243_triggered {
	meta: description = "Rule # 243 Suspicious String Cyb3r-DZ Config triggered"
	strings: $suspicious_string = "Cyb3r-DZ Config"
	condition: $suspicious_string
}
rule Rule_244_triggered {
	meta: description = "Rule # 244 Suspicious String Cyb3r.Bl@d3r triggered"
	strings: $suspicious_string = "Cyb3r.Bl@d3r"
	condition: $suspicious_string
}
rule Rule_245_triggered {
	meta: description = "Rule # 245 Suspicious String Cyber 71 triggered"
	strings: $suspicious_string = "Cyber 71"
	condition: $suspicious_string
}
rule Rule_246_triggered {
	meta: description = "Rule # 246 Suspicious String Cyber Ace triggered"
	strings: $suspicious_string = "Cyber Ace"
	condition: $suspicious_string
}
rule Rule_247_triggered {
	meta: description = "Rule # 247 Suspicious String Cyber Merah Putih triggered"
	strings: $suspicious_string = "Cyber Merah Putih"
	condition: $suspicious_string
}
rule Rule_248_triggered {
	meta: description = "Rule # 248 Suspicious String Cyber Security Down triggered"
	strings: $suspicious_string = "Cyber Security Down"
	condition: $suspicious_string
}
rule Rule_249_triggered {
	meta: description = "Rule # 249 Suspicious String Cyber Tron Darkness triggered"
	strings: $suspicious_string = "Cyber Tron Darkness"
	condition: $suspicious_string
}
rule Rule_250_triggered {
	meta: description = "Rule # 250 Suspicious String CyberTeamRox triggered"
	strings: $suspicious_string = "CyberTeamRox"
	condition: $suspicious_string
}
rule Rule_251_triggered {
	meta: description = "Rule # 251 Suspicious String Cybertech triggered"
	strings: $suspicious_string = "Cybertech"
	condition: $suspicious_string
}
rule Rule_252_triggered {
	meta: description = "Rule # 252 Suspicious String D33F_404  triggered"
	strings: $suspicious_string = "D33F_404 "
	condition: $suspicious_string
}
rule Rule_253_triggered {
	meta: description = "Rule # 253 Suspicious String D4rkSect0r triggered"
	strings: $suspicious_string = "D4rkSect0r"
	condition: $suspicious_string
}
rule Rule_254_triggered {
	meta: description = "Rule # 254 Suspicious String D@rk sH@d0w triggered"
	strings: $suspicious_string = "D@rk sH@d0w"
	condition: $suspicious_string
}
rule Rule_255_triggered {
	meta: description = "Rule # 255 Suspicious String DABBING404 triggered"
	strings: $suspicious_string = "DABBING404"
	condition: $suspicious_string
}
rule Rule_256_triggered {
	meta: description = "Rule # 256 Suspicious String DDoS Perl IrcBot v1.0 triggered"
	strings: $suspicious_string = "DDoS Perl IrcBot v1.0"
	condition: $suspicious_string
}
rule Rule_257_triggered {
	meta: description = "Rule # 257 Suspicious String DEFACE IP GRABBER triggered"
	strings: $suspicious_string = "DEFACE IP GRABBER"
	condition: $suspicious_string
}
rule Rule_258_triggered {
	meta: description = "Rule # 258 Suspicious String DHL WIRE LOG triggered"
	strings: $suspicious_string = "DHL WIRE LOG"
	condition: $suspicious_string
}
rule Rule_259_triggered {
	meta: description = "Rule # 259 Suspicious String DK Shell triggered"
	strings: $suspicious_string = "DK Shell"
	condition: $suspicious_string
}
rule Rule_260_triggered {
	meta: description = "Rule # 260 Suspicious String DM Mini Shell triggered"
	strings: $suspicious_string = "DM Mini Shell"
	condition: $suspicious_string
}
rule Rule_261_triggered {
	meta: description = "Rule # 261 Suspicious String DR.RooT triggered"
	strings: $suspicious_string = "DR.RooT"
	condition: $suspicious_string
}
rule Rule_262_triggered {
	meta: description = "Rule # 262 Suspicious String DaiMon triggered"
	strings: $suspicious_string = "DaiMon"
	condition: $suspicious_string
}
rule Rule_263_triggered {
	meta: description = "Rule # 263 Suspicious String DamaneDz triggered"
	strings: $suspicious_string = "DamaneDz"
	condition: $suspicious_string
}
rule Rule_264_triggered {
	meta: description = "Rule # 264 Suspicious String Dark Pinus Squad triggered"
	strings: $suspicious_string = "Dark Pinus Squad"
	condition: $suspicious_string
}
rule Rule_265_triggered {
	meta: description = "Rule # 265 Suspicious String Dark Shell triggered"
	strings: $suspicious_string = "Dark Shell"
	condition: $suspicious_string
}
rule Rule_266_triggered {
	meta: description = "Rule # 266 Suspicious String Dark.anGel triggered"
	strings: $suspicious_string = "Dark.anGel"
	condition: $suspicious_string
}
rule Rule_267_triggered {
	meta: description = "Rule # 267 Suspicious String DarkWireless  triggered"
	strings: $suspicious_string = "DarkWireless "
	condition: $suspicious_string
}
rule Rule_268_triggered {
	meta: description = "Rule # 268 Suspicious String Darkwolf indishell triggered"
	strings: $suspicious_string = "Darkwolf indishell"
	condition: $suspicious_string
}
rule Rule_269_triggered {
	meta: description = "Rule # 269 Suspicious String DeMiGoD triggered"
	strings: $suspicious_string = "DeMiGoD"
	condition: $suspicious_string
}
rule Rule_270_triggered {
	meta: description = "Rule # 270 Suspicious String Dead Inside triggered"
	strings: $suspicious_string = "Dead Inside"
	condition: $suspicious_string
}
rule Rule_271_triggered {
	meta: description = "Rule # 271 Suspicious String Dear Kids This is Payback! for Defacing The Islamia University of Bahawalpur triggered"
	strings: $suspicious_string = "Dear Kids This is Payback! for Defacing The Islamia University of Bahawalpur"
	condition: $suspicious_string
}
rule Rule_272_triggered {
	meta: description = "Rule # 272 Suspicious String Death Adders Crew triggered"
	strings: $suspicious_string = "Death Adders Crew"
	condition: $suspicious_string
}
rule Rule_273_triggered {
	meta: description = "Rule # 273 Suspicious String Deface Gagal triggered"
	strings: $suspicious_string = "Deface Gagal"
	condition: $suspicious_string
}
rule Rule_274_triggered {
	meta: description = "Rule # 274 Suspicious String Defacer.ID triggered"
	strings: $suspicious_string = "Defacer.ID"
	condition: $suspicious_string
}
rule Rule_275_triggered {
	meta: description = "Rule # 275 Suspicious String Developed By ANASH triggered"
	strings: $suspicious_string = "Developed By ANASH"
	condition: $suspicious_string
}
rule Rule_276_triggered {
	meta: description = "Rule # 276 Suspicious String Developed By Mohajer22 triggered"
	strings: $suspicious_string = "Developed By Mohajer22"
	condition: $suspicious_string
}
rule Rule_277_triggered {
	meta: description = "Rule # 277 Suspicious String Developed By sNiper_hEx triggered"
	strings: $suspicious_string = "Developed By sNiper_hEx"
	condition: $suspicious_string
}
rule Rule_278_triggered {
	meta: description = "Rule # 278 Suspicious String Developer by SnIpEr_SA triggered"
	strings: $suspicious_string = "Developer by SnIpEr_SA"
	condition: $suspicious_string
}
rule Rule_279_triggered {
	meta: description = "Rule # 279 Suspicious String Dhanush triggered"
	strings: $suspicious_string = "Dhanush"
	condition: $suspicious_string
}
rule Rule_280_triggered {
	meta: description = "Rule # 280 Suspicious String Dicky Injector  triggered"
	strings: $suspicious_string = "Dicky Injector "
	condition: $suspicious_string
}
rule Rule_281_triggered {
	meta: description = "Rule # 281 Suspicious String DiffMuRis  triggered"
	strings: $suspicious_string = "DiffMuRis "
	condition: $suspicious_string
}
rule Rule_282_triggered {
	meta: description = "Rule # 282 Suspicious String Dinaraditya154@gmail.com triggered"
	strings: $suspicious_string = "Dinaraditya154@gmail.com"
	condition: $suspicious_string
}
rule Rule_283_triggered {
	meta: description = "Rule # 283 Suspicious String Dinelson Amine triggered"
	strings: $suspicious_string = "Dinelson Amine"
	condition: $suspicious_string
}
rule Rule_284_triggered {
	meta: description = "Rule # 284 Suspicious String Dinoxchrome triggered"
	strings: $suspicious_string = "Dinoxchrome"
	condition: $suspicious_string
}
rule Rule_285_triggered {
	meta: description = "Rule # 285 Suspicious String Dipu Dada triggered"
	strings: $suspicious_string = "Dipu Dada"
	condition: $suspicious_string
}
rule Rule_286_triggered {
	meta: description = "Rule # 286 Suspicious String Dir ngk Writeable triggered"
	strings: $suspicious_string = "Dir ngk Writeable"
	condition: $suspicious_string
}
rule Rule_287_triggered {
	meta: description = "Rule # 287 Suspicious String DoitSelf triggered"
	strings: $suspicious_string = "DoitSelf"
	condition: $suspicious_string
}
rule Rule_288_triggered {
	meta: description = "Rule # 288 Suspicious String Dr.S4mom     triggered"
	strings: $suspicious_string = "Dr.S4mom    "
	condition: $suspicious_string
}
rule Rule_289_triggered {
	meta: description = "Rule # 289 Suspicious String Dr.iExplit triggered"
	strings: $suspicious_string = "Dr.iExplit"
	condition: $suspicious_string
}
rule Rule_290_triggered {
	meta: description = "Rule # 290 Suspicious String Dr.rba7 triggered"
	strings: $suspicious_string = "Dr.rba7"
	condition: $suspicious_string
}
rule Rule_291_triggered {
	meta: description = "Rule # 291 Suspicious String Dz Mafia Team triggered"
	strings: $suspicious_string = "Dz Mafia Team"
	condition: $suspicious_string
}
rule Rule_292_triggered {
	meta: description = "Rule # 292 Suspicious String E108dfcb.com triggered"
	strings: $suspicious_string = "E108dfcb.com"
	condition: $suspicious_string
}
rule Rule_293_triggered {
	meta: description = "Rule # 293 Suspicious String E7B_404 triggered"
	strings: $suspicious_string = "E7B_404"
	condition: $suspicious_string
}
rule Rule_294_triggered {
	meta: description = "Rule # 294 Suspicious String E@GL3 STR!K3R triggered"
	strings: $suspicious_string = "E@GL3 STR!K3R"
	condition: $suspicious_string
}
rule Rule_295_triggered {
	meta: description = "Rule # 295 Suspicious String E@gle Invectus Backdoor Handler triggered"
	strings: $suspicious_string = "E@gle Invectus Backdoor Handler"
	condition: $suspicious_string
}
rule Rule_296_triggered {
	meta: description = "Rule # 296 Suspicious String EBSCO ReZulTsz triggered"
	strings: $suspicious_string = "EBSCO ReZulTsz"
	condition: $suspicious_string
}
rule Rule_297_triggered {
	meta: description = "Rule # 297 Suspicious String EFRAIM AYYILDIZ triggered"
	strings: $suspicious_string = "EFRAIM AYYILDIZ"
	condition: $suspicious_string
}
rule Rule_298_triggered {
	meta: description = "Rule # 298 Suspicious String EITest triggered"
	strings: $suspicious_string = "EITest"
	condition: $suspicious_string
}
rule Rule_299_triggered {
	meta: description = "Rule # 299 Suspicious String EXI2T-team triggered"
	strings: $suspicious_string = "EXI2T-team"
	condition: $suspicious_string
}
rule Rule_300_triggered {
	meta: description = "Rule # 300 Suspicious String EXIT_KERNEL_TO_NULL triggered"
	strings: $suspicious_string = "EXIT_KERNEL_TO_NULL"
	condition: $suspicious_string
}
rule Rule_301_triggered {
	meta: description = "Rule # 301 Suspicious String EXPECT US! triggered"
	strings: $suspicious_string = "EXPECT US!"
	condition: $suspicious_string
}
rule Rule_302_triggered {
	meta: description = "Rule # 302 Suspicious String Eddie Kidiw triggered"
	strings: $suspicious_string = "Eddie Kidiw"
	condition: $suspicious_string
}
rule Rule_303_triggered {
	meta: description = "Rule # 303 Suspicious String EdiT3R: Dr.KAsBeR triggered"
	strings: $suspicious_string = "EdiT3R: Dr.KAsBeR"
	condition: $suspicious_string
}
rule Rule_304_triggered {
	meta: description = "Rule # 304 Suspicious String Edited By GuN-Jack triggered"
	strings: $suspicious_string = "Edited By GuN-Jack"
	condition: $suspicious_string
}
rule Rule_305_triggered {
	meta: description = "Rule # 305 Suspicious String El Moujahidin (the source has been moved and devloped) triggered"
	strings: $suspicious_string = "El Moujahidin (the source has been moved and devloped)"
	condition: $suspicious_string
}
rule Rule_306_triggered {
	meta: description = "Rule # 306 Suspicious String ElKiller.2013 triggered"
	strings: $suspicious_string = "ElKiller.2013"
	condition: $suspicious_string
}
rule Rule_307_triggered {
	meta: description = "Rule # 307 Suspicious String Encryption provided by iWEBTOOL.com triggered"
	strings: $suspicious_string = "Encryption provided by iWEBTOOL.com"
	condition: $suspicious_string
}
rule Rule_308_triggered {
	meta: description = "Rule # 308 Suspicious String ErrOr SquaD triggered"
	strings: $suspicious_string = "ErrOr SquaD"
	condition: $suspicious_string
}
rule Rule_309_triggered {
	meta: description = "Rule # 309 Suspicious String Eval+(GZINFLATE||GZUNCOMPRESS||B64||ROT13) triggered"
	strings: $suspicious_string = "Eval+(GZINFLATE||GZUNCOMPRESS||B64||ROT13)"
	condition: $suspicious_string
}
rule Rule_310_triggered {
	meta: description = "Rule # 310 Suspicious String Evils triggered"
	strings: $suspicious_string = "Evils"
	condition: $suspicious_string
}
rule Rule_311_triggered {
	meta: description = "Rule # 311 Suspicious String Ewa-Turk triggered"
	strings: $suspicious_string = "Ewa-Turk"
	condition: $suspicious_string
}
rule Rule_312_triggered {
	meta: description = "Rule # 312 Suspicious String Extreme Crew ! triggered"
	strings: $suspicious_string = "Extreme Crew !"
	condition: $suspicious_string
}
rule Rule_313_triggered {
	meta: description = "Rule # 313 Suspicious String F13xy triggered"
	strings: $suspicious_string = "F13xy"
	condition: $suspicious_string
}
rule Rule_314_triggered {
	meta: description = "Rule # 314 Suspicious String F1X404 triggered"
	strings: $suspicious_string = "F1X404"
	condition: $suspicious_string
}
rule Rule_315_triggered {
	meta: description = "Rule # 315 Suspicious String FB.com/J1jeI triggered"
	strings: $suspicious_string = "FB.com/J1jeI"
	condition: $suspicious_string
}
rule Rule_316_triggered {
	meta: description = "Rule # 316 Suspicious String FL3Z0X triggered"
	strings: $suspicious_string = "FL3Z0X"
	condition: $suspicious_string
}
rule Rule_317_triggered {
	meta: description = "Rule # 317 Suspicious String FORBIDD3N triggered"
	strings: $suspicious_string = "FORBIDD3N"
	condition: $suspicious_string
}
rule Rule_318_triggered {
	meta: description = "Rule # 318 Suspicious String FREE TOOLS 2015-2016 triggered"
	strings: $suspicious_string = "FREE TOOLS 2015-2016"
	condition: $suspicious_string
}
rule Rule_319_triggered {
	meta: description = "Rule # 319 Suspicious String FRK48    triggered"
	strings: $suspicious_string = "FRK48   "
	condition: $suspicious_string
}
rule Rule_320_triggered {
	meta: description = "Rule # 320 Suspicious String FRU_403 triggered"
	strings: $suspicious_string = "FRU_403"
	condition: $suspicious_string
}
rule Rule_321_triggered {
	meta: description = "Rule # 321 Suspicious String FULLZ LoGiN triggered"
	strings: $suspicious_string = "FULLZ LoGiN"
	condition: $suspicious_string
}
rule Rule_322_triggered {
	meta: description = "Rule # 322 Suspicious String FaisaL Ahmed aka rEd X triggered"
	strings: $suspicious_string = "FaisaL Ahmed aka rEd X"
	condition: $suspicious_string
}
rule Rule_323_triggered {
	meta: description = "Rule # 323 Suspicious String Faisal Symlink Bypass triggered"
	strings: $suspicious_string = "Faisal Symlink Bypass"
	condition: $suspicious_string
}
rule Rule_324_triggered {
	meta: description = "Rule # 324 Suspicious String Fake Root triggered"
	strings: $suspicious_string = "Fake Root"
	condition: $suspicious_string
}
rule Rule_325_triggered {
	meta: description = "Rule # 325 Suspicious String Falc0n Eye triggered"
	strings: $suspicious_string = "Falc0n Eye"
	condition: $suspicious_string
}
rule Rule_326_triggered {
	meta: description = "Rule # 326 Suspicious String Family Attack Cyber triggered"
	strings: $suspicious_string = "Family Attack Cyber"
	condition: $suspicious_string
}
rule Rule_327_triggered {
	meta: description = "Rule # 327 Suspicious String Fazlast triggered"
	strings: $suspicious_string = "Fazlast"
	condition: $suspicious_string
}
rule Rule_328_triggered {
	meta: description = "Rule # 328 Suspicious String FeeLCoMz triggered"
	strings: $suspicious_string = "FeeLCoMz"
	condition: $suspicious_string
}
rule Rule_329_triggered {
	meta: description = "Rule # 329 Suspicious String Ffe ^_^ triggered"
	strings: $suspicious_string = "Ffe ^_^"
	condition: $suspicious_string
}
rule Rule_330_triggered {
	meta: description = "Rule # 330 Suspicious String FilesMan triggered"
	strings: $suspicious_string = "FilesMan"
	condition: $suspicious_string
}
rule Rule_331_triggered {
	meta: description = "Rule # 331 Suspicious String FilesTools triggered"
	strings: $suspicious_string = "FilesTools"
	condition: $suspicious_string
}
rule Rule_332_triggered {
	meta: description = "Rule # 332 Suspicious String Finder Script by c0ax triggered"
	strings: $suspicious_string = "Finder Script by c0ax"
	condition: $suspicious_string
}
rule Rule_333_triggered {
	meta: description = "Rule # 333 Suspicious String Fir3 H@wk triggered"
	strings: $suspicious_string = "Fir3 H@wk"
	condition: $suspicious_string
}
rule Rule_334_triggered {
	meta: description = "Rule # 334 Suspicious String Fl0ki triggered"
	strings: $suspicious_string = "Fl0ki"
	condition: $suspicious_string
}
rule Rule_335_triggered {
	meta: description = "Rule # 335 Suspicious String Frbdn403 triggered"
	strings: $suspicious_string = "Frbdn403"
	condition: $suspicious_string
}
rule Rule_336_triggered {
	meta: description = "Rule # 336 Suspicious String Free Palestine triggered"
	strings: $suspicious_string = "Free Palestine"
	condition: $suspicious_string
}
rule Rule_337_triggered {
	meta: description = "Rule # 337 Suspicious String Freedom For Tunisia triggered"
	strings: $suspicious_string = "Freedom For Tunisia"
	condition: $suspicious_string
}
rule Rule_338_triggered {
	meta: description = "Rule # 338 Suspicious String French Hacker triggered"
	strings: $suspicious_string = "French Hacker"
	condition: $suspicious_string
}
rule Rule_339_triggered {
	meta: description = "Rule # 339 Suspicious String Furubi triggered"
	strings: $suspicious_string = "Furubi"
	condition: $suspicious_string
}
rule Rule_340_triggered {
	meta: description = "Rule # 340 Suspicious String Fx29Sh triggered"
	strings: $suspicious_string = "Fx29Sh"
	condition: $suspicious_string
}
rule Rule_341_triggered {
	meta: description = "Rule # 341 Suspicious String G-Google ACCU triggered"
	strings: $suspicious_string = "G-Google ACCU"
	condition: $suspicious_string
}
rule Rule_342_triggered {
	meta: description = "Rule # 342 Suspicious String GIF8?a.*<?php triggered"
	strings: $suspicious_string = "GIF8?a.*<?php"
	condition: $suspicious_string
}
rule Rule_343_triggered {
	meta: description = "Rule # 343 Suspicious String GREETZ TO ALL KCS MEMBERS triggered"
	strings: $suspicious_string = "GREETZ TO ALL KCS MEMBERS"
	condition: $suspicious_string
}
rule Rule_344_triggered {
	meta: description = "Rule # 344 Suspicious String GaLers xh3LL Backd00r triggered"
	strings: $suspicious_string = "GaLers xh3LL Backd00r"
	condition: $suspicious_string
}
rule Rule_345_triggered {
	meta: description = "Rule # 345 Suspicious String Gagal triggered"
	strings: $suspicious_string = "Gagal"
	condition: $suspicious_string
}
rule Rule_346_triggered {
	meta: description = "Rule # 346 Suspicious String GalehDotId triggered"
	strings: $suspicious_string = "GalehDotId"
	condition: $suspicious_string
}
rule Rule_347_triggered {
	meta: description = "Rule # 347 Suspicious String Gantengers triggered"
	strings: $suspicious_string = "Gantengers"
	condition: $suspicious_string
}
rule Rule_348_triggered {
	meta: description = "Rule # 348 Suspicious String Garuda Security Hacker triggered"
	strings: $suspicious_string = "Garuda Security Hacker"
	condition: $suspicious_string
}
rule Rule_349_triggered {
	meta: description = "Rule # 349 Suspicious String Gend3ruw0    triggered"
	strings: $suspicious_string = "Gend3ruw0   "
	condition: $suspicious_string
}
rule Rule_350_triggered {
	meta: description = "Rule # 350 Suspicious String Girl_Carding triggered"
	strings: $suspicious_string = "Girl_Carding"
	condition: $suspicious_string
}
rule Rule_351_triggered {
	meta: description = "Rule # 351 Suspicious String Gmail recovery details triggered"
	strings: $suspicious_string = "Gmail recovery details"
	condition: $suspicious_string
}
rule Rule_352_triggered {
	meta: description = "Rule # 352 Suspicious String Godzila triggered"
	strings: $suspicious_string = "Godzila"
	condition: $suspicious_string
}
rule Rule_353_triggered {
	meta: description = "Rule # 353 Suspicious String Gok-Boru     triggered"
	strings: $suspicious_string = "Gok-Boru    "
	condition: $suspicious_string
}
rule Rule_354_triggered {
	meta: description = "Rule # 354 Suspicious String Golden boy INDIA triggered"
	strings: $suspicious_string = "Golden boy INDIA"
	condition: $suspicious_string
}
rule Rule_355_triggered {
	meta: description = "Rule # 355 Suspicious String Gr0ss-mailer triggered"
	strings: $suspicious_string = "Gr0ss-mailer"
	condition: $suspicious_string
}
rule Rule_356_triggered {
	meta: description = "Rule # 356 Suspicious String GreenL1ne triggered"
	strings: $suspicious_string = "GreenL1ne"
	condition: $suspicious_string
}
rule Rule_357_triggered {
	meta: description = "Rule # 357 Suspicious String GreenLine Hacker triggered"
	strings: $suspicious_string = "GreenLine Hacker"
	condition: $suspicious_string
}
rule Rule_358_triggered {
	meta: description = "Rule # 358 Suspicious String Greetz triggered"
	strings: $suspicious_string = "Greetz"
	condition: $suspicious_string
}
rule Rule_359_triggered {
	meta: description = "Rule # 359 Suspicious String Greetz : Indonesian People triggered"
	strings: $suspicious_string = "Greetz : Indonesian People"
	condition: $suspicious_string
}
rule Rule_360_triggered {
	meta: description = "Rule # 360 Suspicious String GrenXPaRTa  triggered"
	strings: $suspicious_string = "GrenXPaRTa "
	condition: $suspicious_string
}
rule Rule_361_triggered {
	meta: description = "Rule # 361 Suspicious String Group x3 triggered"
	strings: $suspicious_string = "Group x3"
	condition: $suspicious_string
}
rule Rule_362_triggered {
	meta: description = "Rule # 362 Suspicious String Guru ji zero triggered"
	strings: $suspicious_string = "Guru ji zero"
	condition: $suspicious_string
}
rule Rule_363_triggered {
	meta: description = "Rule # 363 Suspicious String H1R4ICH1 triggered"
	strings: $suspicious_string = "H1R4ICH1"
	condition: $suspicious_string
}
rule Rule_364_triggered {
	meta: description = "Rule # 364 Suspicious String H311 c0d3 triggered"
	strings: $suspicious_string = "H311 c0d3"
	condition: $suspicious_string
}
rule Rule_365_triggered {
	meta: description = "Rule # 365 Suspicious String H3r03ZiM0uZ triggered"
	strings: $suspicious_string = "H3r03ZiM0uZ"
	condition: $suspicious_string
}
rule Rule_366_triggered {
	meta: description = "Rule # 366 Suspicious String H3r3 !s 411 D0m4!ns &amp; Us3rs triggered"
	strings: $suspicious_string = "H3r3 !s 411 D0m4!ns &amp; Us3rs"
	condition: $suspicious_string
}
rule Rule_367_triggered {
	meta: description = "Rule # 367 Suspicious String H3ri.ID  triggered"
	strings: $suspicious_string = "H3ri.ID "
	condition: $suspicious_string
}
rule Rule_368_triggered {
	meta: description = "Rule # 368 Suspicious String H4CK3R triggered"
	strings: $suspicious_string = "H4CK3R"
	condition: $suspicious_string
}
rule Rule_369_triggered {
	meta: description = "Rule # 369 Suspicious String H@SEB triggered"
	strings: $suspicious_string = "H@SEB"
	condition: $suspicious_string
}
rule Rule_370_triggered {
	meta: description = "Rule # 370 Suspicious String HA$KEL triggered"
	strings: $suspicious_string = "HA$KEL"
	condition: $suspicious_string
}
rule Rule_371_triggered {
	meta: description = "Rule # 371 Suspicious String HACKED triggered"
	strings: $suspicious_string = "HACKED"
	condition: $suspicious_string
}
rule Rule_372_triggered {
	meta: description = "Rule # 372 Suspicious String HACKED BY ANONYNIX triggered"
	strings: $suspicious_string = "HACKED BY ANONYNIX"
	condition: $suspicious_string
}
rule Rule_373_triggered {
	meta: description = "Rule # 373 Suspicious String HACKED BY MR.WEXENT triggered"
	strings: $suspicious_string = "HACKED BY MR.WEXENT"
	condition: $suspicious_string
}
rule Rule_374_triggered {
	meta: description = "Rule # 374 Suspicious String HACKED BY SYSTEM G33K triggered"
	strings: $suspicious_string = "HACKED BY SYSTEM G33K"
	condition: $suspicious_string
}
rule Rule_375_triggered {
	meta: description = "Rule # 375 Suspicious String HACKER Yar triggered"
	strings: $suspicious_string = "HACKER Yar"
	condition: $suspicious_string
}
rule Rule_376_triggered {
	meta: description = "Rule # 376 Suspicious String HAXOR N1LOY triggered"
	strings: $suspicious_string = "HAXOR N1LOY"
	condition: $suspicious_string
}
rule Rule_377_triggered {
	meta: description = "Rule # 377 Suspicious String HEXolzWOLF triggered"
	strings: $suspicious_string = "HEXolzWOLF"
	condition: $suspicious_string
}
rule Rule_378_triggered {
	meta: description = "Rule # 378 Suspicious String HOSSAM triggered"
	strings: $suspicious_string = "HOSSAM"
	condition: $suspicious_string
}
rule Rule_379_triggered {
	meta: description = "Rule # 379 Suspicious String H_P_J triggered"
	strings: $suspicious_string = "H_P_J"
	condition: $suspicious_string
}
rule Rule_380_triggered {
	meta: description = "Rule # 380 Suspicious String HaCkEd By Mo3Gza HaCkEr triggered"
	strings: $suspicious_string = "HaCkEd By Mo3Gza HaCkEr"
	condition: $suspicious_string
}
rule Rule_381_triggered {
	meta: description = "Rule # 381 Suspicious String HaCkEd By RxR HaCkEr triggered"
	strings: $suspicious_string = "HaCkEd By RxR HaCkEr"
	condition: $suspicious_string
}
rule Rule_382_triggered {
	meta: description = "Rule # 382 Suspicious String HacKeD By {{LaMiN3 DK}}, Algerian Defacer triggered"
	strings: $suspicious_string = "HacKeD By {{LaMiN3 DK}}, Algerian Defacer"
	condition: $suspicious_string
}
rule Rule_383_triggered {
	meta: description = "Rule # 383 Suspicious String HackTeam triggered"
	strings: $suspicious_string = "HackTeam"
	condition: $suspicious_string
}
rule Rule_384_triggered {
	meta: description = "Rule # 384 Suspicious String HackeD By Hussam triggered"
	strings: $suspicious_string = "HackeD By Hussam"
	condition: $suspicious_string
}
rule Rule_385_triggered {
	meta: description = "Rule # 385 Suspicious String HackeD By Skidie KhaN triggered"
	strings: $suspicious_string = "HackeD By Skidie KhaN"
	condition: $suspicious_string
}
rule Rule_386_triggered {
	meta: description = "Rule # 386 Suspicious String Hackeado triggered"
	strings: $suspicious_string = "Hackeado"
	condition: $suspicious_string
}
rule Rule_387_triggered {
	meta: description = "Rule # 387 Suspicious String Hacked By BALA SNIPER triggered"
	strings: $suspicious_string = "Hacked By BALA SNIPER"
	condition: $suspicious_string
}
rule Rule_388_triggered {
	meta: description = "Rule # 388 Suspicious String Hacked By BDJ-007 triggered"
	strings: $suspicious_string = "Hacked By BDJ-007"
	condition: $suspicious_string
}
rule Rule_389_triggered {
	meta: description = "Rule # 389 Suspicious String Hacked By BadC0de triggered"
	strings: $suspicious_string = "Hacked By BadC0de"
	condition: $suspicious_string
}
rule Rule_390_triggered {
	meta: description = "Rule # 390 Suspicious String Hacked By Black Sniper triggered"
	strings: $suspicious_string = "Hacked By Black Sniper"
	condition: $suspicious_string
}
rule Rule_391_triggered {
	meta: description = "Rule # 391 Suspicious String Hacked By GeNErAL triggered"
	strings: $suspicious_string = "Hacked By GeNErAL"
	condition: $suspicious_string
}
rule Rule_392_triggered {
	meta: description = "Rule # 392 Suspicious String Hacked By HentaiC0de triggered"
	strings: $suspicious_string = "Hacked By HentaiC0de"
	condition: $suspicious_string
}
rule Rule_393_triggered {
	meta: description = "Rule # 393 Suspicious String Hacked By HolaKo triggered"
	strings: $suspicious_string = "Hacked By HolaKo"
	condition: $suspicious_string
}
rule Rule_394_triggered {
	meta: description = "Rule # 394 Suspicious String Hacked By IDBTE4M triggered"
	strings: $suspicious_string = "Hacked By IDBTE4M"
	condition: $suspicious_string
}
rule Rule_395_triggered {
	meta: description = "Rule # 395 Suspicious String Hacked By Imam triggered"
	strings: $suspicious_string = "Hacked By Imam"
	condition: $suspicious_string
}
rule Rule_396_triggered {
	meta: description = "Rule # 396 Suspicious String Hacked By MuhmadEmad triggered"
	strings: $suspicious_string = "Hacked By MuhmadEmad"
	condition: $suspicious_string
}
rule Rule_397_triggered {
	meta: description = "Rule # 397 Suspicious String Hacked By Peyman Siyahi triggered"
	strings: $suspicious_string = "Hacked By Peyman Siyahi"
	condition: $suspicious_string
}
rule Rule_398_triggered {
	meta: description = "Rule # 398 Suspicious String Hacked By SA3D HaCk3D triggered"
	strings: $suspicious_string = "Hacked By SA3D HaCk3D"
	condition: $suspicious_string
}
rule Rule_399_triggered {
	meta: description = "Rule # 399 Suspicious String Hacked By Sneaky triggered"
	strings: $suspicious_string = "Hacked By Sneaky"
	condition: $suspicious_string
}
rule Rule_400_triggered {
	meta: description = "Rule # 400 Suspicious String Hacked By TheWayEnd triggered"
	strings: $suspicious_string = "Hacked By TheWayEnd"
	condition: $suspicious_string
}
rule Rule_401_triggered {
	meta: description = "Rule # 401 Suspicious String Hacked By Ulow triggered"
	strings: $suspicious_string = "Hacked By Ulow"
	condition: $suspicious_string
}
rule Rule_402_triggered {
	meta: description = "Rule # 402 Suspicious String Hacked By XwoLfTn triggered"
	strings: $suspicious_string = "Hacked By XwoLfTn"
	condition: $suspicious_string
}
rule Rule_403_triggered {
	meta: description = "Rule # 403 Suspicious String Hacked By chinafans triggered"
	strings: $suspicious_string = "Hacked By chinafans"
	condition: $suspicious_string
}
rule Rule_404_triggered {
	meta: description = "Rule # 404 Suspicious String Hacked By.D34DCYB3R triggered"
	strings: $suspicious_string = "Hacked By.D34DCYB3R"
	condition: $suspicious_string
}
rule Rule_405_triggered {
	meta: description = "Rule # 405 Suspicious String Hacked By: 4Ri3 60ndr0n9 triggered"
	strings: $suspicious_string = "Hacked By: 4Ri3 60ndr0n9"
	condition: $suspicious_string
}
rule Rule_406_triggered {
	meta: description = "Rule # 406 Suspicious String Hacked ByP!R!7 triggered"
	strings: $suspicious_string = "Hacked ByP!R!7"
	condition: $suspicious_string
}
rule Rule_407_triggered {
	meta: description = "Rule # 407 Suspicious String Hacked by /Mr.KodoC triggered"
	strings: $suspicious_string = "Hacked by /Mr.KodoC"
	condition: $suspicious_string
}
rule Rule_408_triggered {
	meta: description = "Rule # 408 Suspicious String Hacked by BKSMILE triggered"
	strings: $suspicious_string = "Hacked by BKSMILE"
	condition: $suspicious_string
}
rule Rule_409_triggered {
	meta: description = "Rule # 409 Suspicious String Hacked by Dr.SiLnT HilL triggered"
	strings: $suspicious_string = "Hacked by Dr.SiLnT HilL"
	condition: $suspicious_string
}
rule Rule_410_triggered {
	meta: description = "Rule # 410 Suspicious String Hacked by Hunter Bajwa triggered"
	strings: $suspicious_string = "Hacked by Hunter Bajwa"
	condition: $suspicious_string
}
rule Rule_411_triggered {
	meta: description = "Rule # 411 Suspicious String Hacked by MRH.404 triggered"
	strings: $suspicious_string = "Hacked by MRH.404"
	condition: $suspicious_string
}
rule Rule_412_triggered {
	meta: description = "Rule # 412 Suspicious String Hacked by MeRvox triggered"
	strings: $suspicious_string = "Hacked by MeRvox"
	condition: $suspicious_string
}
rule Rule_413_triggered {
	meta: description = "Rule # 413 Suspicious String Hacked by R@qeeB triggered"
	strings: $suspicious_string = "Hacked by R@qeeB"
	condition: $suspicious_string
}
rule Rule_414_triggered {
	meta: description = "Rule # 414 Suspicious String Hacked by RxR HaCkEr triggered"
	strings: $suspicious_string = "Hacked by RxR HaCkEr"
	condition: $suspicious_string
}
rule Rule_415_triggered {
	meta: description = "Rule # 415 Suspicious String Hacked by Shade triggered"
	strings: $suspicious_string = "Hacked by Shade"
	condition: $suspicious_string
}
rule Rule_416_triggered {
	meta: description = "Rule # 416 Suspicious String Hacked by Sxtz triggered"
	strings: $suspicious_string = "Hacked by Sxtz"
	condition: $suspicious_string
}
rule Rule_417_triggered {
	meta: description = "Rule # 417 Suspicious String Hacked by ZeDaN-Mrx triggered"
	strings: $suspicious_string = "Hacked by ZeDaN-Mrx"
	condition: $suspicious_string
}
rule Rule_418_triggered {
	meta: description = "Rule # 418 Suspicious String Hacked in 2015 By [ Mr.PROTOCOL] triggered"
	strings: $suspicious_string = "Hacked in 2015 By [ Mr.PROTOCOL]"
	condition: $suspicious_string
}
rule Rule_419_triggered {
	meta: description = "Rule # 419 Suspicious String Hacker By Conversely triggered"
	strings: $suspicious_string = "Hacker By Conversely"
	condition: $suspicious_string
}
rule Rule_420_triggered {
	meta: description = "Rule # 420 Suspicious String Hacker Patah Hati triggered"
	strings: $suspicious_string = "Hacker Patah Hati"
	condition: $suspicious_string
}
rule Rule_421_triggered {
	meta: description = "Rule # 421 Suspicious String Hacker Sakit Hati  triggered"
	strings: $suspicious_string = "Hacker Sakit Hati "
	condition: $suspicious_string
}
rule Rule_422_triggered {
	meta: description = "Rule # 422 Suspicious String Hackerlady512@gmail.com triggered"
	strings: $suspicious_string = "Hackerlady512@gmail.com"
	condition: $suspicious_string
}
rule Rule_423_triggered {
	meta: description = "Rule # 423 Suspicious String Hacktime triggered"
	strings: $suspicious_string = "Hacktime"
	condition: $suspicious_string
}
rule Rule_424_triggered {
	meta: description = "Rule # 424 Suspicious String Haml3t triggered"
	strings: $suspicious_string = "Haml3t"
	condition: $suspicious_string
}
rule Rule_425_triggered {
	meta: description = "Rule # 425 Suspicious String Happy Ending YunusOchills triggered"
	strings: $suspicious_string = "Happy Ending YunusOchills"
	condition: $suspicious_string
}
rule Rule_426_triggered {
	meta: description = "Rule # 426 Suspicious String Haxor triggered"
	strings: $suspicious_string = "Haxor"
	condition: $suspicious_string
}
rule Rule_427_triggered {
	meta: description = "Rule # 427 Suspicious String Heartz009 triggered"
	strings: $suspicious_string = "Heartz009"
	condition: $suspicious_string
}
rule Rule_428_triggered {
	meta: description = "Rule # 428 Suspicious String HentaiC0de triggered"
	strings: $suspicious_string = "HentaiC0de"
	condition: $suspicious_string
}
rule Rule_429_triggered {
	meta: description = "Rule # 429 Suspicious String HentaiC0de 6enjot in your security triggered"
	strings: $suspicious_string = "HentaiC0de 6enjot in your security"
	condition: $suspicious_string
}
rule Rule_430_triggered {
	meta: description = "Rule # 430 Suspicious String Hexavhobia   triggered"
	strings: $suspicious_string = "Hexavhobia  "
	condition: $suspicious_string
}
rule Rule_431_triggered {
	meta: description = "Rule # 431 Suspicious String HiDder OwnZz You triggered"
	strings: $suspicious_string = "HiDder OwnZz You"
	condition: $suspicious_string
}
rule Rule_432_triggered {
	meta: description = "Rule # 432 Suspicious String HiM! Wire triggered"
	strings: $suspicious_string = "HiM! Wire"
	condition: $suspicious_string
}
rule Rule_433_triggered {
	meta: description = "Rule # 433 Suspicious String HiTLER ALsharef triggered"
	strings: $suspicious_string = "HiTLER ALsharef"
	condition: $suspicious_string
}
rule Rule_434_triggered {
	meta: description = "Rule # 434 Suspicious String Hit Me To Download Tar File triggered"
	strings: $suspicious_string = "Hit Me To Download Tar File"
	condition: $suspicious_string
}
rule Rule_435_triggered {
	meta: description = "Rule # 435 Suspicious String Hmei7 triggered"
	strings: $suspicious_string = "Hmei7"
	condition: $suspicious_string
}
rule Rule_436_triggered {
	meta: description = "Rule # 436 Suspicious String Hodoor triggered"
	strings: $suspicious_string = "Hodoor"
	condition: $suspicious_string
}
rule Rule_437_triggered {
	meta: description = "Rule # 437 Suspicious String HtjhY triggered"
	strings: $suspicious_string = "HtjhY"
	condition: $suspicious_string
}
rule Rule_438_triggered {
	meta: description = "Rule # 438 Suspicious String Hun73r CL4W triggered"
	strings: $suspicious_string = "Hun73r CL4W"
	condition: $suspicious_string
}
rule Rule_439_triggered {
	meta: description = "Rule # 439 Suspicious String HunTerZ Family triggered"
	strings: $suspicious_string = "HunTerZ Family"
	condition: $suspicious_string
}
rule Rule_440_triggered {
	meta: description = "Rule # 440 Suspicious String Hunter Bajwa triggered"
	strings: $suspicious_string = "Hunter Bajwa"
	condition: $suspicious_string
}
rule Rule_441_triggered {
	meta: description = "Rule # 441 Suspicious String Hussamvirus triggered"
	strings: $suspicious_string = "Hussamvirus"
	condition: $suspicious_string
}
rule Rule_442_triggered {
	meta: description = "Rule # 442 Suspicious String HusseiN98D triggered"
	strings: $suspicious_string = "HusseiN98D"
	condition: $suspicious_string
}
rule Rule_443_triggered {
	meta: description = "Rule # 443 Suspicious String Hussin-v triggered"
	strings: $suspicious_string = "Hussin-v"
	condition: $suspicious_string
}
rule Rule_444_triggered {
	meta: description = "Rule # 444 Suspicious String I back to hack triggered"
	strings: $suspicious_string = "I back to hack"
	condition: $suspicious_string
}
rule Rule_445_triggered {
	meta: description = "Rule # 445 Suspicious String I'm so sorry, hacked you are Website triggered"
	strings: $suspicious_string = "I'm so sorry, hacked you are Website"
	condition: $suspicious_string
}
rule Rule_446_triggered {
	meta: description = "Rule # 446 Suspicious String IDBTE4M triggered"
	strings: $suspicious_string = "IDBTE4M"
	condition: $suspicious_string
}
rule Rule_447_triggered {
	meta: description = "Rule # 447 Suspicious String IN73CT0R triggered"
	strings: $suspicious_string = "IN73CT0R"
	condition: $suspicious_string
}
rule Rule_448_triggered {
	meta: description = "Rule # 448 Suspicious String INDONESIAN GRAY HAT HACKER triggered"
	strings: $suspicious_string = "INDONESIAN GRAY HAT HACKER"
	condition: $suspicious_string
}
rule Rule_449_triggered {
	meta: description = "Rule # 449 Suspicious String INX_r0ot triggered"
	strings: $suspicious_string = "INX_r0ot"
	condition: $suspicious_string
}
rule Rule_450_triggered {
	meta: description = "Rule # 450 Suspicious String ISI PESAN triggered"
	strings: $suspicious_string = "ISI PESAN"
	condition: $suspicious_string
}
rule Rule_451_triggered {
	meta: description = "Rule # 451 Suspicious String Iheb Abdelly triggered"
	strings: $suspicious_string = "Iheb Abdelly"
	condition: $suspicious_string
}
rule Rule_452_triggered {
	meta: description = "Rule # 452 Suspicious String Inbox Mass Mailer triggered"
	strings: $suspicious_string = "Inbox Mass Mailer"
	condition: $suspicious_string
}
rule Rule_453_triggered {
	meta: description = "Rule # 453 Suspicious String IndoXploit triggered"
	strings: $suspicious_string = "IndoXploit"
	condition: $suspicious_string
}
rule Rule_454_triggered {
	meta: description = "Rule # 454 Suspicious String IndoXploit Coders Team triggered"
	strings: $suspicious_string = "IndoXploit Coders Team"
	condition: $suspicious_string
}
rule Rule_455_triggered {
	meta: description = "Rule # 455 Suspicious String Indonesia Coders Galau triggered"
	strings: $suspicious_string = "Indonesia Coders Galau"
	condition: $suspicious_string
}
rule Rule_456_triggered {
	meta: description = "Rule # 456 Suspicious String Indonesia Defacer triggered"
	strings: $suspicious_string = "Indonesia Defacer"
	condition: $suspicious_string
}
rule Rule_457_triggered {
	meta: description = "Rule # 457 Suspicious String Indonesia Defacer Tersakiti Team triggered"
	strings: $suspicious_string = "Indonesia Defacer Tersakiti Team"
	condition: $suspicious_string
}
rule Rule_458_triggered {
	meta: description = "Rule # 458 Suspicious String Indonesian Code Party triggered"
	strings: $suspicious_string = "Indonesian Code Party"
	condition: $suspicious_string
}
rule Rule_459_triggered {
	meta: description = "Rule # 459 Suspicious String Indonesian Defacer Tersakiti Team triggered"
	strings: $suspicious_string = "Indonesian Defacer Tersakiti Team"
	condition: $suspicious_string
}
rule Rule_460_triggered {
	meta: description = "Rule # 460 Suspicious String Indonesian Freedom Security triggered"
	strings: $suspicious_string = "Indonesian Freedom Security"
	condition: $suspicious_string
}
rule Rule_461_triggered {
	meta: description = "Rule # 461 Suspicious String Indramayu triggered"
	strings: $suspicious_string = "Indramayu"
	condition: $suspicious_string
}
rule Rule_462_triggered {
	meta: description = "Rule # 462 Suspicious String InjecT0r triggered"
	strings: $suspicious_string = "InjecT0r"
	condition: $suspicious_string
}
rule Rule_463_triggered {
	meta: description = "Rule # 463 Suspicious String InjectorDaher triggered"
	strings: $suspicious_string = "InjectorDaher"
	condition: $suspicious_string
}
rule Rule_464_triggered {
	meta: description = "Rule # 464 Suspicious String Iranian Hackers triggered"
	strings: $suspicious_string = "Iranian Hackers"
	condition: $suspicious_string
}
rule Rule_465_triggered {
	meta: description = "Rule # 465 Suspicious String Irfninja indishell triggered"
	strings: $suspicious_string = "Irfninja indishell"
	condition: $suspicious_string
}
rule Rule_466_triggered {
	meta: description = "Rule # 466 Suspicious String Islamic Cyber triggered"
	strings: $suspicious_string = "Islamic Cyber"
	condition: $suspicious_string
}
rule Rule_467_triggered {
	meta: description = "Rule # 467 Suspicious String Its m3 :p triggered"
	strings: $suspicious_string = "Its m3 :p"
	condition: $suspicious_string
}
rule Rule_468_triggered {
	meta: description = "Rule # 468 Suspicious String Izza009 triggered"
	strings: $suspicious_string = "Izza009"
	condition: $suspicious_string
}
rule Rule_469_triggered {
	meta: description = "Rule # 469 Suspicious String J1ZmZlcmluZw= triggered"
	strings: $suspicious_string = "J1ZmZlcmluZw="
	condition: $suspicious_string
}
rule Rule_470_triggered {
	meta: description = "Rule # 470 Suspicious String JAAALiiiK triggered"
	strings: $suspicious_string = "JAAALiiiK"
	condition: $suspicious_string
}
rule Rule_471_triggered {
	meta: description = "Rule # 471 Suspicious String JMBUD NGNTD CMP WEB triggered"
	strings: $suspicious_string = "JMBUD NGNTD CMP WEB"
	condition: $suspicious_string
}
rule Rule_472_triggered {
	meta: description = "Rule # 472 Suspicious String JPMorgan Chase triggered"
	strings: $suspicious_string = "JPMorgan Chase"
	condition: $suspicious_string
}
rule Rule_473_triggered {
	meta: description = "Rule # 473 Suspicious String JankillError404 triggered"
	strings: $suspicious_string = "JankillError404"
	condition: $suspicious_string
}
rule Rule_474_triggered {
	meta: description = "Rule # 474 Suspicious String Jayalah Indonesiaku triggered"
	strings: $suspicious_string = "Jayalah Indonesiaku"
	condition: $suspicious_string
}
rule Rule_475_triggered {
	meta: description = "Rule # 475 Suspicious String JembriX triggered"
	strings: $suspicious_string = "JembriX"
	condition: $suspicious_string
}
rule Rule_476_triggered {
	meta: description = "Rule # 476 Suspicious String Jiilan404 triggered"
	strings: $suspicious_string = "Jiilan404"
	condition: $suspicious_string
}
rule Rule_477_triggered {
	meta: description = "Rule # 477 Suspicious String Jijle3 triggered"
	strings: $suspicious_string = "Jijle3"
	condition: $suspicious_string
}
rule Rule_478_triggered {
	meta: description = "Rule # 478 Suspicious String Jimycoco triggered"
	strings: $suspicious_string = "Jimycoco"
	condition: $suspicious_string
}
rule Rule_479_triggered {
	meta: description = "Rule # 479 Suspicious String Jingklong triggered"
	strings: $suspicious_string = "Jingklong"
	condition: $suspicious_string
}
rule Rule_480_triggered {
	meta: description = "Rule # 480 Suspicious String Jingklong    triggered"
	strings: $suspicious_string = "Jingklong   "
	condition: $suspicious_string
}
rule Rule_481_triggered {
	meta: description = "Rule # 481 Suspicious String Jiwa Ngidol triggered"
	strings: $suspicious_string = "Jiwa Ngidol"
	condition: $suspicious_string
}
rule Rule_482_triggered {
	meta: description = "Rule # 482 Suspicious String Jokr Haxor triggered"
	strings: $suspicious_string = "Jokr Haxor"
	condition: $suspicious_string
}
rule Rule_483_triggered {
	meta: description = "Rule # 483 Suspicious String Joky Priv8 triggered"
	strings: $suspicious_string = "Joky Priv8"
	condition: $suspicious_string
}
rule Rule_484_triggered {
	meta: description = "Rule # 484 Suspicious String Jombang Cyber Team triggered"
	strings: $suspicious_string = "Jombang Cyber Team"
	condition: $suspicious_string
}
rule Rule_485_triggered {
	meta: description = "Rule # 485 Suspicious String Joomla Auto Edit User triggered"
	strings: $suspicious_string = "Joomla Auto Edit User"
	condition: $suspicious_string
}
rule Rule_486_triggered {
	meta: description = "Rule # 486 Suspicious String Jungle_Sec triggered"
	strings: $suspicious_string = "Jungle_Sec"
	condition: $suspicious_string
}
rule Rule_487_triggered {
	meta: description = "Rule # 487 Suspicious String Just Wolf triggered"
	strings: $suspicious_string = "Just Wolf"
	condition: $suspicious_string
}
rule Rule_488_triggered {
	meta: description = "Rule # 488 Suspicious String K2LL33D SHELL triggered"
	strings: $suspicious_string = "K2LL33D SHELL"
	condition: $suspicious_string
}
rule Rule_489_triggered {
	meta: description = "Rule # 489 Suspicious String K4MVR3T717 triggered"
	strings: $suspicious_string = "K4MVR3T717"
	condition: $suspicious_string
}
rule Rule_490_triggered {
	meta: description = "Rule # 490 Suspicious String KATENABAD triggered"
	strings: $suspicious_string = "KATENABAD"
	condition: $suspicious_string
}
rule Rule_491_triggered {
	meta: description = "Rule # 491 Suspicious String KAYBLAAK2015@GMAIL.COM triggered"
	strings: $suspicious_string = "KAYBLAAK2015@GMAIL.COM"
	condition: $suspicious_string
}
rule Rule_492_triggered {
	meta: description = "Rule # 492 Suspicious String KERALA CYBER SOLDIERS (KCS) triggered"
	strings: $suspicious_string = "KERALA CYBER SOLDIERS (KCS)"
	condition: $suspicious_string
}
rule Rule_493_triggered {
	meta: description = "Rule # 493 Suspicious String Kali Anda Telah Ngecrot  Disini triggered"
	strings: $suspicious_string = "Kali Anda Telah Ngecrot  Disini"
	condition: $suspicious_string
}
rule Rule_494_triggered {
	meta: description = "Rule # 494 Suspicious String Kaneki404  triggered"
	strings: $suspicious_string = "Kaneki404 "
	condition: $suspicious_string
}
rule Rule_495_triggered {
	meta: description = "Rule # 495 Suspicious String Karar alShaMi triggered"
	strings: $suspicious_string = "Karar alShaMi"
	condition: $suspicious_string
}
rule Rule_496_triggered {
	meta: description = "Rule # 496 Suspicious String Kazuya404 triggered"
	strings: $suspicious_string = "Kazuya404"
	condition: $suspicious_string
}
rule Rule_497_triggered {
	meta: description = "Rule # 497 Suspicious String Kesalahan Server triggered"
	strings: $suspicious_string = "Kesalahan Server"
	condition: $suspicious_string
}
rule Rule_498_triggered {
	meta: description = "Rule # 498 Suspicious String Ketan Singh triggered"
	strings: $suspicious_string = "Ketan Singh"
	condition: $suspicious_string
}
rule Rule_499_triggered {
	meta: description = "Rule # 499 Suspicious String Khaled Mardam-Bey triggered"
	strings: $suspicious_string = "Khaled Mardam-Bey"
	condition: $suspicious_string
}
rule Rule_500_triggered {
	meta: description = "Rule # 500 Suspicious String Kish0r3 P4sh4 triggered"
	strings: $suspicious_string = "Kish0r3 P4sh4"
	condition: $suspicious_string
}
rule Rule_501_triggered {
	meta: description = "Rule # 501 Suspicious String KitcPyg/PSRocGhwJ0FVc210dXJucmVzZXR1O3N3JGxpaW5lcnJvcHViO2lmbXRwLT5 triggered"
	strings: $suspicious_string = "KitcPyg/PSRocGhwJ0FVc210dXJucmVzZXR1O3N3JGxpaW5lcnJvcHViO2lmbXRwLT5"
	condition: $suspicious_string
}
rule Rule_502_triggered {
	meta: description = "Rule # 502 Suspicious String Klik Gan triggered"
	strings: $suspicious_string = "Klik Gan"
	condition: $suspicious_string
}
rule Rule_503_triggered {
	meta: description = "Rule # 503 Suspicious String Kontoleglayut triggered"
	strings: $suspicious_string = "Kontoleglayut"
	condition: $suspicious_string
}
rule Rule_504_triggered {
	meta: description = "Rule # 504 Suspicious String Korang Dah Berjaya triggered"
	strings: $suspicious_string = "Korang Dah Berjaya"
	condition: $suspicious_string
}
rule Rule_505_triggered {
	meta: description = "Rule # 505 Suspicious String Korang Gagal triggered"
	strings: $suspicious_string = "Korang Gagal"
	condition: $suspicious_string
}
rule Rule_506_triggered {
	meta: description = "Rule # 506 Suspicious String KrimOu CPanel Cracker Script & Root Server triggered"
	strings: $suspicious_string = "KrimOu CPanel Cracker Script & Root Server"
	condition: $suspicious_string
}
rule Rule_507_triggered {
	meta: description = "Rule # 507 Suspicious String KrimOu CPanelCracker Script triggered"
	strings: $suspicious_string = "KrimOu CPanelCracker Script"
	condition: $suspicious_string
}
rule Rule_508_triggered {
	meta: description = "Rule # 508 Suspicious String Krypton triggered"
	strings: $suspicious_string = "Krypton"
	condition: $suspicious_string
}
rule Rule_509_triggered {
	meta: description = "Rule # 509 Suspicious String Ksk_WTG triggered"
	strings: $suspicious_string = "Ksk_WTG"
	condition: $suspicious_string
}
rule Rule_510_triggered {
	meta: description = "Rule # 510 Suspicious String Kucing Galau  triggered"
	strings: $suspicious_string = "Kucing Galau "
	condition: $suspicious_string
}
rule Rule_511_triggered {
	meta: description = "Rule # 511 Suspicious String Kuuhaku triggered"
	strings: $suspicious_string = "Kuuhaku"
	condition: $suspicious_string
}
rule Rule_512_triggered {
	meta: description = "Rule # 512 Suspicious String Kuzu triggered"
	strings: $suspicious_string = "Kuzu"
	condition: $suspicious_string
}
rule Rule_513_triggered {
	meta: description = "Rule # 513 Suspicious String L3m0t N3t triggered"
	strings: $suspicious_string = "L3m0t N3t"
	condition: $suspicious_string
}
rule Rule_514_triggered {
	meta: description = "Rule # 514 Suspicious String L4W_CyberDKSH404.Not_Found  triggered"
	strings: $suspicious_string = "L4W_CyberDKSH404.Not_Found "
	condition: $suspicious_string
}
rule Rule_515_triggered {
	meta: description = "Rule # 515 Suspicious String L4z4ru5 triggered"
	strings: $suspicious_string = "L4z4ru5"
	condition: $suspicious_string
}
rule Rule_516_triggered {
	meta: description = "Rule # 516 Suspicious String LOCUS7S.COM triggered"
	strings: $suspicious_string = "LOCUS7S.COM"
	condition: $suspicious_string
}
rule Rule_517_triggered {
	meta: description = "Rule # 517 Suspicious String LaHmuQPfnzW triggered"
	strings: $suspicious_string = "LaHmuQPfnzW"
	condition: $suspicious_string
}
rule Rule_518_triggered {
	meta: description = "Rule # 518 Suspicious String Lalabitch triggered"
	strings: $suspicious_string = "Lalabitch"
	condition: $suspicious_string
}
rule Rule_519_triggered {
	meta: description = "Rule # 519 Suspicious String Lalabitch Team triggered"
	strings: $suspicious_string = "Lalabitch Team"
	condition: $suspicious_string
}
rule Rule_520_triggered {
	meta: description = "Rule # 520 Suspicious String Lalabitch Victimz (2017) Ransomware triggered"
	strings: $suspicious_string = "Lalabitch Victimz (2017) Ransomware"
	condition: $suspicious_string
}
rule Rule_521_triggered {
	meta: description = "Rule # 521 Suspicious String Lamongan Exploiters triggered"
	strings: $suspicious_string = "Lamongan Exploiters"
	condition: $suspicious_string
}
rule Rule_522_triggered {
	meta: description = "Rule # 522 Suspicious String Laser69 triggered"
	strings: $suspicious_string = "Laser69"
	condition: $suspicious_string
}
rule Rule_523_triggered {
	meta: description = "Rule # 523 Suspicious String LazyUser_ triggered"
	strings: $suspicious_string = "LazyUser_"
	condition: $suspicious_string
}
rule Rule_524_triggered {
	meta: description = "Rule # 524 Suspicious String Legend Bot triggered"
	strings: $suspicious_string = "Legend Bot"
	condition: $suspicious_string
}
rule Rule_525_triggered {
	meta: description = "Rule # 525 Suspicious String Legion BOmb3r triggered"
	strings: $suspicious_string = "Legion BOmb3r"
	condition: $suspicious_string
}
rule Rule_526_triggered {
	meta: description = "Rule # 526 Suspicious String LinEnum.sh triggered"
	strings: $suspicious_string = "LinEnum.sh"
	condition: $suspicious_string
}
rule Rule_527_triggered {
	meta: description = "Rule # 527 Suspicious String Linux vmsplice Local Root Exploit triggered"
	strings: $suspicious_string = "Linux vmsplice Local Root Exploit"
	condition: $suspicious_string
}
rule Rule_528_triggered {
	meta: description = "Rule # 528 Suspicious String Lion.Hacker triggered"
	strings: $suspicious_string = "Lion.Hacker"
	condition: $suspicious_string
}
rule Rule_529_triggered {
	meta: description = "Rule # 529 Suspicious String LoVe511 Mail3R triggered"
	strings: $suspicious_string = "LoVe511 Mail3R"
	condition: $suspicious_string
}
rule Rule_530_triggered {
	meta: description = "Rule # 530 Suspicious String Local Linux Enumeration & Privilege Escalation Script triggered"
	strings: $suspicious_string = "Local Linux Enumeration & Privilege Escalation Script"
	condition: $suspicious_string
}
rule Rule_531_triggered {
	meta: description = "Rule # 531 Suspicious String Local root indishell triggered"
	strings: $suspicious_string = "Local root indishell"
	condition: $suspicious_string
}
rule Rule_532_triggered {
	meta: description = "Rule # 532 Suspicious String LockeD By Joky triggered"
	strings: $suspicious_string = "LockeD By Joky"
	condition: $suspicious_string
}
rule Rule_533_triggered {
	meta: description = "Rule # 533 Suspicious String Locus7s Modified c100 Shell triggered"
	strings: $suspicious_string = "Locus7s Modified c100 Shell"
	condition: $suspicious_string
}
rule Rule_534_triggered {
	meta: description = "Rule # 534 Suspicious String Login Sukses triggered"
	strings: $suspicious_string = "Login Sukses"
	condition: $suspicious_string
}
rule Rule_535_triggered {
	meta: description = "Rule # 535 Suspicious String Logs Eraser triggered"
	strings: $suspicious_string = "Logs Eraser"
	condition: $suspicious_string
}
rule Rule_536_triggered {
	meta: description = "Rule # 536 Suspicious String LolzSec triggered"
	strings: $suspicious_string = "LolzSec"
	condition: $suspicious_string
}
rule Rule_537_triggered {
	meta: description = "Rule # 537 Suspicious String Lon.Cua.Co.Be triggered"
	strings: $suspicious_string = "Lon.Cua.Co.Be"
	condition: $suspicious_string
}
rule Rule_538_triggered {
	meta: description = "Rule # 538 Suspicious String LorD of IRAN HACKERS SABOTAGE triggered"
	strings: $suspicious_string = "LorD of IRAN HACKERS SABOTAGE"
	condition: $suspicious_string
}
rule Rule_539_triggered {
	meta: description = "Rule # 539 Suspicious String LorD-C0d3r-NT triggered"
	strings: $suspicious_string = "LorD-C0d3r-NT"
	condition: $suspicious_string
}
rule Rule_540_triggered {
	meta: description = "Rule # 540 Suspicious String Lov3rDns triggered"
	strings: $suspicious_string = "Lov3rDns"
	condition: $suspicious_string
}
rule Rule_541_triggered {
	meta: description = "Rule # 541 Suspicious String Ludarubma triggered"
	strings: $suspicious_string = "Ludarubma"
	condition: $suspicious_string
}
rule Rule_542_triggered {
	meta: description = "Rule # 542 Suspicious String Luge Racer triggered"
	strings: $suspicious_string = "Luge Racer"
	condition: $suspicious_string
}
rule Rule_543_triggered {
	meta: description = "Rule # 543 Suspicious String Lutfen Shell Secin triggered"
	strings: $suspicious_string = "Lutfen Shell Secin"
	condition: $suspicious_string
}
rule Rule_544_triggered {
	meta: description = "Rule # 544 Suspicious String LyMaNlYmCo@YahoO.CoM triggered"
	strings: $suspicious_string = "LyMaNlYmCo@YahoO.CoM"
	condition: $suspicious_string
}
rule Rule_545_triggered {
	meta: description = "Rule # 545 Suspicious String Ly_Forbidden triggered"
	strings: $suspicious_string = "Ly_Forbidden"
	condition: $suspicious_string
}
rule Rule_546_triggered {
	meta: description = "Rule # 546 Suspicious String Ly_Gh0st triggered"
	strings: $suspicious_string = "Ly_Gh0st"
	condition: $suspicious_string
}
rule Rule_547_triggered {
	meta: description = "Rule # 547 Suspicious String M-Iraq triggered"
	strings: $suspicious_string = "M-Iraq"
	condition: $suspicious_string
}
rule Rule_548_triggered {
	meta: description = "Rule # 548 Suspicious String M4RY_PR0S4 triggered"
	strings: $suspicious_string = "M4RY_PR0S4"
	condition: $suspicious_string
}
rule Rule_549_triggered {
	meta: description = "Rule # 549 Suspicious String MA DZ TN V2 triggered"
	strings: $suspicious_string = "MA DZ TN V2"
	condition: $suspicious_string
}
rule Rule_550_triggered {
	meta: description = "Rule # 550 Suspicious String MATRIX CYBER TEAM triggered"
	strings: $suspicious_string = "MATRIX CYBER TEAM"
	condition: $suspicious_string
}
rule Rule_551_triggered {
	meta: description = "Rule # 551 Suspicious String MA_h4ck0601 triggered"
	strings: $suspicious_string = "MA_h4ck0601"
	condition: $suspicious_string
}
rule Rule_552_triggered {
	meta: description = "Rule # 552 Suspicious String MCA Shell triggered"
	strings: $suspicious_string = "MCA Shell"
	condition: $suspicious_string
}
rule Rule_553_triggered {
	meta: description = "Rule # 553 Suspicious String MD-GHOST triggered"
	strings: $suspicious_string = "MD-GHOST"
	condition: $suspicious_string
}
rule Rule_554_triggered {
	meta: description = "Rule # 554 Suspicious String ML/EF8ZjRZnsUrk/hVMOJaQZS19pZ triggered"
	strings: $suspicious_string = "ML/EF8ZjRZnsUrk/hVMOJaQZS19pZ"
	condition: $suspicious_string
}
rule Rule_555_triggered {
	meta: description = "Rule # 555 Suspicious String MNTR27 triggered"
	strings: $suspicious_string = "MNTR27"
	condition: $suspicious_string
}
rule Rule_556_triggered {
	meta: description = "Rule # 556 Suspicious String MOSLEM CYBER TEAM triggered"
	strings: $suspicious_string = "MOSLEM CYBER TEAM"
	condition: $suspicious_string
}
rule Rule_557_triggered {
	meta: description = "Rule # 557 Suspicious String MR.N00I3 triggered"
	strings: $suspicious_string = "MR.N00I3"
	condition: $suspicious_string
}
rule Rule_558_triggered {
	meta: description = "Rule # 558 Suspicious String MR.ROBOT triggered"
	strings: $suspicious_string = "MR.ROBOT"
	condition: $suspicious_string
}
rule Rule_559_triggered {
	meta: description = "Rule # 559 Suspicious String MR.ZADZIK triggered"
	strings: $suspicious_string = "MR.ZADZIK"
	condition: $suspicious_string
}
rule Rule_560_triggered {
	meta: description = "Rule # 560 Suspicious String MSRml.pl triggered"
	strings: $suspicious_string = "MSRml.pl"
	condition: $suspicious_string
}
rule Rule_561_triggered {
	meta: description = "Rule # 561 Suspicious String MYREALDAY triggered"
	strings: $suspicious_string = "MYREALDAY"
	condition: $suspicious_string
}
rule Rule_562_triggered {
	meta: description = "Rule # 562 Suspicious String MaDLeeTs triggered"
	strings: $suspicious_string = "MaDLeeTs"
	condition: $suspicious_string
}
rule Rule_563_triggered {
	meta: description = "Rule # 563 Suspicious String MaStEr HaCkEr triggered"
	strings: $suspicious_string = "MaStEr HaCkEr"
	condition: $suspicious_string
}
rule Rule_564_triggered {
	meta: description = "Rule # 564 Suspicious String Maestro404 triggered"
	strings: $suspicious_string = "Maestro404"
	condition: $suspicious_string
}
rule Rule_565_triggered {
	meta: description = "Rule # 565 Suspicious String Magico HelpeR triggered"
	strings: $suspicious_string = "Magico HelpeR"
	condition: $suspicious_string
}
rule Rule_566_triggered {
	meta: description = "Rule # 566 Suspicious String Magico pws triggered"
	strings: $suspicious_string = "Magico pws"
	condition: $suspicious_string
}
rule Rule_567_triggered {
	meta: description = "Rule # 567 Suspicious String Magnum sniper triggered"
	strings: $suspicious_string = "Magnum sniper"
	condition: $suspicious_string
}
rule Rule_568_triggered {
	meta: description = "Rule # 568 Suspicious String Mahdi Curva Sud triggered"
	strings: $suspicious_string = "Mahdi Curva Sud"
	condition: $suspicious_string
}
rule Rule_569_triggered {
	meta: description = "Rule # 569 Suspicious String Mahiin triggered"
	strings: $suspicious_string = "Mahiin"
	condition: $suspicious_string
}
rule Rule_570_triggered {
	meta: description = "Rule # 570 Suspicious String MailBox Renewal Portal triggered"
	strings: $suspicious_string = "MailBox Renewal Portal"
	condition: $suspicious_string
}
rule Rule_571_triggered {
	meta: description = "Rule # 571 Suspicious String Maile Inbox By triggered"
	strings: $suspicious_string = "Maile Inbox By"
	condition: $suspicious_string
}
rule Rule_572_triggered {
	meta: description = "Rule # 572 Suspicious String Mailer by X-Nero triggered"
	strings: $suspicious_string = "Mailer by X-Nero"
	condition: $suspicious_string
}
rule Rule_573_triggered {
	meta: description = "Rule # 573 Suspicious String MainHack triggered"
	strings: $suspicious_string = "MainHack"
	condition: $suspicious_string
}
rule Rule_574_triggered {
	meta: description = "Rule # 574 Suspicious String Make in China triggered"
	strings: $suspicious_string = "Make in China"
	condition: $suspicious_string
}
rule Rule_575_triggered {
	meta: description = "Rule # 575 Suspicious String Maked By  triggered"
	strings: $suspicious_string = "Maked By "
	condition: $suspicious_string
}
rule Rule_576_triggered {
	meta: description = "Rule # 576 Suspicious String Man404_ID  triggered"
	strings: $suspicious_string = "Man404_ID "
	condition: $suspicious_string
}
rule Rule_577_triggered {
	meta: description = "Rule # 577 Suspicious String Mannu triggered"
	strings: $suspicious_string = "Mannu"
	condition: $suspicious_string
}
rule Rule_578_triggered {
	meta: description = "Rule # 578 Suspicious String Marwan007 triggered"
	strings: $suspicious_string = "Marwan007"
	condition: $suspicious_string
}
rule Rule_579_triggered {
	meta: description = "Rule # 579 Suspicious String Mauritania Attacker triggered"
	strings: $suspicious_string = "Mauritania Attacker"
	condition: $suspicious_string
}
rule Rule_580_triggered {
	meta: description = "Rule # 580 Suspicious String Mauritania HaCker Team triggered"
	strings: $suspicious_string = "Mauritania HaCker Team"
	condition: $suspicious_string
}
rule Rule_581_triggered {
	meta: description = "Rule # 581 Suspicious String Mdn_newbie triggered"
	strings: $suspicious_string = "Mdn_newbie"
	condition: $suspicious_string
}
rule Rule_582_triggered {
	meta: description = "Rule # 582 Suspicious String Melvin and all ljuska.org and x0rg.org members triggered"
	strings: $suspicious_string = "Melvin and all ljuska.org and x0rg.org members"
	condition: $suspicious_string
}
rule Rule_583_triggered {
	meta: description = "Rule # 583 Suspicious String Mercury2911 triggered"
	strings: $suspicious_string = "Mercury2911"
	condition: $suspicious_string
}
rule Rule_584_triggered {
	meta: description = "Rule # 584 Suspicious String MikiSoft triggered"
	strings: $suspicious_string = "MikiSoft"
	condition: $suspicious_string
}
rule Rule_585_triggered {
	meta: description = "Rule # 585 Suspicious String Minhal Mehdi  triggered"
	strings: $suspicious_string = "Minhal Mehdi "
	condition: $suspicious_string
}
rule Rule_586_triggered {
	meta: description = "Rule # 586 Suspicious String Mini shell triggered"
	strings: $suspicious_string = "Mini shell"
	condition: $suspicious_string
}
rule Rule_587_triggered {
	meta: description = "Rule # 587 Suspicious String Mirror Zone-BBHH triggered"
	strings: $suspicious_string = "Mirror Zone-BBHH"
	condition: $suspicious_string
}
rule Rule_588_triggered {
	meta: description = "Rule # 588 Suspicious String Missing type of reverse shell triggered"
	strings: $suspicious_string = "Missing type of reverse shell"
	condition: $suspicious_string
}
rule Rule_589_triggered {
	meta: description = "Rule # 589 Suspicious String Miyachung triggered"
	strings: $suspicious_string = "Miyachung"
	condition: $suspicious_string
}
rule Rule_590_triggered {
	meta: description = "Rule # 590 Suspicious String Mizt3riO-uZ triggered"
	strings: $suspicious_string = "Mizt3riO-uZ"
	condition: $suspicious_string
}
rule Rule_591_triggered {
	meta: description = "Rule # 591 Suspicious String Modified by Shadow & Preddy triggered"
	strings: $suspicious_string = "Modified by Shadow & Preddy"
	condition: $suspicious_string
}
rule Rule_592_triggered {
	meta: description = "Rule # 592 Suspicious String Modon Tak triggered"
	strings: $suspicious_string = "Modon Tak"
	condition: $suspicious_string
}
rule Rule_593_triggered {
	meta: description = "Rule # 593 Suspicious String Mohammad Yasir triggered"
	strings: $suspicious_string = "Mohammad Yasir"
	condition: $suspicious_string
}
rule Rule_594_triggered {
	meta: description = "Rule # 594 Suspicious String Mohkalad HaXor triggered"
	strings: $suspicious_string = "Mohkalad HaXor"
	condition: $suspicious_string
}
rule Rule_595_triggered {
	meta: description = "Rule # 595 Suspicious String Moneer Masoud triggered"
	strings: $suspicious_string = "Moneer Masoud"
	condition: $suspicious_string
}
rule Rule_596_triggered {
	meta: description = "Rule # 596 Suspicious String Monkey B Luffy triggered"
	strings: $suspicious_string = "Monkey B Luffy"
	condition: $suspicious_string
}
rule Rule_597_triggered {
	meta: description = "Rule # 597 Suspicious String Monsters Defacers triggered"
	strings: $suspicious_string = "Monsters Defacers"
	condition: $suspicious_string
}
rule Rule_598_triggered {
	meta: description = "Rule # 598 Suspicious String MooT HaCkEr - NaiF KSA triggered"
	strings: $suspicious_string = "MooT HaCkEr - NaiF KSA"
	condition: $suspicious_string
}
rule Rule_599_triggered {
	meta: description = "Rule # 599 Suspicious String Moroccan H4x0r triggered"
	strings: $suspicious_string = "Moroccan H4x0r"
	condition: $suspicious_string
}
rule Rule_600_triggered {
	meta: description = "Rule # 600 Suspicious String Morocco.Security.Rulz triggered"
	strings: $suspicious_string = "Morocco.Security.Rulz"
	condition: $suspicious_string
}
rule Rule_601_triggered {
	meta: description = "Rule # 601 Suspicious String Mr-Anobs triggered"
	strings: $suspicious_string = "Mr-Anobs"
	condition: $suspicious_string
}
rule Rule_602_triggered {
	meta: description = "Rule # 602 Suspicious String Mr-Lordz triggered"
	strings: $suspicious_string = "Mr-Lordz"
	condition: $suspicious_string
}
rule Rule_603_triggered {
	meta: description = "Rule # 603 Suspicious String Mr. DellatioNx196 triggered"
	strings: $suspicious_string = "Mr. DellatioNx196"
	condition: $suspicious_string
}
rule Rule_604_triggered {
	meta: description = "Rule # 604 Suspicious String Mr. Trojan triggered"
	strings: $suspicious_string = "Mr. Trojan"
	condition: $suspicious_string
}
rule Rule_605_triggered {
	meta: description = "Rule # 605 Suspicious String Mr.404_NotFound  triggered"
	strings: $suspicious_string = "Mr.404_NotFound "
	condition: $suspicious_string
}
rule Rule_606_triggered {
	meta: description = "Rule # 606 Suspicious String Mr.Acid Khan triggered"
	strings: $suspicious_string = "Mr.Acid Khan"
	condition: $suspicious_string
}
rule Rule_607_triggered {
	meta: description = "Rule # 607 Suspicious String Mr.BIN triggered"
	strings: $suspicious_string = "Mr.BIN"
	condition: $suspicious_string
}
rule Rule_608_triggered {
	meta: description = "Rule # 608 Suspicious String Mr.Blank007 triggered"
	strings: $suspicious_string = "Mr.Blank007"
	condition: $suspicious_string
}
rule Rule_609_triggered {
	meta: description = "Rule # 609 Suspicious String Mr.BroTx triggered"
	strings: $suspicious_string = "Mr.BroTx"
	condition: $suspicious_string
}
rule Rule_610_triggered {
	meta: description = "Rule # 610 Suspicious String Mr.Bro_Tx triggered"
	strings: $suspicious_string = "Mr.Bro_Tx"
	condition: $suspicious_string
}
rule Rule_611_triggered {
	meta: description = "Rule # 611 Suspicious String Mr.Cakil triggered"
	strings: $suspicious_string = "Mr.Cakil"
	condition: $suspicious_string
}
rule Rule_612_triggered {
	meta: description = "Rule # 612 Suspicious String Mr.Dork  triggered"
	strings: $suspicious_string = "Mr.Dork "
	condition: $suspicious_string
}
rule Rule_613_triggered {
	meta: description = "Rule # 613 Suspicious String Mr.Dr3awe triggered"
	strings: $suspicious_string = "Mr.Dr3awe"
	condition: $suspicious_string
}
rule Rule_614_triggered {
	meta: description = "Rule # 614 Suspicious String Mr.FMR triggered"
	strings: $suspicious_string = "Mr.FMR"
	condition: $suspicious_string
}
rule Rule_615_triggered {
	meta: description = "Rule # 615 Suspicious String Mr.Ghostteror_404  triggered"
	strings: $suspicious_string = "Mr.Ghostteror_404 "
	condition: $suspicious_string
}
rule Rule_616_triggered {
	meta: description = "Rule # 616 Suspicious String Mr.HTTP    triggered"
	strings: $suspicious_string = "Mr.HTTP   "
	condition: $suspicious_string
}
rule Rule_617_triggered {
	meta: description = "Rule # 617 Suspicious String Mr.HanzID triggered"
	strings: $suspicious_string = "Mr.HanzID"
	condition: $suspicious_string
}
rule Rule_618_triggered {
	meta: description = "Rule # 618 Suspicious String Mr.HaurgeulisX196  triggered"
	strings: $suspicious_string = "Mr.HaurgeulisX196 "
	condition: $suspicious_string
}
rule Rule_619_triggered {
	meta: description = "Rule # 619 Suspicious String Mr.HiTman triggered"
	strings: $suspicious_string = "Mr.HiTman"
	condition: $suspicious_string
}
rule Rule_620_triggered {
	meta: description = "Rule # 620 Suspicious String Mr.HydR4 triggered"
	strings: $suspicious_string = "Mr.HydR4"
	condition: $suspicious_string
}
rule Rule_621_triggered {
	meta: description = "Rule # 621 Suspicious String Mr.Hydr4 triggered"
	strings: $suspicious_string = "Mr.Hydr4"
	condition: $suspicious_string
}
rule Rule_622_triggered {
	meta: description = "Rule # 622 Suspicious String Mr.Java404 triggered"
	strings: $suspicious_string = "Mr.Java404"
	condition: $suspicious_string
}
rule Rule_623_triggered {
	meta: description = "Rule # 623 Suspicious String Mr.Kro0oz.305 triggered"
	strings: $suspicious_string = "Mr.Kro0oz.305"
	condition: $suspicious_string
}
rule Rule_624_triggered {
	meta: description = "Rule # 624 Suspicious String Mr.Labib404 triggered"
	strings: $suspicious_string = "Mr.Labib404"
	condition: $suspicious_string
}
rule Rule_625_triggered {
	meta: description = "Rule # 625 Suspicious String Mr.LittleHaxor  triggered"
	strings: $suspicious_string = "Mr.LittleHaxor "
	condition: $suspicious_string
}
rule Rule_626_triggered {
	meta: description = "Rule # 626 Suspicious String Mr.Luciferz triggered"
	strings: $suspicious_string = "Mr.Luciferz"
	condition: $suspicious_string
}
rule Rule_627_triggered {
	meta: description = "Rule # 627 Suspicious String Mr.N00B triggered"
	strings: $suspicious_string = "Mr.N00B"
	condition: $suspicious_string
}
rule Rule_628_triggered {
	meta: description = "Rule # 628 Suspicious String Mr.P41J0  triggered"
	strings: $suspicious_string = "Mr.P41J0 "
	condition: $suspicious_string
}
rule Rule_629_triggered {
	meta: description = "Rule # 629 Suspicious String Mr.PoorBAD@Alpha.com triggered"
	strings: $suspicious_string = "Mr.PoorBAD@Alpha.com"
	condition: $suspicious_string
}
rule Rule_630_triggered {
	meta: description = "Rule # 630 Suspicious String Mr.R007 triggered"
	strings: $suspicious_string = "Mr.R007"
	condition: $suspicious_string
}
rule Rule_631_triggered {
	meta: description = "Rule # 631 Suspicious String Mr.Robot triggered"
	strings: $suspicious_string = "Mr.Robot"
	condition: $suspicious_string
}
rule Rule_632_triggered {
	meta: description = "Rule # 632 Suspicious String Mr.Swan triggered"
	strings: $suspicious_string = "Mr.Swan"
	condition: $suspicious_string
}
rule Rule_633_triggered {
	meta: description = "Rule # 633 Suspicious String Mr.TenWap triggered"
	strings: $suspicious_string = "Mr.TenWap"
	condition: $suspicious_string
}
rule Rule_634_triggered {
	meta: description = "Rule # 634 Suspicious String Mr.Trouble5hooting triggered"
	strings: $suspicious_string = "Mr.Trouble5hooting"
	condition: $suspicious_string
}
rule Rule_635_triggered {
	meta: description = "Rule # 635 Suspicious String Mr.Vendetta_404 triggered"
	strings: $suspicious_string = "Mr.Vendetta_404"
	condition: $suspicious_string
}
rule Rule_636_triggered {
	meta: description = "Rule # 636 Suspicious String Mr.WeXenT triggered"
	strings: $suspicious_string = "Mr.WeXenT"
	condition: $suspicious_string
}
rule Rule_637_triggered {
	meta: description = "Rule # 637 Suspicious String Mr.X98 triggered"
	strings: $suspicious_string = "Mr.X98"
	condition: $suspicious_string
}
rule Rule_638_triggered {
	meta: description = "Rule # 638 Suspicious String Mr.aji.192  triggered"
	strings: $suspicious_string = "Mr.aji.192 "
	condition: $suspicious_string
}
rule Rule_639_triggered {
	meta: description = "Rule # 639 Suspicious String Mr.dexter.305  triggered"
	strings: $suspicious_string = "Mr.dexter.305 "
	condition: $suspicious_string
}
rule Rule_640_triggered {
	meta: description = "Rule # 640 Suspicious String Mr.foxIND27 triggered"
	strings: $suspicious_string = "Mr.foxIND27"
	condition: $suspicious_string
}
rule Rule_641_triggered {
	meta: description = "Rule # 641 Suspicious String Mr.greetz69 triggered"
	strings: $suspicious_string = "Mr.greetz69"
	condition: $suspicious_string
}
rule Rule_642_triggered {
	meta: description = "Rule # 642 Suspicious String Mr.wexent triggered"
	strings: $suspicious_string = "Mr.wexent"
	condition: $suspicious_string
}
rule Rule_643_triggered {
	meta: description = "Rule # 643 Suspicious String Mr.x0x triggered"
	strings: $suspicious_string = "Mr.x0x"
	condition: $suspicious_string
}
rule Rule_644_triggered {
	meta: description = "Rule # 644 Suspicious String Mr.xBaraKuda triggered"
	strings: $suspicious_string = "Mr.xBaraKuda"
	condition: $suspicious_string
}
rule Rule_645_triggered {
	meta: description = "Rule # 645 Suspicious String MrJoker triggered"
	strings: $suspicious_string = "MrJoker"
	condition: $suspicious_string
}
rule Rule_646_triggered {
	meta: description = "Rule # 646 Suspicious String Mr_Oxygen  triggered"
	strings: $suspicious_string = "Mr_Oxygen "
	condition: $suspicious_string
}
rule Rule_647_triggered {
	meta: description = "Rule # 647 Suspicious String MrxCyberX  triggered"
	strings: $suspicious_string = "MrxCyberX "
	condition: $suspicious_string
}
rule Rule_648_triggered {
	meta: description = "Rule # 648 Suspicious String Mugi Doa Ibu Ingkang Varokah triggered"
	strings: $suspicious_string = "Mugi Doa Ibu Ingkang Varokah"
	condition: $suspicious_string
}
rule Rule_649_triggered {
	meta: description = "Rule # 649 Suspicious String MugiwaraCrew triggered"
	strings: $suspicious_string = "MugiwaraCrew"
	condition: $suspicious_string
}
rule Rule_650_triggered {
	meta: description = "Rule # 650 Suspicious String Mujahidin Cyber Army triggered"
	strings: $suspicious_string = "Mujahidin Cyber Army"
	condition: $suspicious_string
}
rule Rule_651_triggered {
	meta: description = "Rule # 651 Suspicious String Mujahidin303 triggered"
	strings: $suspicious_string = "Mujahidin303"
	condition: $suspicious_string
}
rule Rule_652_triggered {
	meta: description = "Rule # 652 Suspicious String Muslim Cyber Army triggered"
	strings: $suspicious_string = "Muslim Cyber Army"
	condition: $suspicious_string
}
rule Rule_653_triggered {
	meta: description = "Rule # 653 Suspicious String Muslim Cyber Security triggered"
	strings: $suspicious_string = "Muslim Cyber Security"
	condition: $suspicious_string
}
rule Rule_654_triggered {
	meta: description = "Rule # 654 Suspicious String My Bee triggered"
	strings: $suspicious_string = "My Bee"
	condition: $suspicious_string
}
rule Rule_655_triggered {
	meta: description = "Rule # 655 Suspicious String My DARK-H triggered"
	strings: $suspicious_string = "My DARK-H"
	condition: $suspicious_string
}
rule Rule_656_triggered {
	meta: description = "Rule # 656 Suspicious String My ZONE-H triggered"
	strings: $suspicious_string = "My ZONE-H"
	condition: $suspicious_string
}
rule Rule_657_triggered {
	meta: description = "Rule # 657 Suspicious String N16H7H4WK triggered"
	strings: $suspicious_string = "N16H7H4WK"
	condition: $suspicious_string
}
rule Rule_658_triggered {
	meta: description = "Rule # 658 Suspicious String N45HT triggered"
	strings: $suspicious_string = "N45HT"
	condition: $suspicious_string
}
rule Rule_659_triggered {
	meta: description = "Rule # 659 Suspicious String N4sKun triggered"
	strings: $suspicious_string = "N4sKun"
	condition: $suspicious_string
}
rule Rule_660_triggered {
	meta: description = "Rule # 660 Suspicious String NO update exists boss triggered"
	strings: $suspicious_string = "NO update exists boss"
	condition: $suspicious_string
}
rule Rule_661_triggered {
	meta: description = "Rule # 661 Suspicious String NONE@ggledocs.com triggered"
	strings: $suspicious_string = "NONE@ggledocs.com"
	condition: $suspicious_string
}
rule Rule_662_triggered {
	meta: description = "Rule # 662 Suspicious String Naughty_r00tz  triggered"
	strings: $suspicious_string = "Naughty_r00tz "
	condition: $suspicious_string
}
rule Rule_663_triggered {
	meta: description = "Rule # 663 Suspicious String NeEeO_HaCk triggered"
	strings: $suspicious_string = "NeEeO_HaCk"
	condition: $suspicious_string
}
rule Rule_664_triggered {
	meta: description = "Rule # 664 Suspicious String Neneng Juhairiah triggered"
	strings: $suspicious_string = "Neneng Juhairiah"
	condition: $suspicious_string
}
rule Rule_665_triggered {
	meta: description = "Rule # 665 Suspicious String Neo hacker ICA triggered"
	strings: $suspicious_string = "Neo hacker ICA"
	condition: $suspicious_string
}
rule Rule_666_triggered {
	meta: description = "Rule # 666 Suspicious String Net Scrap Shop triggered"
	strings: $suspicious_string = "Net Scrap Shop"
	condition: $suspicious_string
}
rule Rule_667_triggered {
	meta: description = "Rule # 667 Suspicious String NetJackal triggered"
	strings: $suspicious_string = "NetJackal"
	condition: $suspicious_string
}
rule Rule_668_triggered {
	meta: description = "Rule # 668 Suspicious String Netflix - Billing Information triggered"
	strings: $suspicious_string = "Netflix - Billing Information"
	condition: $suspicious_string
}
rule Rule_669_triggered {
	meta: description = "Rule # 669 Suspicious String Netflix - Payment Information triggered"
	strings: $suspicious_string = "Netflix - Payment Information"
	condition: $suspicious_string
}
rule Rule_670_triggered {
	meta: description = "Rule # 670 Suspicious String Newbie3viLc063s h3x4Crew RileksCrew Family triggered"
	strings: $suspicious_string = "Newbie3viLc063s h3x4Crew RileksCrew Family"
	condition: $suspicious_string
}
rule Rule_671_triggered {
	meta: description = "Rule # 671 Suspicious String Nginx1337 triggered"
	strings: $suspicious_string = "Nginx1337"
	condition: $suspicious_string
}
rule Rule_672_triggered {
	meta: description = "Rule # 672 Suspicious String Nilotpal Biswas triggered"
	strings: $suspicious_string = "Nilotpal Biswas"
	condition: $suspicious_string
}
rule Rule_673_triggered {
	meta: description = "Rule # 673 Suspicious String Ninja-Security triggered"
	strings: $suspicious_string = "Ninja-Security"
	condition: $suspicious_string
}
rule Rule_674_triggered {
	meta: description = "Rule # 674 Suspicious String NmR.Hacker triggered"
	strings: $suspicious_string = "NmR.Hacker"
	condition: $suspicious_string
}
rule Rule_675_triggered {
	meta: description = "Rule # 675 Suspicious String Nobrex triggered"
	strings: $suspicious_string = "Nobrex"
	condition: $suspicious_string
}
rule Rule_676_triggered {
	meta: description = "Rule # 676 Suspicious String NonameUser triggered"
	strings: $suspicious_string = "NonameUser"
	condition: $suspicious_string
}
rule Rule_677_triggered {
	meta: description = "Rule # 677 Suspicious String O-Ghost Hacker triggered"
	strings: $suspicious_string = "O-Ghost Hacker"
	condition: $suspicious_string
}
rule Rule_678_triggered {
	meta: description = "Rule # 678 Suspicious String Obat Kuat triggered"
	strings: $suspicious_string = "Obat Kuat"
	condition: $suspicious_string
}
rule Rule_679_triggered {
	meta: description = "Rule # 679 Suspicious String Obfuscation provided by FOPO triggered"
	strings: $suspicious_string = "Obfuscation provided by FOPO"
	condition: $suspicious_string
}
rule Rule_680_triggered {
	meta: description = "Rule # 680 Suspicious String Obisidian Cyber Team triggered"
	strings: $suspicious_string = "Obisidian Cyber Team"
	condition: $suspicious_string
}
rule Rule_681_triggered {
	meta: description = "Rule # 681 Suspicious String Old-Rebuild Lady triggered"
	strings: $suspicious_string = "Old-Rebuild Lady"
	condition: $suspicious_string
}
rule Rule_682_triggered {
	meta: description = "Rule # 682 Suspicious String Oli404 triggered"
	strings: $suspicious_string = "Oli404"
	condition: $suspicious_string
}
rule Rule_683_triggered {
	meta: description = "Rule # 683 Suspicious String Open-Realty triggered"
	strings: $suspicious_string = "Open-Realty"
	condition: $suspicious_string
}
rule Rule_684_triggered {
	meta: description = "Rule # 684 Suspicious String Opreker triggered"
	strings: $suspicious_string = "Opreker"
	condition: $suspicious_string
}
rule Rule_685_triggered {
	meta: description = "Rule # 685 Suspicious String OrionsHunter triggered"
	strings: $suspicious_string = "OrionsHunter"
	condition: $suspicious_string
}
rule Rule_686_triggered {
	meta: description = "Rule # 686 Suspicious String Ov3rLorD triggered"
	strings: $suspicious_string = "Ov3rLorD"
	condition: $suspicious_string
}
rule Rule_687_triggered {
	meta: description = "Rule # 687 Suspicious String Overl0ser triggered"
	strings: $suspicious_string = "Overl0ser"
	condition: $suspicious_string
}
rule Rule_688_triggered {
	meta: description = "Rule # 688 Suspicious String Ownedby|v!nc3 triggered"
	strings: $suspicious_string = "Ownedby|v!nc3"
	condition: $suspicious_string
}
rule Rule_689_triggered {
	meta: description = "Rule # 689 Suspicious String P0150n Op3r470r triggered"
	strings: $suspicious_string = "P0150n Op3r470r"
	condition: $suspicious_string
}
rule Rule_690_triggered {
	meta: description = "Rule # 690 Suspicious String P0w3r3d By pedro triggered"
	strings: $suspicious_string = "P0w3r3d By pedro"
	condition: $suspicious_string
}
rule Rule_691_triggered {
	meta: description = "Rule # 691 Suspicious String PATO LOKO PARA DE VIADAGEM triggered"
	strings: $suspicious_string = "PATO LOKO PARA DE VIADAGEM"
	condition: $suspicious_string
}
rule Rule_692_triggered {
	meta: description = "Rule # 692 Suspicious String PD9waHAgJHsiXHg0N0xceDR triggered"
	strings: $suspicious_string = "PD9waHAgJHsiXHg0N0xceDR"
	condition: $suspicious_string
}
rule Rule_693_triggered {
	meta: description = "Rule # 693 Suspicious String PETR03X triggered"
	strings: $suspicious_string = "PETR03X"
	condition: $suspicious_string
}
rule Rule_694_triggered {
	meta: description = "Rule # 694 Suspicious String PH4NTHER     triggered"
	strings: $suspicious_string = "PH4NTHER    "
	condition: $suspicious_string
}
rule Rule_695_triggered {
	meta: description = "Rule # 695 Suspicious String PHOENIX SHELL triggered"
	strings: $suspicious_string = "PHOENIX SHELL"
	condition: $suspicious_string
}
rule Rule_696_triggered {
	meta: description = "Rule # 696 Suspicious String PHP Encode by  http://Www.PHPJiaMi.Com/ triggered"
	strings: $suspicious_string = "PHP Encode by  http://Www.PHPJiaMi.Com/"
	condition: $suspicious_string
}
rule Rule_697_triggered {
	meta: description = "Rule # 697 Suspicious String PHPJackal triggered"
	strings: $suspicious_string = "PHPJackal"
	condition: $suspicious_string
}
rule Rule_698_triggered {
	meta: description = "Rule # 698 Suspicious String PR0L3T3RS triggered"
	strings: $suspicious_string = "PR0L3T3RS"
	condition: $suspicious_string
}
rule Rule_699_triggered {
	meta: description = "Rule # 699 Suspicious String PRI[ll triggered"
	strings: $suspicious_string = "PRI[ll"
	condition: $suspicious_string
}
rule Rule_700_triggered {
	meta: description = "Rule # 700 Suspicious String PUBER - triggered"
	strings: $suspicious_string = "PUBER -"
	condition: $suspicious_string
}
rule Rule_701_triggered {
	meta: description = "Rule # 701 Suspicious String Pain Script To Symlink Configs triggered"
	strings: $suspicious_string = "Pain Script To Symlink Configs"
	condition: $suspicious_string
}
rule Rule_702_triggered {
	meta: description = "Rule # 702 Suspicious String Pain Symlink triggered"
	strings: $suspicious_string = "Pain Symlink"
	condition: $suspicious_string
}
rule Rule_703_triggered {
	meta: description = "Rule # 703 Suspicious String Pak Cyber Pyrates triggered"
	strings: $suspicious_string = "Pak Cyber Pyrates"
	condition: $suspicious_string
}
rule Rule_704_triggered {
	meta: description = "Rule # 704 Suspicious String Pak Hunters triggered"
	strings: $suspicious_string = "Pak Hunters"
	condition: $suspicious_string
}
rule Rule_705_triggered {
	meta: description = "Rule # 705 Suspicious String Pakistan Zindabad triggered"
	strings: $suspicious_string = "Pakistan Zindabad"
	condition: $suspicious_string
}
rule Rule_706_triggered {
	meta: description = "Rule # 706 Suspicious String Panel Cracker By Team IndiShell triggered"
	strings: $suspicious_string = "Panel Cracker By Team IndiShell"
	condition: $suspicious_string
}
rule Rule_707_triggered {
	meta: description = "Rule # 707 Suspicious String Pankaj Sharma triggered"
	strings: $suspicious_string = "Pankaj Sharma"
	condition: $suspicious_string
}
rule Rule_708_triggered {
	meta: description = "Rule # 708 Suspicious String PayPal US Bank Spam ReZulT triggered"
	strings: $suspicious_string = "PayPal US Bank Spam ReZulT"
	condition: $suspicious_string
}
rule Rule_709_triggered {
	meta: description = "Rule # 709 Suspicious String Paypal Token Generator triggered"
	strings: $suspicious_string = "Paypal Token Generator"
	condition: $suspicious_string
}
rule Rule_710_triggered {
	meta: description = "Rule # 710 Suspicious String Penggila Coli triggered"
	strings: $suspicious_string = "Penggila Coli"
	condition: $suspicious_string
}
rule Rule_711_triggered {
	meta: description = "Rule # 711 Suspicious String Persian Gulf For Ever triggered"
	strings: $suspicious_string = "Persian Gulf For Ever"
	condition: $suspicious_string
}
rule Rule_712_triggered {
	meta: description = "Rule # 712 Suspicious String Peruvian R00lz triggered"
	strings: $suspicious_string = "Peruvian R00lz"
	condition: $suspicious_string
}
rule Rule_713_triggered {
	meta: description = "Rule # 713 Suspicious String Ph33r triggered"
	strings: $suspicious_string = "Ph33r"
	condition: $suspicious_string
}
rule Rule_714_triggered {
	meta: description = "Rule # 714 Suspicious String PhantomGhost triggered"
	strings: $suspicious_string = "PhantomGhost"
	condition: $suspicious_string
}
rule Rule_715_triggered {
	meta: description = "Rule # 715 Suspicious String Phreaker triggered"
	strings: $suspicious_string = "Phreaker"
	condition: $suspicious_string
}
rule Rule_716_triggered {
	meta: description = "Rule # 716 Suspicious String Pinpal triggered"
	strings: $suspicious_string = "Pinpal"
	condition: $suspicious_string
}
rule Rule_717_triggered {
	meta: description = "Rule # 717 Suspicious String Please enter the new password triggered"
	strings: $suspicious_string = "Please enter the new password"
	condition: $suspicious_string
}
rule Rule_718_triggered {
	meta: description = "Rule # 718 Suspicious String Plugin Name: Wordpress Plugin Manager triggered"
	strings: $suspicious_string = "Plugin Name: Wordpress Plugin Manager"
	condition: $suspicious_string
}
rule Rule_719_triggered {
	meta: description = "Rule # 719 Suspicious String PoTi_SaD-Dz triggered"
	strings: $suspicious_string = "PoTi_SaD-Dz"
	condition: $suspicious_string
}
rule Rule_720_triggered {
	meta: description = "Rule # 720 Suspicious String Post DC Back Connect triggered"
	strings: $suspicious_string = "Post DC Back Connect"
	condition: $suspicious_string
}
rule Rule_721_triggered {
	meta: description = "Rule # 721 Suspicious String Powered By leetc0des.blogspot.com triggered"
	strings: $suspicious_string = "Powered By leetc0des.blogspot.com"
	condition: $suspicious_string
}
rule Rule_722_triggered {
	meta: description = "Rule # 722 Suspicious String Prappo Prince triggered"
	strings: $suspicious_string = "Prappo Prince"
	condition: $suspicious_string
}
rule Rule_723_triggered {
	meta: description = "Rule # 723 Suspicious String Priv8 2011 Attack Shell triggered"
	strings: $suspicious_string = "Priv8 2011 Attack Shell"
	condition: $suspicious_string
}
rule Rule_724_triggered {
	meta: description = "Rule # 724 Suspicious String Priv8 M@iler triggered"
	strings: $suspicious_string = "Priv8 M@iler"
	condition: $suspicious_string
}
rule Rule_725_triggered {
	meta: description = "Rule # 725 Suspicious String Private Mailer 6.2 triggered"
	strings: $suspicious_string = "Private Mailer 6.2"
	condition: $suspicious_string
}
rule Rule_726_triggered {
	meta: description = "Rule # 726 Suspicious String Problem Cyber Team triggered"
	strings: $suspicious_string = "Problem Cyber Team"
	condition: $suspicious_string
}
rule Rule_727_triggered {
	meta: description = "Rule # 727 Suspicious String Procoderz Team Albania triggered"
	strings: $suspicious_string = "Procoderz Team Albania"
	condition: $suspicious_string
}
rule Rule_728_triggered {
	meta: description = "Rule # 728 Suspicious String Procoder’z Team Albania triggered"
	strings: $suspicious_string = "Procoder’z Team Albania"
	condition: $suspicious_string
}
rule Rule_729_triggered {
	meta: description = "Rule # 729 Suspicious String Prosox triggered"
	strings: $suspicious_string = "Prosox"
	condition: $suspicious_string
}
rule Rule_730_triggered {
	meta: description = "Rule # 730 Suspicious String Pwnd? triggered"
	strings: $suspicious_string = "Pwnd?"
	condition: $suspicious_string
}
rule Rule_731_triggered {
	meta: description = "Rule # 731 Suspicious String Pwned by Lalabitch triggered"
	strings: $suspicious_string = "Pwned by Lalabitch"
	condition: $suspicious_string
}
rule Rule_732_triggered {
	meta: description = "Rule # 732 Suspicious String QHR hacker triggered"
	strings: $suspicious_string = "QHR hacker"
	condition: $suspicious_string
}
rule Rule_733_triggered {
	meta: description = "Rule # 733 Suspicious String R00t3d Br4!n triggered"
	strings: $suspicious_string = "R00t3d Br4!n"
	condition: $suspicious_string
}
rule Rule_734_triggered {
	meta: description = "Rule # 734 Suspicious String R0xPQkFMUw== triggered"
	strings: $suspicious_string = "R0xPQkFMUw=="
	condition: $suspicious_string
}
rule Rule_735_triggered {
	meta: description = "Rule # 735 Suspicious String R3DD3V1L  triggered"
	strings: $suspicious_string = "R3DD3V1L "
	condition: $suspicious_string
}
rule Rule_736_triggered {
	meta: description = "Rule # 736 Suspicious String R4ST4_R00T triggered"
	strings: $suspicious_string = "R4ST4_R00T"
	condition: $suspicious_string
}
rule Rule_737_triggered {
	meta: description = "Rule # 737 Suspicious String R4ZW4N BIN SUL4IM4N triggered"
	strings: $suspicious_string = "R4ZW4N BIN SUL4IM4N"
	condition: $suspicious_string
}
rule Rule_738_triggered {
	meta: description = "Rule # 738 Suspicious String REVO HAS B33N B4CK triggered"
	strings: $suspicious_string = "REVO HAS B33N B4CK"
	condition: $suspicious_string
}
rule Rule_739_triggered {
	meta: description = "Rule # 739 Suspicious String REVO SHELL triggered"
	strings: $suspicious_string = "REVO SHELL"
	condition: $suspicious_string
}
rule Rule_740_triggered {
	meta: description = "Rule # 740 Suspicious String ROOTSHELL triggered"
	strings: $suspicious_string = "ROOTSHELL"
	condition: $suspicious_string
}
rule Rule_741_triggered {
	meta: description = "Rule # 741 Suspicious String ROOTTN triggered"
	strings: $suspicious_string = "ROOTTN"
	condition: $suspicious_string
}
rule Rule_742_triggered {
	meta: description = "Rule # 742 Suspicious String Raj bhai ji triggered"
	strings: $suspicious_string = "Raj bhai ji"
	condition: $suspicious_string
}
rule Rule_743_triggered {
	meta: description = "Rule # 743 Suspicious String Re-Modified by  triggered"
	strings: $suspicious_string = "Re-Modified by "
	condition: $suspicious_string
}
rule Rule_744_triggered {
	meta: description = "Rule # 744 Suspicious String ReZulT triggered"
	strings: $suspicious_string = "ReZulT"
	condition: $suspicious_string
}
rule Rule_745_triggered {
	meta: description = "Rule # 745 Suspicious String Reborn India triggered"
	strings: $suspicious_string = "Reborn India"
	condition: $suspicious_string
}
rule Rule_746_triggered {
	meta: description = "Rule # 746 Suspicious String Recoded By XGHoSTn triggered"
	strings: $suspicious_string = "Recoded By XGHoSTn"
	condition: $suspicious_string
}
rule Rule_747_triggered {
	meta: description = "Rule # 747 Suspicious String Recovery Email Address: triggered"
	strings: $suspicious_string = "Recovery Email Address:"
	condition: $suspicious_string
}
rule Rule_748_triggered {
	meta: description = "Rule # 748 Suspicious String Red Warrior triggered"
	strings: $suspicious_string = "Red Warrior"
	condition: $suspicious_string
}
rule Rule_749_triggered {
	meta: description = "Rule # 749 Suspicious String Red X triggered"
	strings: $suspicious_string = "Red X"
	condition: $suspicious_string
}
rule Rule_750_triggered {
	meta: description = "Rule # 750 Suspicious String Remote Code Execution Exploit triggered"
	strings: $suspicious_string = "Remote Code Execution Exploit"
	condition: $suspicious_string
}
rule Rule_751_triggered {
	meta: description = "Rule # 751 Suspicious String Retarol triggered"
	strings: $suspicious_string = "Retarol"
	condition: $suspicious_string
}
rule Rule_752_triggered {
	meta: description = "Rule # 752 Suspicious String Rg0d triggered"
	strings: $suspicious_string = "Rg0d"
	condition: $suspicious_string
}
rule Rule_753_triggered {
	meta: description = "Rule # 753 Suspicious String Rifqyajx triggered"
	strings: $suspicious_string = "Rifqyajx"
	condition: $suspicious_string
}
rule Rule_754_triggered {
	meta: description = "Rule # 754 Suspicious String Rinto AR  triggered"
	strings: $suspicious_string = "Rinto AR "
	condition: $suspicious_string
}
rule Rule_755_triggered {
	meta: description = "Rule # 755 Suspicious String Rizi_haxor triggered"
	strings: $suspicious_string = "Rizi_haxor"
	condition: $suspicious_string
}
rule Rule_756_triggered {
	meta: description = "Rule # 756 Suspicious String Rizky21ID triggered"
	strings: $suspicious_string = "Rizky21ID"
	condition: $suspicious_string
}
rule Rule_757_triggered {
	meta: description = "Rule # 757 Suspicious String Robot Pirates triggered"
	strings: $suspicious_string = "Robot Pirates"
	condition: $suspicious_string
}
rule Rule_758_triggered {
	meta: description = "Rule # 758 Suspicious String Romanian Security Team triggered"
	strings: $suspicious_string = "Romanian Security Team"
	condition: $suspicious_string
}
rule Rule_759_triggered {
	meta: description = "Rule # 759 Suspicious String RooTTn & REV! triggered"
	strings: $suspicious_string = "RooTTn & REV!"
	condition: $suspicious_string
}
rule Rule_760_triggered {
	meta: description = "Rule # 760 Suspicious String Ryan Duff and Firas Durri triggered"
	strings: $suspicious_string = "Ryan Duff and Firas Durri"
	condition: $suspicious_string
}
rule Rule_761_triggered {
	meta: description = "Rule # 761 Suspicious String S-Man triggered"
	strings: $suspicious_string = "S-Man"
	condition: $suspicious_string
}
rule Rule_762_triggered {
	meta: description = "Rule # 762 Suspicious String S4!Lh34t triggered"
	strings: $suspicious_string = "S4!Lh34t"
	condition: $suspicious_string
}
rule Rule_763_triggered {
	meta: description = "Rule # 763 Suspicious String S4MP4H triggered"
	strings: $suspicious_string = "S4MP4H"
	condition: $suspicious_string
}
rule Rule_764_triggered {
	meta: description = "Rule # 764 Suspicious String SAMPAH triggered"
	strings: $suspicious_string = "SAMPAH"
	condition: $suspicious_string
}
rule Rule_765_triggered {
	meta: description = "Rule # 765 Suspicious String SCAM PAGE PPL V5 triggered"
	strings: $suspicious_string = "SCAM PAGE PPL V5"
	condition: $suspicious_string
}
rule Rule_766_triggered {
	meta: description = "Rule # 766 Suspicious String SCAM PAYPAL triggered"
	strings: $suspicious_string = "SCAM PAYPAL"
	condition: $suspicious_string
}
rule Rule_767_triggered {
	meta: description = "Rule # 767 Suspicious String SCAMA triggered"
	strings: $suspicious_string = "SCAMA"
	condition: $suspicious_string
}
rule Rule_768_triggered {
	meta: description = "Rule # 768 Suspicious String SCYTHE404_LOL triggered"
	strings: $suspicious_string = "SCYTHE404_LOL"
	condition: $suspicious_string
}
rule Rule_769_triggered {
	meta: description = "Rule # 769 Suspicious String SHADOW Z118 triggered"
	strings: $suspicious_string = "SHADOW Z118"
	condition: $suspicious_string
}
rule Rule_770_triggered {
	meta: description = "Rule # 770 Suspicious String SILVER FOX triggered"
	strings: $suspicious_string = "SILVER FOX"
	condition: $suspicious_string
}
rule Rule_771_triggered {
	meta: description = "Rule # 771 Suspicious String SKSking triggered"
	strings: $suspicious_string = "SKSking"
	condition: $suspicious_string
}
rule Rule_772_triggered {
	meta: description = "Rule # 772 Suspicious String SMTP Grabber triggered"
	strings: $suspicious_string = "SMTP Grabber"
	condition: $suspicious_string
}
rule Rule_773_triggered {
	meta: description = "Rule # 773 Suspicious String SNMP cracker triggered"
	strings: $suspicious_string = "SNMP cracker"
	condition: $suspicious_string
}
rule Rule_774_triggered {
	meta: description = "Rule # 774 Suspicious String SQL CMD 3.0 | al-swisre triggered"
	strings: $suspicious_string = "SQL CMD 3.0 | al-swisre"
	condition: $suspicious_string
}
rule Rule_775_triggered {
	meta: description = "Rule # 775 Suspicious String SQL_CMD 3.0 by al-swisre triggered"
	strings: $suspicious_string = "SQL_CMD 3.0 by al-swisre"
	condition: $suspicious_string
}
rule Rule_776_triggered {
	meta: description = "Rule # 776 Suspicious String SQli 1.0 Exploiter  triggered"
	strings: $suspicious_string = "SQli 1.0 Exploiter "
	condition: $suspicious_string
}
rule Rule_777_triggered {
	meta: description = "Rule # 777 Suspicious String SUNUCU HAKKINDA triggered"
	strings: $suspicious_string = "SUNUCU HAKKINDA"
	condition: $suspicious_string
}
rule Rule_778_triggered {
	meta: description = "Rule # 778 Suspicious String SYMLINKER BY GRAY BYTE triggered"
	strings: $suspicious_string = "SYMLINKER BY GRAY BYTE"
	condition: $suspicious_string
}
rule Rule_779_triggered {
	meta: description = "Rule # 779 Suspicious String SaM Shell triggered"
	strings: $suspicious_string = "SaM Shell"
	condition: $suspicious_string
}
rule Rule_780_triggered {
	meta: description = "Rule # 780 Suspicious String SaTtAr triggered"
	strings: $suspicious_string = "SaTtAr"
	condition: $suspicious_string
}
rule Rule_781_triggered {
	meta: description = "Rule # 781 Suspicious String Sadrazam SHELL triggered"
	strings: $suspicious_string = "Sadrazam SHELL"
	condition: $suspicious_string
}
rule Rule_782_triggered {
	meta: description = "Rule # 782 Suspicious String SahaainG triggered"
	strings: $suspicious_string = "SahaainG"
	condition: $suspicious_string
}
rule Rule_783_triggered {
	meta: description = "Rule # 783 Suspicious String Saliy Tool triggered"
	strings: $suspicious_string = "Saliy Tool"
	condition: $suspicious_string
}
rule Rule_784_triggered {
	meta: description = "Rule # 784 Suspicious String Sanjungan Jiwa Team triggered"
	strings: $suspicious_string = "Sanjungan Jiwa Team"
	condition: $suspicious_string
}
rule Rule_785_triggered {
	meta: description = "Rule # 785 Suspicious String Saudi Attacker triggered"
	strings: $suspicious_string = "Saudi Attacker"
	condition: $suspicious_string
}
rule Rule_786_triggered {
	meta: description = "Rule # 786 Suspicious String Say To Safemode Go To HeLl By php.ini triggered"
	strings: $suspicious_string = "Say To Safemode Go To HeLl By php.ini"
	condition: $suspicious_string
}
rule Rule_787_triggered {
	meta: description = "Rule # 787 Suspicious String ScarleT7 triggered"
	strings: $suspicious_string = "ScarleT7"
	condition: $suspicious_string
}
rule Rule_788_triggered {
	meta: description = "Rule # 788 Suspicious String Scorpiol triggered"
	strings: $suspicious_string = "Scorpiol"
	condition: $suspicious_string
}
rule Rule_789_triggered {
	meta: description = "Rule # 789 Suspicious String Script Resetpass CP triggered"
	strings: $suspicious_string = "Script Resetpass CP"
	condition: $suspicious_string
}
rule Rule_790_triggered {
	meta: description = "Rule # 790 Suspicious String Sec BY Jonior.com triggered"
	strings: $suspicious_string = "Sec BY Jonior.com"
	condition: $suspicious_string
}
rule Rule_791_triggered {
	meta: description = "Rule # 791 Suspicious String Secsion<infos@hacker_Shenzen> triggered"
	strings: $suspicious_string = "Secsion<infos@hacker_Shenzen>"
	condition: $suspicious_string
}
rule Rule_792_triggered {
	meta: description = "Rule # 792 Suspicious String Security Angel Team [S4T] triggered"
	strings: $suspicious_string = "Security Angel Team [S4T]"
	condition: $suspicious_string
}
rule Rule_793_triggered {
	meta: description = "Rule # 793 Suspicious String Security Cyber Art triggered"
	strings: $suspicious_string = "Security Cyber Art"
	condition: $suspicious_string
}
rule Rule_794_triggered {
	meta: description = "Rule # 794 Suspicious String Security Ghost triggered"
	strings: $suspicious_string = "Security Ghost"
	condition: $suspicious_string
}
rule Rule_795_triggered {
	meta: description = "Rule # 795 Suspicious String SecurityBus triggered"
	strings: $suspicious_string = "SecurityBus"
	condition: $suspicious_string
}
rule Rule_796_triggered {
	meta: description = "Rule # 796 Suspicious String Setor PP Boz triggered"
	strings: $suspicious_string = "Setor PP Boz"
	condition: $suspicious_string
}
rule Rule_797_triggered {
	meta: description = "Rule # 797 Suspicious String Sh4hien triggered"
	strings: $suspicious_string = "Sh4hien"
	condition: $suspicious_string
}
rule Rule_798_triggered {
	meta: description = "Rule # 798 Suspicious String Shalyse triggered"
	strings: $suspicious_string = "Shalyse"
	condition: $suspicious_string
}
rule Rule_799_triggered {
	meta: description = "Rule # 799 Suspicious String Shardhanand triggered"
	strings: $suspicious_string = "Shardhanand"
	condition: $suspicious_string
}
rule Rule_800_triggered {
	meta: description = "Rule # 800 Suspicious String Sheko H4CK3R triggered"
	strings: $suspicious_string = "Sheko H4CK3R"
	condition: $suspicious_string
}
rule Rule_801_triggered {
	meta: description = "Rule # 801 Suspicious String Shell Accessed!!! triggered"
	strings: $suspicious_string = "Shell Accessed!!!"
	condition: $suspicious_string
}
rule Rule_802_triggered {
	meta: description = "Rule # 802 Suspicious String Shell Checker triggered"
	strings: $suspicious_string = "Shell Checker"
	condition: $suspicious_string
}
rule Rule_803_triggered {
	meta: description = "Rule # 803 Suspicious String Shell Finder triggered"
	strings: $suspicious_string = "Shell Finder"
	condition: $suspicious_string
}
rule Rule_804_triggered {
	meta: description = "Rule # 804 Suspicious String Shell Recoded From IndoXploit Shell triggered"
	strings: $suspicious_string = "Shell Recoded From IndoXploit Shell"
	condition: $suspicious_string
}
rule Rule_805_triggered {
	meta: description = "Rule # 805 Suspicious String ShinChan triggered"
	strings: $suspicious_string = "ShinChan"
	condition: $suspicious_string
}
rule Rule_806_triggered {
	meta: description = "Rule # 806 Suspicious String ShinChan     triggered"
	strings: $suspicious_string = "ShinChan    "
	condition: $suspicious_string
}
rule Rule_807_triggered {
	meta: description = "Rule # 807 Suspicious String Shindex404     triggered"
	strings: $suspicious_string = "Shindex404    "
	condition: $suspicious_string
}
rule Rule_808_triggered {
	meta: description = "Rule # 808 Suspicious String Shut_Down404  triggered"
	strings: $suspicious_string = "Shut_Down404 "
	condition: $suspicious_string
}
rule Rule_809_triggered {
	meta: description = "Rule # 809 Suspicious String Silent poison India triggered"
	strings: $suspicious_string = "Silent poison India"
	condition: $suspicious_string
}
rule Rule_810_triggered {
	meta: description = "Rule # 810 Suspicious String Siliwangi triggered"
	strings: $suspicious_string = "Siliwangi"
	condition: $suspicious_string
}
rule Rule_811_triggered {
	meta: description = "Rule # 811 Suspicious String Siluman nanas triggered"
	strings: $suspicious_string = "Siluman nanas"
	condition: $suspicious_string
}
rule Rule_812_triggered {
	meta: description = "Rule # 812 Suspicious String Skidie Khan triggered"
	strings: $suspicious_string = "Skidie Khan"
	condition: $suspicious_string
}
rule Rule_813_triggered {
	meta: description = "Rule # 813 Suspicious String Something is wrong. Download - IS NOT OK triggered"
	strings: $suspicious_string = "Something is wrong. Download - IS NOT OK"
	condition: $suspicious_string
}
rule Rule_814_triggered {
	meta: description = "Rule # 814 Suspicious String Special Thanks To MadLeets triggered"
	strings: $suspicious_string = "Special Thanks To MadLeets"
	condition: $suspicious_string
}
rule Rule_815_triggered {
	meta: description = "Rule # 815 Suspicious String SpecimenT triggered"
	strings: $suspicious_string = "SpecimenT"
	condition: $suspicious_string
}
rule Rule_816_triggered {
	meta: description = "Rule # 816 Suspicious String Spirit Hunder triggered"
	strings: $suspicious_string = "Spirit Hunder"
	condition: $suspicious_string
}
rule Rule_817_triggered {
	meta: description = "Rule # 817 Suspicious String SpyHackerz.Com triggered"
	strings: $suspicious_string = "SpyHackerz.Com"
	condition: $suspicious_string
}
rule Rule_818_triggered {
	meta: description = "Rule # 818 Suspicious String Spyk1r4 triggered"
	strings: $suspicious_string = "Spyk1r4"
	condition: $suspicious_string
}
rule Rule_819_triggered {
	meta: description = "Rule # 819 Suspicious String Stealth MultiFunctional IrcBot writen in Perl triggered"
	strings: $suspicious_string = "Stealth MultiFunctional IrcBot writen in Perl"
	condition: $suspicious_string
}
rule Rule_820_triggered {
	meta: description = "Rule # 820 Suspicious String Stealth Shellbot triggered"
	strings: $suspicious_string = "Stealth Shellbot"
	condition: $suspicious_string
}
rule Rule_821_triggered {
	meta: description = "Rule # 821 Suspicious String Stm Nazie 102 triggered"
	strings: $suspicious_string = "Stm Nazie 102"
	condition: $suspicious_string
}
rule Rule_822_triggered {
	meta: description = "Rule # 822 Suspicious String Stupidc0de Family triggered"
	strings: $suspicious_string = "Stupidc0de Family"
	condition: $suspicious_string
}
rule Rule_823_triggered {
	meta: description = "Rule # 823 Suspicious String SuLiMaN.HackeR triggered"
	strings: $suspicious_string = "SuLiMaN.HackeR"
	condition: $suspicious_string
}
rule Rule_824_triggered {
	meta: description = "Rule # 824 Suspicious String Success Upload :D triggered"
	strings: $suspicious_string = "Success Upload :D"
	condition: $suspicious_string
}
rule Rule_825_triggered {
	meta: description = "Rule # 825 Suspicious String Successfully R00T(ed) triggered"
	strings: $suspicious_string = "Successfully R00T(ed)"
	condition: $suspicious_string
}
rule Rule_826_triggered {
	meta: description = "Rule # 826 Suspicious String Sukses Deface triggered"
	strings: $suspicious_string = "Sukses Deface"
	condition: $suspicious_string
}
rule Rule_827_triggered {
	meta: description = "Rule # 827 Suspicious String SultanHaikal triggered"
	strings: $suspicious_string = "SultanHaikal"
	condition: $suspicious_string
}
rule Rule_828_triggered {
	meta: description = "Rule # 828 Suspicious String Suç İşleyeceksen Sanat'a Çevir triggered"
	strings: $suspicious_string = "Suç İşleyeceksen Sanat'a Çevir"
	condition: $suspicious_string
}
rule Rule_829_triggered {
	meta: description = "Rule # 829 Suspicious String Sy-Hacker triggered"
	strings: $suspicious_string = "Sy-Hacker"
	condition: $suspicious_string
}
rule Rule_830_triggered {
	meta: description = "Rule # 830 Suspicious String Symlink Based Cpanel Cracker triggered"
	strings: $suspicious_string = "Symlink Based Cpanel Cracker"
	condition: $suspicious_string
}
rule Rule_831_triggered {
	meta: description = "Rule # 831 Suspicious String Symlink ByPass triggered"
	strings: $suspicious_string = "Symlink ByPass"
	condition: $suspicious_string
}
rule Rule_832_triggered {
	meta: description = "Rule # 832 Suspicious String Symlink Bypass 2014 by Faisal 1337 triggered"
	strings: $suspicious_string = "Symlink Bypass 2014 by Faisal 1337"
	condition: $suspicious_string
}
rule Rule_833_triggered {
	meta: description = "Rule # 833 Suspicious String Symlink Config Graber triggered"
	strings: $suspicious_string = "Symlink Config Graber"
	condition: $suspicious_string
}
rule Rule_834_triggered {
	meta: description = "Rule # 834 Suspicious String Symlink based cpanel cracking triggered"
	strings: $suspicious_string = "Symlink based cpanel cracking"
	condition: $suspicious_string
}
rule Rule_835_triggered {
	meta: description = "Rule # 835 Suspicious String Syntax-True triggered"
	strings: $suspicious_string = "Syntax-True"
	condition: $suspicious_string
}
rule Rule_836_triggered {
	meta: description = "Rule # 836 Suspicious String SyntaxNotFound triggered"
	strings: $suspicious_string = "SyntaxNotFound"
	condition: $suspicious_string
}
rule Rule_837_triggered {
	meta: description = "Rule # 837 Suspicious String SystemX64MGB  triggered"
	strings: $suspicious_string = "SystemX64MGB "
	condition: $suspicious_string
}
rule Rule_838_triggered {
	meta: description = "Rule # 838 Suspicious String T1KUS90T triggered"
	strings: $suspicious_string = "T1KUS90T"
	condition: $suspicious_string
}
rule Rule_839_triggered {
	meta: description = "Rule # 839 Suspicious String TC9A16C47DA8EEE87 triggered"
	strings: $suspicious_string = "TC9A16C47DA8EEE87"
	condition: $suspicious_string
}
rule Rule_840_triggered {
	meta: description = "Rule # 840 Suspicious String THA Disastar triggered"
	strings: $suspicious_string = "THA Disastar"
	condition: $suspicious_string
}
rule Rule_841_triggered {
	meta: description = "Rule # 841 Suspicious String TKJ Cyber Art triggered"
	strings: $suspicious_string = "TKJ Cyber Art"
	condition: $suspicious_string
}
rule Rule_842_triggered {
	meta: description = "Rule # 842 Suspicious String TOBILOBA triggered"
	strings: $suspicious_string = "TOBILOBA"
	condition: $suspicious_string
}
rule Rule_843_triggered {
	meta: description = "Rule # 843 Suspicious String Tak Ada Kata triggered"
	strings: $suspicious_string = "Tak Ada Kata"
	condition: $suspicious_string
}
rule Rule_844_triggered {
	meta: description = "Rule # 844 Suspicious String TanpaNama404  triggered"
	strings: $suspicious_string = "TanpaNama404 "
	condition: $suspicious_string
}
rule Rule_845_triggered {
	meta: description = "Rule # 845 Suspicious String Tapi Selebihnya triggered"
	strings: $suspicious_string = "Tapi Selebihnya"
	condition: $suspicious_string
}
rule Rule_846_triggered {
	meta: description = "Rule # 846 Suspicious String Tata ReZulT triggered"
	strings: $suspicious_string = "Tata ReZulT"
	condition: $suspicious_string
}
rule Rule_847_triggered {
	meta: description = "Rule # 847 Suspicious String Tatsumi Crew triggered"
	strings: $suspicious_string = "Tatsumi Crew"
	condition: $suspicious_string
}
rule Rule_848_triggered {
	meta: description = "Rule # 848 Suspicious String Tchix triggered"
	strings: $suspicious_string = "Tchix"
	condition: $suspicious_string
}
rule Rule_849_triggered {
	meta: description = "Rule # 849 Suspicious String TeaM HacKer EgypT triggered"
	strings: $suspicious_string = "TeaM HacKer EgypT"
	condition: $suspicious_string
}
rule Rule_850_triggered {
	meta: description = "Rule # 850 Suspicious String TeaM System Dz triggered"
	strings: $suspicious_string = "TeaM System Dz"
	condition: $suspicious_string
}
rule Rule_851_triggered {
	meta: description = "Rule # 851 Suspicious String Team Arena triggered"
	strings: $suspicious_string = "Team Arena"
	condition: $suspicious_string
}
rule Rule_852_triggered {
	meta: description = "Rule # 852 Suspicious String Team BlackLeets triggered"
	strings: $suspicious_string = "Team BlackLeets"
	condition: $suspicious_string
}
rule Rule_853_triggered {
	meta: description = "Rule # 853 Suspicious String Team IndiShell triggered"
	strings: $suspicious_string = "Team IndiShell"
	condition: $suspicious_string
}
rule Rule_854_triggered {
	meta: description = "Rule # 854 Suspicious String Team_CC triggered"
	strings: $suspicious_string = "Team_CC"
	condition: $suspicious_string
}
rule Rule_855_triggered {
	meta: description = "Rule # 855 Suspicious String Teamp0ison triggered"
	strings: $suspicious_string = "Teamp0ison"
	condition: $suspicious_string
}
rule Rule_856_triggered {
	meta: description = "Rule # 856 Suspicious String Tersakti triggered"
	strings: $suspicious_string = "Tersakti"
	condition: $suspicious_string
}
rule Rule_857_triggered {
	meta: description = "Rule # 857 Suspicious String Th3 D3str0yer triggered"
	strings: $suspicious_string = "Th3 D3str0yer"
	condition: $suspicious_string
}
rule Rule_858_triggered {
	meta: description = "Rule # 858 Suspicious String Th3 K!LL3r Dz triggered"
	strings: $suspicious_string = "Th3 K!LL3r Dz"
	condition: $suspicious_string
}
rule Rule_859_triggered {
	meta: description = "Rule # 859 Suspicious String Th3 K!ng Scam triggered"
	strings: $suspicious_string = "Th3 K!ng Scam"
	condition: $suspicious_string
}
rule Rule_860_triggered {
	meta: description = "Rule # 860 Suspicious String Thanks Buat Yg Udh Support Buat Shell Ini triggered"
	strings: $suspicious_string = "Thanks Buat Yg Udh Support Buat Shell Ini"
	condition: $suspicious_string
}
rule Rule_861_triggered {
	meta: description = "Rule # 861 Suspicious String Thanks To Brothers V!rus YassCom triggered"
	strings: $suspicious_string = "Thanks To Brothers V!rus YassCom"
	condition: $suspicious_string
}
rule Rule_862_triggered {
	meta: description = "Rule # 862 Suspicious String Thats Good lemme try triggered"
	strings: $suspicious_string = "Thats Good lemme try"
	condition: $suspicious_string
}
rule Rule_863_triggered {
	meta: description = "Rule # 863 Suspicious String The Cyber Heroez White-Hat Crew triggered"
	strings: $suspicious_string = "The Cyber Heroez White-Hat Crew"
	condition: $suspicious_string
}
rule Rule_864_triggered {
	meta: description = "Rule # 864 Suspicious String The Next JanCox Shell triggered"
	strings: $suspicious_string = "The Next JanCox Shell"
	condition: $suspicious_string
}
rule Rule_865_triggered {
	meta: description = "Rule # 865 Suspicious String The Scam is 100% Clean Undetected Forever triggered"
	strings: $suspicious_string = "The Scam is 100% Clean Undetected Forever"
	condition: $suspicious_string
}
rule Rule_866_triggered {
	meta: description = "Rule # 866 Suspicious String The file you want Downloadable was nonexistent triggered"
	strings: $suspicious_string = "The file you want Downloadable was nonexistent"
	condition: $suspicious_string
}
rule Rule_867_triggered {
	meta: description = "Rule # 867 Suspicious String The r600 mailer has finished his job triggered"
	strings: $suspicious_string = "The r600 mailer has finished his job"
	condition: $suspicious_string
}
rule Rule_868_triggered {
	meta: description = "Rule # 868 Suspicious String TheChozen triggered"
	strings: $suspicious_string = "TheChozen"
	condition: $suspicious_string
}
rule Rule_869_triggered {
	meta: description = "Rule # 869 Suspicious String TheLords triggered"
	strings: $suspicious_string = "TheLords"
	condition: $suspicious_string
}
rule Rule_870_triggered {
	meta: description = "Rule # 870 Suspicious String Tn-ViRus triggered"
	strings: $suspicious_string = "Tn-ViRus"
	condition: $suspicious_string
}
rule Rule_871_triggered {
	meta: description = "Rule # 871 Suspicious String Tn.SkullCyber triggered"
	strings: $suspicious_string = "Tn.SkullCyber"
	condition: $suspicious_string
}
rule Rule_872_triggered {
	meta: description = "Rule # 872 Suspicious String To known the password, you must first send triggered"
	strings: $suspicious_string = "To known the password, you must first send"
	condition: $suspicious_string
}
rule Rule_873_triggered {
	meta: description = "Rule # 873 Suspicious String TobaSec triggered"
	strings: $suspicious_string = "TobaSec"
	condition: $suspicious_string
}
rule Rule_874_triggered {
	meta: description = "Rule # 874 Suspicious String TobaSec  triggered"
	strings: $suspicious_string = "TobaSec "
	condition: $suspicious_string
}
rule Rule_875_triggered {
	meta: description = "Rule # 875 Suspicious String Tools Carder triggered"
	strings: $suspicious_string = "Tools Carder"
	condition: $suspicious_string
}
rule Rule_876_triggered {
	meta: description = "Rule # 876 Suspicious String Toxica DZ Was Here triggered"
	strings: $suspicious_string = "Toxica DZ Was Here"
	condition: $suspicious_string
}
rule Rule_877_triggered {
	meta: description = "Rule # 877 Suspicious String TrYaG triggered"
	strings: $suspicious_string = "TrYaG"
	condition: $suspicious_string
}
rule Rule_878_triggered {
	meta: description = "Rule # 878 Suspicious String Trickster triggered"
	strings: $suspicious_string = "Trickster"
	condition: $suspicious_string
}
rule Rule_879_triggered {
	meta: description = "Rule # 879 Suspicious String Triple A triggered"
	strings: $suspicious_string = "Triple A"
	condition: $suspicious_string
}
rule Rule_880_triggered {
	meta: description = "Rule # 880 Suspicious String True Login (via cURL) Scams triggered"
	strings: $suspicious_string = "True Login (via cURL) Scams"
	condition: $suspicious_string
}
rule Rule_881_triggered {
	meta: description = "Rule # 881 Suspicious String Tryag File Manager triggered"
	strings: $suspicious_string = "Tryag File Manager"
	condition: $suspicious_string
}
rule Rule_882_triggered {
	meta: description = "Rule # 882 Suspicious String Tu5b0l3d triggered"
	strings: $suspicious_string = "Tu5b0l3d"
	condition: $suspicious_string
}
rule Rule_883_triggered {
	meta: description = "Rule # 883 Suspicious String Tu5b0l3d     triggered"
	strings: $suspicious_string = "Tu5b0l3d    "
	condition: $suspicious_string
}
rule Rule_884_triggered {
	meta: description = "Rule # 884 Suspicious String Tuan_galau  triggered"
	strings: $suspicious_string = "Tuan_galau "
	condition: $suspicious_string
}
rule Rule_885_triggered {
	meta: description = "Rule # 885 Suspicious String Tunisian HaCker triggered"
	strings: $suspicious_string = "Tunisian HaCker"
	condition: $suspicious_string
}
rule Rule_886_triggered {
	meta: description = "Rule # 886 Suspicious String Turbo Force By TrYaG.CC triggered"
	strings: $suspicious_string = "Turbo Force By TrYaG.CC"
	condition: $suspicious_string
}
rule Rule_887_triggered {
	meta: description = "Rule # 887 Suspicious String Tuyul Gaul Team  triggered"
	strings: $suspicious_string = "Tuyul Gaul Team "
	condition: $suspicious_string
}
rule Rule_888_triggered {
	meta: description = "Rule # 888 Suspicious String T�x�� Ph��t�m triggered"
	strings: $suspicious_string = "T�x�� Ph��t�m"
	condition: $suspicious_string
}
rule Rule_889_triggered {
	meta: description = "Rule # 889 Suspicious String U7TiM4T3 H4x0R triggered"
	strings: $suspicious_string = "U7TiM4T3 H4x0R"
	condition: $suspicious_string
}
rule Rule_890_triggered {
	meta: description = "Rule # 890 Suspicious String UDP DDoSing triggered"
	strings: $suspicious_string = "UDP DDoSing"
	condition: $suspicious_string
}
rule Rule_891_triggered {
	meta: description = "Rule # 891 Suspicious String UNDERGROUND HACKERS triggered"
	strings: $suspicious_string = "UNDERGROUND HACKERS"
	condition: $suspicious_string
}
rule Rule_892_triggered {
	meta: description = "Rule # 892 Suspicious String UP=\"pentagon\" triggered"
	strings: $suspicious_string = "UP=\"pentagon\""
	condition: $suspicious_string
}
rule Rule_893_triggered {
	meta: description = "Rule # 893 Suspicious String United Bangladeshi Hackers triggered"
	strings: $suspicious_string = "United Bangladeshi Hackers"
	condition: $suspicious_string
}
rule Rule_894_triggered {
	meta: description = "Rule # 894 Suspicious String UnkCrew triggered"
	strings: $suspicious_string = "UnkCrew"
	condition: $suspicious_string
}
rule Rule_895_triggered {
	meta: description = "Rule # 895 Suspicious String Upl04d3r triggered"
	strings: $suspicious_string = "Upl04d3r"
	condition: $suspicious_string
}
rule Rule_896_triggered {
	meta: description = "Rule # 896 Suspicious String Upload Fail !!! triggered"
	strings: $suspicious_string = "Upload Fail !!!"
	condition: $suspicious_string
}
rule Rule_897_triggered {
	meta: description = "Rule # 897 Suspicious String Upload Shell Korang triggered"
	strings: $suspicious_string = "Upload Shell Korang"
	condition: $suspicious_string
}
rule Rule_898_triggered {
	meta: description = "Rule # 898 Suspicious String Upload Success !!! triggered"
	strings: $suspicious_string = "Upload Success !!!"
	condition: $suspicious_string
}
rule Rule_899_triggered {
	meta: description = "Rule # 899 Suspicious String Uploader By Psyco! triggered"
	strings: $suspicious_string = "Uploader By Psyco!"
	condition: $suspicious_string
}
rule Rule_900_triggered {
	meta: description = "Rule # 900 Suspicious String Use this function to check in witch domain zones user comes triggered"
	strings: $suspicious_string = "Use this function to check in witch domain zones user comes"
	condition: $suspicious_string
}
rule Rule_901_triggered {
	meta: description = "Rule # 901 Suspicious String UseYourBrain triggered"
	strings: $suspicious_string = "UseYourBrain"
	condition: $suspicious_string
}
rule Rule_902_triggered {
	meta: description = "Rule # 902 Suspicious String UseYourDream triggered"
	strings: $suspicious_string = "UseYourDream"
	condition: $suspicious_string
}
rule Rule_903_triggered {
	meta: description = "Rule # 903 Suspicious String V3rluchie triggered"
	strings: $suspicious_string = "V3rluchie"
	condition: $suspicious_string
}
rule Rule_904_triggered {
	meta: description = "Rule # 904 Suspicious String VERSION mIRC version by LaNTaK GaNTeNG triggered"
	strings: $suspicious_string = "VERSION mIRC version by LaNTaK GaNTeNG"
	condition: $suspicious_string
}
rule Rule_905_triggered {
	meta: description = "Rule # 905 Suspicious String VIRUSX triggered"
	strings: $suspicious_string = "VIRUSX"
	condition: $suspicious_string
}
rule Rule_906_triggered {
	meta: description = "Rule # 906 Suspicious String VISA_DYALNA triggered"
	strings: $suspicious_string = "VISA_DYALNA"
	condition: $suspicious_string
}
rule Rule_907_triggered {
	meta: description = "Rule # 907 Suspicious String VNC ScaNNer by ARZ triggered"
	strings: $suspicious_string = "VNC ScaNNer by ARZ"
	condition: $suspicious_string
}
rule Rule_908_triggered {
	meta: description = "Rule # 908 Suspicious String ViKi  triggered"
	strings: $suspicious_string = "ViKi "
	condition: $suspicious_string
}
rule Rule_909_triggered {
	meta: description = "Rule # 909 Suspicious String ViRuS702 triggered"
	strings: $suspicious_string = "ViRuS702"
	condition: $suspicious_string
}
rule Rule_910_triggered {
	meta: description = "Rule # 910 Suspicious String ViRusx triggered"
	strings: $suspicious_string = "ViRusx"
	condition: $suspicious_string
}
rule Rule_911_triggered {
	meta: description = "Rule # 911 Suspicious String Virusa Worm triggered"
	strings: $suspicious_string = "Virusa Worm"
	condition: $suspicious_string
}
rule Rule_912_triggered {
	meta: description = "Rule # 912 Suspicious String VrCy     triggered"
	strings: $suspicious_string = "VrCy    "
	condition: $suspicious_string
}
rule Rule_913_triggered {
	meta: description = "Rule # 913 Suspicious String Vrcy triggered"
	strings: $suspicious_string = "Vrcy"
	condition: $suspicious_string
}
rule Rule_914_triggered {
	meta: description = "Rule # 914 Suspicious String Vurdum mu Samari Oynar Gotunun Damari triggered"
	strings: $suspicious_string = "Vurdum mu Samari Oynar Gotunun Damari"
	condition: $suspicious_string
}
rule Rule_915_triggered {
	meta: description = "Rule # 915 Suspicious String W1R3 triggered"
	strings: $suspicious_string = "W1R3"
	condition: $suspicious_string
}
rule Rule_916_triggered {
	meta: description = "Rule # 916 Suspicious String W3lc0m3 M4st3r triggered"
	strings: $suspicious_string = "W3lc0m3 M4st3r"
	condition: $suspicious_string
}
rule Rule_917_triggered {
	meta: description = "Rule # 917 Suspicious String WHIT3 DR4G0N triggered"
	strings: $suspicious_string = "WHIT3 DR4G0N"
	condition: $suspicious_string
}
rule Rule_918_triggered {
	meta: description = "Rule # 918 Suspicious String WHMCS KILLER V3 CODED BY RAB3OUN triggered"
	strings: $suspicious_string = "WHMCS KILLER V3 CODED BY RAB3OUN"
	condition: $suspicious_string
}
rule Rule_919_triggered {
	meta: description = "Rule # 919 Suspicious String WHMCS Killer v3 Decoded By N!nj@ triggered"
	strings: $suspicious_string = "WHMCS Killer v3 Decoded By N!nj@"
	condition: $suspicious_string
}
rule Rule_920_triggered {
	meta: description = "Rule # 920 Suspicious String WORK HARD DREAM B!G triggered"
	strings: $suspicious_string = "WORK HARD DREAM B!G"
	condition: $suspicious_string
}
rule Rule_921_triggered {
	meta: description = "Rule # 921 Suspicious String WSO 2.1.5 triggered"
	strings: $suspicious_string = "WSO 2.1.5"
	condition: $suspicious_string
}
rule Rule_922_triggered {
	meta: description = "Rule # 922 Suspicious String WSO [2.6] triggered"
	strings: $suspicious_string = "WSO [2.6]"
	condition: $suspicious_string
}
rule Rule_923_triggered {
	meta: description = "Rule # 923 Suspicious String WSO r3coded by eX-Sh1Ne triggered"
	strings: $suspicious_string = "WSO r3coded by eX-Sh1Ne"
	condition: $suspicious_string
}
rule Rule_924_triggered {
	meta: description = "Rule # 924 Suspicious String WSOsetcookie triggered"
	strings: $suspicious_string = "WSOsetcookie"
	condition: $suspicious_string
}
rule Rule_925_triggered {
	meta: description = "Rule # 925 Suspicious String WScript.Shell triggered"
	strings: $suspicious_string = "WScript.Shell"
	condition: $suspicious_string
}
rule Rule_926_triggered {
	meta: description = "Rule # 926 Suspicious String Wa7sh Hacker triggered"
	strings: $suspicious_string = "Wa7sh Hacker"
	condition: $suspicious_string
}
rule Rule_927_triggered {
	meta: description = "Rule # 927 Suspicious String Walid Curva Nord triggered"
	strings: $suspicious_string = "Walid Curva Nord"
	condition: $suspicious_string
}
rule Rule_928_triggered {
	meta: description = "Rule # 928 Suspicious String Wayaw triggered"
	strings: $suspicious_string = "Wayaw"
	condition: $suspicious_string
}
rule Rule_929_triggered {
	meta: description = "Rule # 929 Suspicious String We Are Anonymous triggered"
	strings: $suspicious_string = "We Are Anonymous"
	condition: $suspicious_string
}
rule Rule_930_triggered {
	meta: description = "Rule # 930 Suspicious String We Are Bangladeshi Hacker triggered"
	strings: $suspicious_string = "We Are Bangladeshi Hacker"
	condition: $suspicious_string
}
rule Rule_931_triggered {
	meta: description = "Rule # 931 Suspicious String We Are Legion triggered"
	strings: $suspicious_string = "We Are Legion"
	condition: $suspicious_string
}
rule Rule_932_triggered {
	meta: description = "Rule # 932 Suspicious String We Are Royal Battler BD triggered"
	strings: $suspicious_string = "We Are Royal Battler BD"
	condition: $suspicious_string
}
rule Rule_933_triggered {
	meta: description = "Rule # 933 Suspicious String We Do not Forget triggered"
	strings: $suspicious_string = "We Do not Forget"
	condition: $suspicious_string
}
rule Rule_934_triggered {
	meta: description = "Rule # 934 Suspicious String We Do not Forgiv triggered"
	strings: $suspicious_string = "We Do not Forgiv"
	condition: $suspicious_string
}
rule Rule_935_triggered {
	meta: description = "Rule # 935 Suspicious String We aRe International Muslim Hacker Team triggered"
	strings: $suspicious_string = "We aRe International Muslim Hacker Team"
	condition: $suspicious_string
}
rule Rule_936_triggered {
	meta: description = "Rule # 936 Suspicious String We are Anonymous triggered"
	strings: $suspicious_string = "We are Anonymous"
	condition: $suspicious_string
}
rule Rule_937_triggered {
	meta: description = "Rule # 937 Suspicious String We are Legion triggered"
	strings: $suspicious_string = "We are Legion"
	condition: $suspicious_string
}
rule Rule_938_triggered {
	meta: description = "Rule # 938 Suspicious String We do not Forget triggered"
	strings: $suspicious_string = "We do not Forget"
	condition: $suspicious_string
}
rule Rule_939_triggered {
	meta: description = "Rule # 939 Suspicious String We do not Forgive triggered"
	strings: $suspicious_string = "We do not Forgive"
	condition: $suspicious_string
}
rule Rule_940_triggered {
	meta: description = "Rule # 940 Suspicious String We make your security better by breaking it triggered"
	strings: $suspicious_string = "We make your security better by breaking it"
	condition: $suspicious_string
}
rule Rule_941_triggered {
	meta: description = "Rule # 941 Suspicious String We only wanna Mine triggered"
	strings: $suspicious_string = "We only wanna Mine"
	condition: $suspicious_string
}
rule Rule_942_triggered {
	meta: description = "Rule # 942 Suspicious String We will return as our ancestors did triggered"
	strings: $suspicious_string = "We will return as our ancestors did"
	condition: $suspicious_string
}
rule Rule_943_triggered {
	meta: description = "Rule # 943 Suspicious String Web Shell triggered"
	strings: $suspicious_string = "Web Shell"
	condition: $suspicious_string
}
rule Rule_944_triggered {
	meta: description = "Rule # 944 Suspicious String Web Shell by HARD _LINUX triggered"
	strings: $suspicious_string = "Web Shell by HARD _LINUX"
	condition: $suspicious_string
}
rule Rule_945_triggered {
	meta: description = "Rule # 945 Suspicious String WebShellOrb 2.6 - With PHP 7 triggered"
	strings: $suspicious_string = "WebShellOrb 2.6 - With PHP 7"
	condition: $suspicious_string
}
rule Rule_946_triggered {
	meta: description = "Rule # 946 Suspicious String Webmail Of Sellers triggered"
	strings: $suspicious_string = "Webmail Of Sellers"
	condition: $suspicious_string
}
rule Rule_947_triggered {
	meta: description = "Rule # 947 Suspicious String Webshell triggered"
	strings: $suspicious_string = "Webshell"
	condition: $suspicious_string
}
rule Rule_948_triggered {
	meta: description = "Rule # 948 Suspicious String WellsFargo Login Result triggered"
	strings: $suspicious_string = "WellsFargo Login Result"
	condition: $suspicious_string
}
rule Rule_949_triggered {
	meta: description = "Rule # 949 Suspicious String What is your favourite plac? triggered"
	strings: $suspicious_string = "What is your favourite plac?"
	condition: $suspicious_string
}
rule Rule_950_triggered {
	meta: description = "Rule # 950 Suspicious String Whcms Killer triggered"
	strings: $suspicious_string = "Whcms Killer"
	condition: $suspicious_string
}
rule Rule_951_triggered {
	meta: description = "Rule # 951 Suspicious String WordPress Auto Deface triggered"
	strings: $suspicious_string = "WordPress Auto Deface"
	condition: $suspicious_string
}
rule Rule_952_triggered {
	meta: description = "Rule # 952 Suspicious String Wordpress Csrf Exploit triggered"
	strings: $suspicious_string = "Wordpress Csrf Exploit"
	condition: $suspicious_string
}
rule Rule_953_triggered {
	meta: description = "Rule # 953 Suspicious String Wr0nG P4sSw0rD triggered"
	strings: $suspicious_string = "Wr0nG P4sSw0rD"
	condition: $suspicious_string
}
rule Rule_954_triggered {
	meta: description = "Rule # 954 Suspicious String Wscript.Shell triggered"
	strings: $suspicious_string = "Wscript.Shell"
	condition: $suspicious_string
}
rule Rule_955_triggered {
	meta: description = "Rule # 955 Suspicious String Wso1 SHELL triggered"
	strings: $suspicious_string = "Wso1 SHELL"
	condition: $suspicious_string
}
rule Rule_956_triggered {
	meta: description = "Rule # 956 Suspicious String WwW.Gaza-Hacker.NeT triggered"
	strings: $suspicious_string = "WwW.Gaza-Hacker.NeT"
	condition: $suspicious_string
}
rule Rule_957_triggered {
	meta: description = "Rule # 957 Suspicious String WwW.SeCuReDeAtH.cOm triggered"
	strings: $suspicious_string = "WwW.SeCuReDeAtH.cOm"
	condition: $suspicious_string
}
rule Rule_958_triggered {
	meta: description = "Rule # 958 Suspicious String X Attacker triggered"
	strings: $suspicious_string = "X Attacker"
	condition: $suspicious_string
}
rule Rule_959_triggered {
	meta: description = "Rule # 959 Suspicious String X-Blackerz INC. triggered"
	strings: $suspicious_string = "X-Blackerz INC."
	condition: $suspicious_string
}
rule Rule_960_triggered {
	meta: description = "Rule # 960 Suspicious String X-GHOST MA triggered"
	strings: $suspicious_string = "X-GHOST MA"
	condition: $suspicious_string
}
rule Rule_961_triggered {
	meta: description = "Rule # 961 Suspicious String X-Sn!p3r_P4l triggered"
	strings: $suspicious_string = "X-Sn!p3r_P4l"
	condition: $suspicious_string
}
rule Rule_962_triggered {
	meta: description = "Rule # 962 Suspicious String X-Wjdy triggered"
	strings: $suspicious_string = "X-Wjdy"
	condition: $suspicious_string
}
rule Rule_963_triggered {
	meta: description = "Rule # 963 Suspicious String X-Wu7z  triggered"
	strings: $suspicious_string = "X-Wu7z "
	condition: $suspicious_string
}
rule Rule_964_triggered {
	meta: description = "Rule # 964 Suspicious String X0blank@yahoo.com triggered"
	strings: $suspicious_string = "X0blank@yahoo.com"
	condition: $suspicious_string
}
rule Rule_965_triggered {
	meta: description = "Rule # 965 Suspicious String X3VzZXJfYWJ triggered"
	strings: $suspicious_string = "X3VzZXJfYWJ"
	condition: $suspicious_string
}
rule Rule_966_triggered {
	meta: description = "Rule # 966 Suspicious String XMRig triggered"
	strings: $suspicious_string = "XMRig"
	condition: $suspicious_string
}
rule Rule_967_triggered {
	meta: description = "Rule # 967 Suspicious String XXX~HACKER TEAM triggered"
	strings: $suspicious_string = "XXX~HACKER TEAM"
	condition: $suspicious_string
}
rule Rule_968_triggered {
	meta: description = "Rule # 968 Suspicious String XXX~HACKER TEAM WAS HERE triggered"
	strings: $suspicious_string = "XXX~HACKER TEAM WAS HERE"
	condition: $suspicious_string
}
rule Rule_969_triggered {
	meta: description = "Rule # 969 Suspicious String XaiSyndicate triggered"
	strings: $suspicious_string = "XaiSyndicate"
	condition: $suspicious_string
}
rule Rule_970_triggered {
	meta: description = "Rule # 970 Suspicious String Xalvadela  triggered"
	strings: $suspicious_string = "Xalvadela "
	condition: $suspicious_string
}
rule Rule_971_triggered {
	meta: description = "Rule # 971 Suspicious String Xaveroz_Tersakiti triggered"
	strings: $suspicious_string = "Xaveroz_Tersakiti"
	condition: $suspicious_string
}
rule Rule_972_triggered {
	meta: description = "Rule # 972 Suspicious String Xaveroz_Tersakiti  triggered"
	strings: $suspicious_string = "Xaveroz_Tersakiti "
	condition: $suspicious_string
}
rule Rule_973_triggered {
	meta: description = "Rule # 973 Suspicious String Xclusiv-3D-Logs triggered"
	strings: $suspicious_string = "Xclusiv-3D-Logs"
	condition: $suspicious_string
}
rule Rule_974_triggered {
	meta: description = "Rule # 974 Suspicious String XnonGremX triggered"
	strings: $suspicious_string = "XnonGremX"
	condition: $suspicious_string
}
rule Rule_975_triggered {
	meta: description = "Rule # 975 Suspicious String YAHOO 2015 triggered"
	strings: $suspicious_string = "YAHOO 2015"
	condition: $suspicious_string
}
rule Rule_976_triggered {
	meta: description = "Rule # 976 Suspicious String YAHOO.membership triggered"
	strings: $suspicious_string = "YAHOO.membership"
	condition: $suspicious_string
}
rule Rule_977_triggered {
	meta: description = "Rule # 977 Suspicious String YASSINOX CONFIG FUCKER triggered"
	strings: $suspicious_string = "YASSINOX CONFIG FUCKER"
	condition: $suspicious_string
}
rule Rule_978_triggered {
	meta: description = "Rule # 978 Suspicious String YaNaL-x Jo triggered"
	strings: $suspicious_string = "YaNaL-x Jo"
	condition: $suspicious_string
}
rule Rule_979_triggered {
	meta: description = "Rule # 979 Suspicious String YaSser Ma triggered"
	strings: $suspicious_string = "YaSser Ma"
	condition: $suspicious_string
}
rule Rule_980_triggered {
	meta: description = "Rule # 980 Suspicious String Yash triggered"
	strings: $suspicious_string = "Yash"
	condition: $suspicious_string
}
rule Rule_981_triggered {
	meta: description = "Rule # 981 Suspicious String Yazilimlar SHELL triggered"
	strings: $suspicious_string = "Yazilimlar SHELL"
	condition: $suspicious_string
}
rule Rule_982_triggered {
	meta: description = "Rule # 982 Suspicious String YeMeNi HaCkeR triggered"
	strings: $suspicious_string = "YeMeNi HaCkeR"
	condition: $suspicious_string
}
rule Rule_983_triggered {
	meta: description = "Rule # 983 Suspicious String Yet Another Miner by yvg1900 triggered"
	strings: $suspicious_string = "Yet Another Miner by yvg1900"
	condition: $suspicious_string
}
rule Rule_984_triggered {
	meta: description = "Rule # 984 Suspicious String You Security is very low triggered"
	strings: $suspicious_string = "You Security is very low"
	condition: $suspicious_string
}
rule Rule_985_triggered {
	meta: description = "Rule # 985 Suspicious String Your WebSite Got Boxed triggered"
	strings: $suspicious_string = "Your WebSite Got Boxed"
	condition: $suspicious_string
}
rule Rule_986_triggered {
	meta: description = "Rule # 986 Suspicious String Your data are encrypted triggered"
	strings: $suspicious_string = "Your data are encrypted"
	condition: $suspicious_string
}
rule Rule_987_triggered {
	meta: description = "Rule # 987 Suspicious String Yrid06  triggered"
	strings: $suspicious_string = "Yrid06 "
	condition: $suspicious_string
}
rule Rule_988_triggered {
	meta: description = "Rule # 988 Suspicious String ZETHA WEB SHELL triggered"
	strings: $suspicious_string = "ZETHA WEB SHELL"
	condition: $suspicious_string
}
rule Rule_989_triggered {
	meta: description = "Rule # 989 Suspicious String ZONE-H triggered"
	strings: $suspicious_string = "ZONE-H"
	condition: $suspicious_string
}
rule Rule_990_triggered {
	meta: description = "Rule # 990 Suspicious String ZWNobyAiPGI+Ii5waHBfdW5hbWUoKS4iPC9iPiI7IA0KZWNobyAiPGJy triggered"
	strings: $suspicious_string = "ZWNobyAiPGI+Ii5waHBfdW5hbWUoKS4iPC9iPiI7IA0KZWNobyAiPGJy"
	condition: $suspicious_string
}
rule Rule_991_triggered {
	meta: description = "Rule # 991 Suspicious String ZXJyb3JfcmVwb3J0aW5nKDApO triggered"
	strings: $suspicious_string = "ZXJyb3JfcmVwb3J0aW5nKDApO"
	condition: $suspicious_string
}
rule Rule_992_triggered {
	meta: description = "Rule # 992 Suspicious String ZakirDotId triggered"
	strings: $suspicious_string = "ZakirDotId"
	condition: $suspicious_string
}
rule Rule_993_triggered {
	meta: description = "Rule # 993 Suspicious String Zar0us triggered"
	strings: $suspicious_string = "Zar0us"
	condition: $suspicious_string
}
rule Rule_994_triggered {
	meta: description = "Rule # 994 Suspicious String ZeroBy7es triggered"
	strings: $suspicious_string = "ZeroBy7es"
	condition: $suspicious_string
}
rule Rule_995_triggered {
	meta: description = "Rule # 995 Suspicious String Zero_S triggered"
	strings: $suspicious_string = "Zero_S"
	condition: $suspicious_string
}
rule Rule_996_triggered {
	meta: description = "Rule # 996 Suspicious String Zetas Oujdi triggered"
	strings: $suspicious_string = "Zetas Oujdi"
	condition: $suspicious_string
}
rule Rule_997_triggered {
	meta: description = "Rule # 997 Suspicious String ZoRRoKiN triggered"
	strings: $suspicious_string = "ZoRRoKiN"
	condition: $suspicious_string
}
rule Rule_998_triggered {
	meta: description = "Rule # 998 Suspicious String Zone-H triggered"
	strings: $suspicious_string = "Zone-H"
	condition: $suspicious_string
}
rule Rule_999_triggered {
	meta: description = "Rule # 999 Suspicious String Zz3ro CooL triggered"
	strings: $suspicious_string = "Zz3ro CooL"
	condition: $suspicious_string
}
rule Rule_1000_triggered {
	meta: description = "Rule # 1000 Suspicious String [+] Founded  triggered"
	strings: $suspicious_string = "[+] Founded "
	condition: $suspicious_string
}
rule Rule_1001_triggered {
	meta: description = "Rule # 1001 Suspicious String _0xaae8 triggered"
	strings: $suspicious_string = "_0xaae8"
	condition: $suspicious_string
}
rule Rule_1002_triggered {
	meta: description = "Rule # 1002 Suspicious String _68758598 triggered"
	strings: $suspicious_string = "_68758598"
	condition: $suspicious_string
}
rule Rule_1003_triggered {
	meta: description = "Rule # 1003 Suspicious String _Tuan2Fay_  triggered"
	strings: $suspicious_string = "_Tuan2Fay_ "
	condition: $suspicious_string
}
rule Rule_1004_triggered {
	meta: description = "Rule # 1004 Suspicious String a8ab0 triggered"
	strings: $suspicious_string = "a8ab0"
	condition: $suspicious_string
}
rule Rule_1005_triggered {
	meta: description = "Rule # 1005 Suspicious String aBu.HaLiL501 triggered"
	strings: $suspicious_string = "aBu.HaLiL501"
	condition: $suspicious_string
}
rule Rule_1006_triggered {
	meta: description = "Rule # 1006 Suspicious String aWYgKGlzc2V0KCRfUkVRVUVTVFsnc triggered"
	strings: $suspicious_string = "aWYgKGlzc2V0KCRfUkVRVUVTVFsnc"
	condition: $suspicious_string
}
rule Rule_1007_triggered {
	meta: description = "Rule # 1007 Suspicious String ada data yang kosong triggered"
	strings: $suspicious_string = "ada data yang kosong"
	condition: $suspicious_string
}
rule Rule_1008_triggered {
	meta: description = "Rule # 1008 Suspicious String add.francafranca.com triggered"
	strings: $suspicious_string = "add.francafranca.com"
	condition: $suspicious_string
}
rule Rule_1009_triggered {
	meta: description = "Rule # 1009 Suspicious String admin.furstoutountzi.com triggered"
	strings: $suspicious_string = "admin.furstoutountzi.com"
	condition: $suspicious_string
}
rule Rule_1010_triggered {
	meta: description = "Rule # 1010 Suspicious String adminer.php triggered"
	strings: $suspicious_string = "adminer.php"
	condition: $suspicious_string
}
rule Rule_1011_triggered {
	meta: description = "Rule # 1011 Suspicious String adorablejimalvarez@gmail.com triggered"
	strings: $suspicious_string = "adorablejimalvarez@gmail.com"
	condition: $suspicious_string
}
rule Rule_1012_triggered {
	meta: description = "Rule # 1012 Suspicious String advanced html base64 encryptor triggered"
	strings: $suspicious_string = "advanced html base64 encryptor"
	condition: $suspicious_string
}
rule Rule_1013_triggered {
	meta: description = "Rule # 1013 Suspicious String aeskoly triggered"
	strings: $suspicious_string = "aeskoly"
	condition: $suspicious_string
}
rule Rule_1014_triggered {
	meta: description = "Rule # 1014 Suspicious String afoikoko@gmail.com triggered"
	strings: $suspicious_string = "afoikoko@gmail.com"
	condition: $suspicious_string
}
rule Rule_1015_triggered {
	meta: description = "Rule # 1015 Suspicious String agileurbia.com/2ltN triggered"
	strings: $suspicious_string = "agileurbia.com/2ltN"
	condition: $suspicious_string
}
rule Rule_1016_triggered {
	meta: description = "Rule # 1016 Suspicious String ahufvcoivw triggered"
	strings: $suspicious_string = "ahufvcoivw"
	condition: $suspicious_string
}
rule Rule_1017_triggered {
	meta: description = "Rule # 1017 Suspicious String alcustomer1984@gmail.com triggered"
	strings: $suspicious_string = "alcustomer1984@gmail.com"
	condition: $suspicious_string
}
rule Rule_1018_triggered {
	meta: description = "Rule # 1018 Suspicious String alextho676@gmail.com triggered"
	strings: $suspicious_string = "alextho676@gmail.com"
	condition: $suspicious_string
}
rule Rule_1019_triggered {
	meta: description = "Rule # 1019 Suspicious String ali.lazaar22@Gmail.com triggered"
	strings: $suspicious_string = "ali.lazaar22@Gmail.com"
	condition: $suspicious_string
}
rule Rule_1020_triggered {
	meta: description = "Rule # 1020 Suspicious String alm3refh.com triggered"
	strings: $suspicious_string = "alm3refh.com"
	condition: $suspicious_string
}
rule Rule_1021_triggered {
	meta: description = "Rule # 1021 Suspicious String alonecode triggered"
	strings: $suspicious_string = "alonecode"
	condition: $suspicious_string
}
rule Rule_1022_triggered {
	meta: description = "Rule # 1022 Suspicious String alubarika4ever@gmail.com triggered"
	strings: $suspicious_string = "alubarika4ever@gmail.com"
	condition: $suspicious_string
}
rule Rule_1023_triggered {
	meta: description = "Rule # 1023 Suspicious String amazon scams triggered"
	strings: $suspicious_string = "amazon scams"
	condition: $suspicious_string
}
rule Rule_1024_triggered {
	meta: description = "Rule # 1024 Suspicious String angular.club/js/everlast.js triggered"
	strings: $suspicious_string = "angular.club/js/everlast.js"
	condition: $suspicious_string
}
rule Rule_1025_triggered {
	meta: description = "Rule # 1025 Suspicious String anjirGBX  triggered"
	strings: $suspicious_string = "anjirGBX "
	condition: $suspicious_string
}
rule Rule_1026_triggered {
	meta: description = "Rule # 1026 Suspicious String aoldocs triggered"
	strings: $suspicious_string = "aoldocs"
	condition: $suspicious_string
}
rule Rule_1027_triggered {
	meta: description = "Rule # 1027 Suspicious String ashrepetto43@gmail.com triggered"
	strings: $suspicious_string = "ashrepetto43@gmail.com"
	condition: $suspicious_string
}
rule Rule_1028_triggered {
	meta: description = "Rule # 1028 Suspicious String awertase triggered"
	strings: $suspicious_string = "awertase"
	condition: $suspicious_string
}
rule Rule_1029_triggered {
	meta: description = "Rule # 1029 Suspicious String awso shell triggered"
	strings: $suspicious_string = "awso shell"
	condition: $suspicious_string
}
rule Rule_1030_triggered {
	meta: description = "Rule # 1030 Suspicious String axabanque.fr triggered"
	strings: $suspicious_string = "axabanque.fr"
	condition: $suspicious_string
}
rule Rule_1031_triggered {
	meta: description = "Rule # 1031 Suspicious String aykutbilgic@gmail.com triggered"
	strings: $suspicious_string = "aykutbilgic@gmail.com"
	condition: $suspicious_string
}
rule Rule_1032_triggered {
	meta: description = "Rule # 1032 Suspicious String ayotomiwa11@gmail.com triggered"
	strings: $suspicious_string = "ayotomiwa11@gmail.com"
	condition: $suspicious_string
}
rule Rule_1033_triggered {
	meta: description = "Rule # 1033 Suspicious String ayoubaittoto@gmail.com triggered"
	strings: $suspicious_string = "ayoubaittoto@gmail.com"
	condition: $suspicious_string
}
rule Rule_1034_triggered {
	meta: description = "Rule # 1034 Suspicious String azzatssins.cyberserkers triggered"
	strings: $suspicious_string = "azzatssins.cyberserkers"
	condition: $suspicious_string
}
rule Rule_1035_triggered {
	meta: description = "Rule # 1035 Suspicious String b0ne triggered"
	strings: $suspicious_string = "b0ne"
	condition: $suspicious_string
}
rule Rule_1036_triggered {
	meta: description = "Rule # 1036 Suspicious String b374k 2.8 triggered"
	strings: $suspicious_string = "b374k 2.8"
	condition: $suspicious_string
}
rule Rule_1037_triggered {
	meta: description = "Rule # 1037 Suspicious String b374k-shell triggered"
	strings: $suspicious_string = "b374k-shell"
	condition: $suspicious_string
}
rule Rule_1038_triggered {
	meta: description = "Rule # 1038 Suspicious String b4che10r triggered"
	strings: $suspicious_string = "b4che10r"
	condition: $suspicious_string
}
rule Rule_1039_triggered {
	meta: description = "Rule # 1039 Suspicious String backconnect weevely triggered"
	strings: $suspicious_string = "backconnect weevely"
	condition: $suspicious_string
}
rule Rule_1040_triggered {
	meta: description = "Rule # 1040 Suspicious String badermuhamed@yahoo.com triggered"
	strings: $suspicious_string = "badermuhamed@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1041_triggered {
	meta: description = "Rule # 1041 Suspicious String badrddine777@gmail.com triggered"
	strings: $suspicious_string = "badrddine777@gmail.com"
	condition: $suspicious_string
}
rule Rule_1042_triggered {
	meta: description = "Rule # 1042 Suspicious String bangladeshblackhat triggered"
	strings: $suspicious_string = "bangladeshblackhat"
	condition: $suspicious_string
}
rule Rule_1043_triggered {
	meta: description = "Rule # 1043 Suspicious String bankofamerica.com triggered"
	strings: $suspicious_string = "bankofamerica.com"
	condition: $suspicious_string
}
rule Rule_1044_triggered {
	meta: description = "Rule # 1044 Suspicious String base64_decode(\"DQplcnJvcl9yZXBvcnRpbmcoM triggered"
	strings: $suspicious_string = "base64_decode(\"DQplcnJvcl9yZXBvcnRpbmcoM"
	condition: $suspicious_string
}
rule Rule_1045_triggered {
	meta: description = "Rule # 1045 Suspicious String bash autoroot.sh triggered"
	strings: $suspicious_string = "bash autoroot.sh"
	condition: $suspicious_string
}
rule Rule_1046_triggered {
	meta: description = "Rule # 1046 Suspicious String bash_history triggered"
	strings: $suspicious_string = "bash_history"
	condition: $suspicious_string
}
rule Rule_1047_triggered {
	meta: description = "Rule # 1047 Suspicious String bbc.wehbeconstruction.com triggered"
	strings: $suspicious_string = "bbc.wehbeconstruction.com"
	condition: $suspicious_string
}
rule Rule_1048_triggered {
	meta: description = "Rule # 1048 Suspicious String bbhhinternational triggered"
	strings: $suspicious_string = "bbhhinternational"
	condition: $suspicious_string
}
rule Rule_1049_triggered {
	meta: description = "Rule # 1049 Suspicious String bckdrprm triggered"
	strings: $suspicious_string = "bckdrprm"
	condition: $suspicious_string
}
rule Rule_1050_triggered {
	meta: description = "Rule # 1050 Suspicious String bdblackhat.net triggered"
	strings: $suspicious_string = "bdblackhat.net"
	condition: $suspicious_string
}
rule Rule_1051_triggered {
	meta: description = "Rule # 1051 Suspicious String bdhh52@gmail.com triggered"
	strings: $suspicious_string = "bdhh52@gmail.com"
	condition: $suspicious_string
}
rule Rule_1052_triggered {
	meta: description = "Rule # 1052 Suspicious String believd triggered"
	strings: $suspicious_string = "believd"
	condition: $suspicious_string
}
rule Rule_1053_triggered {
	meta: description = "Rule # 1053 Suspicious String bella_mafia_quackafella triggered"
	strings: $suspicious_string = "bella_mafia_quackafella"
	condition: $suspicious_string
}
rule Rule_1054_triggered {
	meta: description = "Rule # 1054 Suspicious String bitchx triggered"
	strings: $suspicious_string = "bitchx"
	condition: $suspicious_string
}
rule Rule_1055_triggered {
	meta: description = "Rule # 1055 Suspicious String bjqnt triggered"
	strings: $suspicious_string = "bjqnt"
	condition: $suspicious_string
}
rule Rule_1056_triggered {
	meta: description = "Rule # 1056 Suspicious String blowtime666@gmail.com triggered"
	strings: $suspicious_string = "blowtime666@gmail.com"
	condition: $suspicious_string
}
rule Rule_1057_triggered {
	meta: description = "Rule # 1057 Suspicious String bobreed085@gmail.com triggered"
	strings: $suspicious_string = "bobreed085@gmail.com"
	condition: $suspicious_string
}
rule Rule_1058_triggered {
	meta: description = "Rule # 1058 Suspicious String bomba1 triggered"
	strings: $suspicious_string = "bomba1"
	condition: $suspicious_string
}
rule Rule_1059_triggered {
	meta: description = "Rule # 1059 Suspicious String botnick triggered"
	strings: $suspicious_string = "botnick"
	condition: $suspicious_string
}
rule Rule_1060_triggered {
	meta: description = "Rule # 1060 Suspicious String brewer_armstrong@yahoo.com triggered"
	strings: $suspicious_string = "brewer_armstrong@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1061_triggered {
	meta: description = "Rule # 1061 Suspicious String btnCreditCard.paymentBtn.creditcard triggered"
	strings: $suspicious_string = "btnCreditCard.paymentBtn.creditcard"
	condition: $suspicious_string
}
rule Rule_1062_triggered {
	meta: description = "Rule # 1062 Suspicious String burayaoraya triggered"
	strings: $suspicious_string = "burayaoraya"
	condition: $suspicious_string
}
rule Rule_1063_triggered {
	meta: description = "Rule # 1063 Suspicious String by INJECTOR_MA triggered"
	strings: $suspicious_string = "by INJECTOR_MA"
	condition: $suspicious_string
}
rule Rule_1064_triggered {
	meta: description = "Rule # 1064 Suspicious String by KingSolomon triggered"
	strings: $suspicious_string = "by KingSolomon"
	condition: $suspicious_string
}
rule Rule_1065_triggered {
	meta: description = "Rule # 1065 Suspicious String by misafir triggered"
	strings: $suspicious_string = "by misafir"
	condition: $suspicious_string
}
rule Rule_1066_triggered {
	meta: description = "Rule # 1066 Suspicious String by w4l3XzY3 triggered"
	strings: $suspicious_string = "by w4l3XzY3"
	condition: $suspicious_string
}
rule Rule_1067_triggered {
	meta: description = "Rule # 1067 Suspicious String c.21-2n.com triggered"
	strings: $suspicious_string = "c.21-2n.com"
	condition: $suspicious_string
}
rule Rule_1068_triggered {
	meta: description = "Rule # 1068 Suspicious String c.21-3n.com triggered"
	strings: $suspicious_string = "c.21-3n.com"
	condition: $suspicious_string
}
rule Rule_1069_triggered {
	meta: description = "Rule # 1069 Suspicious String c.21-3n.xyz triggered"
	strings: $suspicious_string = "c.21-3n.xyz"
	condition: $suspicious_string
}
rule Rule_1070_triggered {
	meta: description = "Rule # 1070 Suspicious String c0d3d By triggered"
	strings: $suspicious_string = "c0d3d By"
	condition: $suspicious_string
}
rule Rule_1071_triggered {
	meta: description = "Rule # 1071 Suspicious String c0d3d by lionaneesh triggered"
	strings: $suspicious_string = "c0d3d by lionaneesh"
	condition: $suspicious_string
}
rule Rule_1072_triggered {
	meta: description = "Rule # 1072 Suspicious String c43760b9 triggered"
	strings: $suspicious_string = "c43760b9"
	condition: $suspicious_string
}
rule Rule_1073_triggered {
	meta: description = "Rule # 1073 Suspicious String c7ca8 triggered"
	strings: $suspicious_string = "c7ca8"
	condition: $suspicious_string
}
rule Rule_1074_triggered {
	meta: description = "Rule # 1074 Suspicious String c84c8098.com triggered"
	strings: $suspicious_string = "c84c8098.com"
	condition: $suspicious_string
}
rule Rule_1075_triggered {
	meta: description = "Rule # 1075 Suspicious String c99 triggered"
	strings: $suspicious_string = "c99"
	condition: $suspicious_string
}
rule Rule_1076_triggered {
	meta: description = "Rule # 1076 Suspicious String c99.me/base triggered"
	strings: $suspicious_string = "c99.me/base"
	condition: $suspicious_string
}
rule Rule_1077_triggered {
	meta: description = "Rule # 1077 Suspicious String c999sh_surl triggered"
	strings: $suspicious_string = "c999sh_surl"
	condition: $suspicious_string
}
rule Rule_1078_triggered {
	meta: description = "Rule # 1078 Suspicious String c9gmks5fidne triggered"
	strings: $suspicious_string = "c9gmks5fidne"
	condition: $suspicious_string
}
rule Rule_1079_triggered {
	meta: description = "Rule # 1079 Suspicious String cPanel Cracker triggered"
	strings: $suspicious_string = "cPanel Cracker"
	condition: $suspicious_string
}
rule Rule_1080_triggered {
	meta: description = "Rule # 1080 Suspicious String cPanel Finder/Cracker triggered"
	strings: $suspicious_string = "cPanel Finder/Cracker"
	condition: $suspicious_string
}
rule Rule_1081_triggered {
	meta: description = "Rule # 1081 Suspicious String callbrhy triggered"
	strings: $suspicious_string = "callbrhy"
	condition: $suspicious_string
}
rule Rule_1082_triggered {
	meta: description = "Rule # 1082 Suspicious String cardnumber: triggered"
	strings: $suspicious_string = "cardnumber:"
	condition: $suspicious_string
}
rule Rule_1083_triggered {
	meta: description = "Rule # 1083 Suspicious String cazanova.haxor@hotmail.com triggered"
	strings: $suspicious_string = "cazanova.haxor@hotmail.com"
	condition: $suspicious_string
}
rule Rule_1084_triggered {
	meta: description = "Rule # 1084 Suspicious String cazanova163 triggered"
	strings: $suspicious_string = "cazanova163"
	condition: $suspicious_string
}
rule Rule_1085_triggered {
	meta: description = "Rule # 1085 Suspicious String ccteam.ru triggered"
	strings: $suspicious_string = "ccteam.ru"
	condition: $suspicious_string
}
rule Rule_1086_triggered {
	meta: description = "Rule # 1086 Suspicious String cdn.popcash.net/pop.js triggered"
	strings: $suspicious_string = "cdn.popcash.net/pop.js"
	condition: $suspicious_string
}
rule Rule_1087_triggered {
	meta: description = "Rule # 1087 Suspicious String cdob1s triggered"
	strings: $suspicious_string = "cdob1s"
	condition: $suspicious_string
}
rule Rule_1088_triggered {
	meta: description = "Rule # 1088 Suspicious String cek Disini goblok! triggered"
	strings: $suspicious_string = "cek Disini goblok!"
	condition: $suspicious_string
}
rule Rule_1089_triggered {
	meta: description = "Rule # 1089 Suspicious String centurylink.com triggered"
	strings: $suspicious_string = "centurylink.com"
	condition: $suspicious_string
}
rule Rule_1090_triggered {
	meta: description = "Rule # 1090 Suspicious String cgitelnet triggered"
	strings: $suspicious_string = "cgitelnet"
	condition: $suspicious_string
}
rule Rule_1091_triggered {
	meta: description = "Rule # 1091 Suspicious String cha88.cn triggered"
	strings: $suspicious_string = "cha88.cn"
	condition: $suspicious_string
}
rule Rule_1092_triggered {
	meta: description = "Rule # 1092 Suspicious String changed every time so chrome & bots can't see the scam source code triggered"
	strings: $suspicious_string = "changed every time so chrome & bots can't see the scam source code"
	condition: $suspicious_string
}
rule Rule_1093_triggered {
	meta: description = "Rule # 1093 Suspicious String chase.com triggered"
	strings: $suspicious_string = "chase.com"
	condition: $suspicious_string
}
rule Rule_1094_triggered {
	meta: description = "Rule # 1094 Suspicious String chiacheng2012@gmail.com triggered"
	strings: $suspicious_string = "chiacheng2012@gmail.com"
	condition: $suspicious_string
}
rule Rule_1095_triggered {
	meta: description = "Rule # 1095 Suspicious String chinazfans@gmail.com triggered"
	strings: $suspicious_string = "chinazfans@gmail.com"
	condition: $suspicious_string
}
rule Rule_1096_triggered {
	meta: description = "Rule # 1096 Suspicious String chishijen12 triggered"
	strings: $suspicious_string = "chishijen12"
	condition: $suspicious_string
}
rule Rule_1097_triggered {
	meta: description = "Rule # 1097 Suspicious String chizzyspamm@gmail.com triggered"
	strings: $suspicious_string = "chizzyspamm@gmail.com"
	condition: $suspicious_string
}
rule Rule_1098_triggered {
	meta: description = "Rule # 1098 Suspicious String chr(112).chr(49) triggered"
	strings: $suspicious_string = "chr(112).chr(49)"
	condition: $suspicious_string
}
rule Rule_1099_triggered {
	meta: description = "Rule # 1099 Suspicious String christbb616@gmail.com triggered"
	strings: $suspicious_string = "christbb616@gmail.com"
	condition: $suspicious_string
}
rule Rule_1100_triggered {
	meta: description = "Rule # 1100 Suspicious String chukuma0000007@yahoo.com triggered"
	strings: $suspicious_string = "chukuma0000007@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1101_triggered {
	meta: description = "Rule # 1101 Suspicious String click to Extract usernames and mass symlink triggered"
	strings: $suspicious_string = "click to Extract usernames and mass symlink"
	condition: $suspicious_string
}
rule Rule_1102_triggered {
	meta: description = "Rule # 1102 Suspicious String cocuk escort triggered"
	strings: $suspicious_string = "cocuk escort"
	condition: $suspicious_string
}
rule Rule_1103_triggered {
	meta: description = "Rule # 1103 Suspicious String code breaker ica triggered"
	strings: $suspicious_string = "code breaker ica"
	condition: $suspicious_string
}
rule Rule_1104_triggered {
	meta: description = "Rule # 1104 Suspicious String coded by Fian harbas triggered"
	strings: $suspicious_string = "coded by Fian harbas"
	condition: $suspicious_string
}
rule Rule_1105_triggered {
	meta: description = "Rule # 1105 Suspicious String coinhive triggered"
	strings: $suspicious_string = "coinhive"
	condition: $suspicious_string
}
rule Rule_1106_triggered {
	meta: description = "Rule # 1106 Suspicious String cold fire hacker triggered"
	strings: $suspicious_string = "cold fire hacker"
	condition: $suspicious_string
}
rule Rule_1107_triggered {
	meta: description = "Rule # 1107 Suspicious String columbuscolumbus45@gmail.com triggered"
	strings: $suspicious_string = "columbuscolumbus45@gmail.com"
	condition: $suspicious_string
}
rule Rule_1108_triggered {
	meta: description = "Rule # 1108 Suspicious String con.pechemignon.co triggered"
	strings: $suspicious_string = "con.pechemignon.co"
	condition: $suspicious_string
}
rule Rule_1109_triggered {
	meta: description = "Rule # 1109 Suspicious String con7ext-exeuser.rhcloud.com triggered"
	strings: $suspicious_string = "con7ext-exeuser.rhcloud.com"
	condition: $suspicious_string
}
rule Rule_1110_triggered {
	meta: description = "Rule # 1110 Suspicious String config-grabber.sh triggered"
	strings: $suspicious_string = "config-grabber.sh"
	condition: $suspicious_string
}
rule Rule_1111_triggered {
	meta: description = "Rule # 1111 Suspicious String config-sniper triggered"
	strings: $suspicious_string = "config-sniper"
	condition: $suspicious_string
}
rule Rule_1112_triggered {
	meta: description = "Rule # 1112 Suspicious String connectjbmoveisok triggered"
	strings: $suspicious_string = "connectjbmoveisok"
	condition: $suspicious_string
}
rule Rule_1113_triggered {
	meta: description = "Rule # 1113 Suspicious String cool shavik<br>Ebin V Thomas triggered"
	strings: $suspicious_string = "cool shavik<br>Ebin V Thomas"
	condition: $suspicious_string
}
rule Rule_1114_triggered {
	meta: description = "Rule # 1114 Suspicious String cool toad triggered"
	strings: $suspicious_string = "cool toad"
	condition: $suspicious_string
}
rule Rule_1115_triggered {
	meta: description = "Rule # 1115 Suspicious String copy 2010, MeGo triggered"
	strings: $suspicious_string = "copy 2010, MeGo"
	condition: $suspicious_string
}
rule Rule_1116_triggered {
	meta: description = "Rule # 1116 Suspicious String cpcracker.py triggered"
	strings: $suspicious_string = "cpcracker.py"
	condition: $suspicious_string
}
rule Rule_1117_triggered {
	meta: description = "Rule # 1117 Suspicious String cr1p.blogspot.com triggered"
	strings: $suspicious_string = "cr1p.blogspot.com"
	condition: $suspicious_string
}
rule Rule_1118_triggered {
	meta: description = "Rule # 1118 Suspicious String cracktype triggered"
	strings: $suspicious_string = "cracktype"
	condition: $suspicious_string
}
rule Rule_1119_triggered {
	meta: description = "Rule # 1119 Suspicious String crax0 triggered"
	strings: $suspicious_string = "crax0"
	condition: $suspicious_string
}
rule Rule_1120_triggered {
	meta: description = "Rule # 1120 Suspicious String crkekatkek_kfkukncktkikon triggered"
	strings: $suspicious_string = "crkekatkek_kfkukncktkikon"
	condition: $suspicious_string
}
rule Rule_1121_triggered {
	meta: description = "Rule # 1121 Suspicious String crowdweed triggered"
	strings: $suspicious_string = "crowdweed"
	condition: $suspicious_string
}
rule Rule_1122_triggered {
	meta: description = "Rule # 1122 Suspicious String cryptonight triggered"
	strings: $suspicious_string = "cryptonight"
	condition: $suspicious_string
}
rule Rule_1123_triggered {
	meta: description = "Rule # 1123 Suspicious String ctcpflood triggered"
	strings: $suspicious_string = "ctcpflood"
	condition: $suspicious_string
}
rule Rule_1124_triggered {
	meta: description = "Rule # 1124 Suspicious String cwings triggered"
	strings: $suspicious_string = "cwings"
	condition: $suspicious_string
}
rule Rule_1125_triggered {
	meta: description = "Rule # 1125 Suspicious String cxib [ a.T] securityreason [ d0t] com triggered"
	strings: $suspicious_string = "cxib [ a.T] securityreason [ d0t] com"
	condition: $suspicious_string
}
rule Rule_1126_triggered {
	meta: description = "Rule # 1126 Suspicious String cyber gladiator triggered"
	strings: $suspicious_string = "cyber gladiator"
	condition: $suspicious_string
}
rule Rule_1127_triggered {
	meta: description = "Rule # 1127 Suspicious String cyber warrior triggered"
	strings: $suspicious_string = "cyber warrior"
	condition: $suspicious_string
}
rule Rule_1128_triggered {
	meta: description = "Rule # 1128 Suspicious String cyberheroez.ddos.im triggered"
	strings: $suspicious_string = "cyberheroez.ddos.im"
	condition: $suspicious_string
}
rule Rule_1129_triggered {
	meta: description = "Rule # 1129 Suspicious String cydippian triggered"
	strings: $suspicious_string = "cydippian"
	condition: $suspicious_string
}
rule Rule_1130_triggered {
	meta: description = "Rule # 1130 Suspicious String czw_07  triggered"
	strings: $suspicious_string = "czw_07 "
	condition: $suspicious_string
}
rule Rule_1131_triggered {
	meta: description = "Rule # 1131 Suspicious String d.heheda.tk triggered"
	strings: $suspicious_string = "d.heheda.tk"
	condition: $suspicious_string
}
rule Rule_1132_triggered {
	meta: description = "Rule # 1132 Suspicious String d0mains triggered"
	strings: $suspicious_string = "d0mains"
	condition: $suspicious_string
}
rule Rule_1133_triggered {
	meta: description = "Rule # 1133 Suspicious String d3b~X triggered"
	strings: $suspicious_string = "d3b~X"
	condition: $suspicious_string
}
rule Rule_1134_triggered {
	meta: description = "Rule # 1134 Suspicious String dGhteXR2 triggered"
	strings: $suspicious_string = "dGhteXR2"
	condition: $suspicious_string
}
rule Rule_1135_triggered {
	meta: description = "Rule # 1135 Suspicious String dR.ArmY triggered"
	strings: $suspicious_string = "dR.ArmY"
	condition: $suspicious_string
}
rule Rule_1136_triggered {
	meta: description = "Rule # 1136 Suspicious String dalnet triggered"
	strings: $suspicious_string = "dalnet"
	condition: $suspicious_string
}
rule Rule_1137_triggered {
	meta: description = "Rule # 1137 Suspicious String dangerissaoui@outlook.com.fr triggered"
	strings: $suspicious_string = "dangerissaoui@outlook.com.fr"
	condition: $suspicious_string
}
rule Rule_1138_triggered {
	meta: description = "Rule # 1138 Suspicious String danielgrochowski1@gmail.com triggered"
	strings: $suspicious_string = "danielgrochowski1@gmail.com"
	condition: $suspicious_string
}
rule Rule_1139_triggered {
	meta: description = "Rule # 1139 Suspicious String dannymckay triggered"
	strings: $suspicious_string = "dannymckay"
	condition: $suspicious_string
}
rule Rule_1140_triggered {
	meta: description = "Rule # 1140 Suspicious String dcvi.net triggered"
	strings: $suspicious_string = "dcvi.net"
	condition: $suspicious_string
}
rule Rule_1141_triggered {
	meta: description = "Rule # 1141 Suspicious String deface triggered"
	strings: $suspicious_string = "deface"
	condition: $suspicious_string
}
rule Rule_1142_triggered {
	meta: description = "Rule # 1142 Suspicious String default pass : haurgeulis triggered"
	strings: $suspicious_string = "default pass : haurgeulis"
	condition: $suspicious_string
}
rule Rule_1143_triggered {
	meta: description = "Rule # 1143 Suspicious String dgkxjegdyzqnv triggered"
	strings: $suspicious_string = "dgkxjegdyzqnv"
	condition: $suspicious_string
}
rule Rule_1144_triggered {
	meta: description = "Rule # 1144 Suspicious String diapedesis triggered"
	strings: $suspicious_string = "diapedesis"
	condition: $suspicious_string
}
rule Rule_1145_triggered {
	meta: description = "Rule # 1145 Suspicious String die(PHP_OS.chr(49).chr(48).chr(43).md5(0987654321 triggered"
	strings: $suspicious_string = "die(PHP_OS.chr(49).chr(48).chr(43).md5(0987654321"
	condition: $suspicious_string
}
rule Rule_1146_triggered {
	meta: description = "Rule # 1146 Suspicious String dimakanhwik@gmail.com triggered"
	strings: $suspicious_string = "dimakanhwik@gmail.com"
	condition: $suspicious_string
}
rule Rule_1147_triggered {
	meta: description = "Rule # 1147 Suspicious String dirtycow triggered"
	strings: $suspicious_string = "dirtycow"
	condition: $suspicious_string
}
rule Rule_1148_triggered {
	meta: description = "Rule # 1148 Suspicious String dollypizzu37@gmail.com triggered"
	strings: $suspicious_string = "dollypizzu37@gmail.com"
	condition: $suspicious_string
}
rule Rule_1149_triggered {
	meta: description = "Rule # 1149 Suspicious String domains.yougetsignal.com triggered"
	strings: $suspicious_string = "domains.yougetsignal.com"
	condition: $suspicious_string
}
rule Rule_1150_triggered {
	meta: description = "Rule # 1150 Suspicious String donflow2015@yahoo.com triggered"
	strings: $suspicious_string = "donflow2015@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1151_triggered {
	meta: description = "Rule # 1151 Suspicious String downserverdown@gmail.com triggered"
	strings: $suspicious_string = "downserverdown@gmail.com"
	condition: $suspicious_string
}
rule Rule_1152_triggered {
	meta: description = "Rule # 1152 Suspicious String dqnxfsqvd triggered"
	strings: $suspicious_string = "dqnxfsqvd"
	condition: $suspicious_string
}
rule Rule_1153_triggered {
	meta: description = "Rule # 1153 Suspicious String dr.t3rr0r triggered"
	strings: $suspicious_string = "dr.t3rr0r"
	condition: $suspicious_string
}
rule Rule_1154_triggered {
	meta: description = "Rule # 1154 Suspicious String dropmybin.me triggered"
	strings: $suspicious_string = "dropmybin.me"
	condition: $suspicious_string
}
rule Rule_1155_triggered {
	meta: description = "Rule # 1155 Suspicious String dzph@bk.ru triggered"
	strings: $suspicious_string = "dzph@bk.ru"
	condition: $suspicious_string
}
rule Rule_1156_triggered {
	meta: description = "Rule # 1156 Suspicious String e0aae triggered"
	strings: $suspicious_string = "e0aae"
	condition: $suspicious_string
}
rule Rule_1157_triggered {
	meta: description = "Rule # 1157 Suspicious String e42d078d.com triggered"
	strings: $suspicious_string = "e42d078d.com"
	condition: $suspicious_string
}
rule Rule_1158_triggered {
	meta: description = "Rule # 1158 Suspicious String e5057bd08dc553311081fd1107f05d7a triggered"
	strings: $suspicious_string = "e5057bd08dc553311081fd1107f05d7a"
	condition: $suspicious_string
}
rule Rule_1159_triggered {
	meta: description = "Rule # 1159 Suspicious String e5b57288.com triggered"
	strings: $suspicious_string = "e5b57288.com"
	condition: $suspicious_string
}
rule Rule_1160_triggered {
	meta: description = "Rule # 1160 Suspicious String e5b57288.com|31.184.192.173 triggered"
	strings: $suspicious_string = "e5b57288.com|31.184.192.173"
	condition: $suspicious_string
}
rule Rule_1161_triggered {
	meta: description = "Rule # 1161 Suspicious String e693bc675b171a2f4ad0338d6a9b158c515295e1 triggered"
	strings: $suspicious_string = "e693bc675b171a2f4ad0338d6a9b158c515295e1"
	condition: $suspicious_string
}
rule Rule_1162_triggered {
	meta: description = "Rule # 1162 Suspicious String eIAgn9fjRC68DC7QIDhGN43qSDcw2 triggered"
	strings: $suspicious_string = "eIAgn9fjRC68DC7QIDhGN43qSDcw2"
	condition: $suspicious_string
}
rule Rule_1163_triggered {
	meta: description = "Rule # 1163 Suspicious String eM.Pr404 triggered"
	strings: $suspicious_string = "eM.Pr404"
	condition: $suspicious_string
}
rule Rule_1164_triggered {
	meta: description = "Rule # 1164 Suspicious String easywaylogs@outlook.com triggered"
	strings: $suspicious_string = "easywaylogs@outlook.com"
	condition: $suspicious_string
}
rule Rule_1165_triggered {
	meta: description = "Rule # 1165 Suspicious String ec38fe2a8497e0a8d6d349b3533038cb triggered"
	strings: $suspicious_string = "ec38fe2a8497e0a8d6d349b3533038cb"
	condition: $suspicious_string
}
rule Rule_1166_triggered {
	meta: description = "Rule # 1166 Suspicious String eelqnn@yandex.ru triggered"
	strings: $suspicious_string = "eelqnn@yandex.ru"
	condition: $suspicious_string
}
rule Rule_1167_triggered {
	meta: description = "Rule # 1167 Suspicious String eelsmarch@gmail.com triggered"
	strings: $suspicious_string = "eelsmarch@gmail.com"
	condition: $suspicious_string
}
rule Rule_1168_triggered {
	meta: description = "Rule # 1168 Suspicious String ef50185@gmail.com triggered"
	strings: $suspicious_string = "ef50185@gmail.com"
	condition: $suspicious_string
}
rule Rule_1169_triggered {
	meta: description = "Rule # 1169 Suspicious String ejykesouth@gmail.com triggered"
	strings: $suspicious_string = "ejykesouth@gmail.com"
	condition: $suspicious_string
}
rule Rule_1170_triggered {
	meta: description = "Rule # 1170 Suspicious String elcuate2339@hotmail.com triggered"
	strings: $suspicious_string = "elcuate2339@hotmail.com"
	condition: $suspicious_string
}
rule Rule_1171_triggered {
	meta: description = "Rule # 1171 Suspicious String emp3ror.com triggered"
	strings: $suspicious_string = "emp3ror.com"
	condition: $suspicious_string
}
rule Rule_1172_triggered {
	meta: description = "Rule # 1172 Suspicious String engcolinjj@gmail.com triggered"
	strings: $suspicious_string = "engcolinjj@gmail.com"
	condition: $suspicious_string
}
rule Rule_1173_triggered {
	meta: description = "Rule # 1173 Suspicious String eqzv4.resonguterthet.top triggered"
	strings: $suspicious_string = "eqzv4.resonguterthet.top"
	condition: $suspicious_string
}
rule Rule_1174_triggered {
	meta: description = "Rule # 1174 Suspicious String ethicalnoob Indishell triggered"
	strings: $suspicious_string = "ethicalnoob Indishell"
	condition: $suspicious_string
}
rule Rule_1175_triggered {
	meta: description = "Rule # 1175 Suspicious String exilibre7@gmail.com triggered"
	strings: $suspicious_string = "exilibre7@gmail.com"
	condition: $suspicious_string
}
rule Rule_1176_triggered {
	meta: description = "Rule # 1176 Suspicious String expl0i13r triggered"
	strings: $suspicious_string = "expl0i13r"
	condition: $suspicious_string
}
rule Rule_1177_triggered {
	meta: description = "Rule # 1177 Suspicious String f0x35tech@gmail.com triggered"
	strings: $suspicious_string = "f0x35tech@gmail.com"
	condition: $suspicious_string
}
rule Rule_1178_triggered {
	meta: description = "Rule # 1178 Suspicious String fake mailer triggered"
	strings: $suspicious_string = "fake mailer"
	condition: $suspicious_string
}
rule Rule_1179_triggered {
	meta: description = "Rule # 1179 Suspicious String faqux1@gmail.com triggered"
	strings: $suspicious_string = "faqux1@gmail.com"
	condition: $suspicious_string
}
rule Rule_1180_triggered {
	meta: description = "Rule # 1180 Suspicious String fedora.chen.polymet@gmail.com triggered"
	strings: $suspicious_string = "fedora.chen.polymet@gmail.com"
	condition: $suspicious_string
}
rule Rule_1181_triggered {
	meta: description = "Rule # 1181 Suspicious String fhVENcmKTJ triggered"
	strings: $suspicious_string = "fhVENcmKTJ"
	condition: $suspicious_string
}
rule Rule_1182_triggered {
	meta: description = "Rule # 1182 Suspicious String fighterkamrul562@gmail.com triggered"
	strings: $suspicious_string = "fighterkamrul562@gmail.com"
	condition: $suspicious_string
}
rule Rule_1183_triggered {
	meta: description = "Rule # 1183 Suspicious String firefart triggered"
	strings: $suspicious_string = "firefart"
	condition: $suspicious_string
}
rule Rule_1184_triggered {
	meta: description = "Rule # 1184 Suspicious String fn5c098ab854647 triggered"
	strings: $suspicious_string = "fn5c098ab854647"
	condition: $suspicious_string
}
rule Rule_1185_triggered {
	meta: description = "Rule # 1185 Suspicious String focusyearme@yahoo.com triggered"
	strings: $suspicious_string = "focusyearme@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1186_triggered {
	meta: description = "Rule # 1186 Suspicious String for All My Friends and All Defacer triggered"
	strings: $suspicious_string = "for All My Friends and All Defacer"
	condition: $suspicious_string
}
rule Rule_1187_triggered {
	meta: description = "Rule # 1187 Suspicious String frankcasanas.com/tmp/zzz.txt triggered"
	strings: $suspicious_string = "frankcasanas.com/tmp/zzz.txt"
	condition: $suspicious_string
}
rule Rule_1188_triggered {
	meta: description = "Rule # 1188 Suspicious String free shell triggered"
	strings: $suspicious_string = "free shell"
	condition: $suspicious_string
}
rule Rule_1189_triggered {
	meta: description = "Rule # 1189 Suspicious String freshnewly@she.com triggered"
	strings: $suspicious_string = "freshnewly@she.com"
	condition: $suspicious_string
}
rule Rule_1190_triggered {
	meta: description = "Rule # 1190 Suspicious String fretiles@fretillers.com triggered"
	strings: $suspicious_string = "fretiles@fretillers.com"
	condition: $suspicious_string
}
rule Rule_1191_triggered {
	meta: description = "Rule # 1191 Suspicious String from: EGFM triggered"
	strings: $suspicious_string = "from: EGFM"
	condition: $suspicious_string
}
rule Rule_1192_triggered {
	meta: description = "Rule # 1192 Suspicious String fuckyou4321 triggered"
	strings: $suspicious_string = "fuckyou4321"
	condition: $suspicious_string
}
rule Rule_1193_triggered {
	meta: description = "Rule # 1193 Suspicious String fukq triggered"
	strings: $suspicious_string = "fukq"
	condition: $suspicious_string
}
rule Rule_1194_triggered {
	meta: description = "Rule # 1194 Suspicious String func7PLUOCHPZY017 triggered"
	strings: $suspicious_string = "func7PLUOCHPZY017"
	condition: $suspicious_string
}
rule Rule_1195_triggered {
	meta: description = "Rule # 1195 Suspicious String func8YVJMH5AR86A52 triggered"
	strings: $suspicious_string = "func8YVJMH5AR86A52"
	condition: $suspicious_string
}
rule Rule_1196_triggered {
	meta: description = "Rule # 1196 Suspicious String funcXOUUTM54E67A triggered"
	strings: $suspicious_string = "funcXOUUTM54E67A"
	condition: $suspicious_string
}
rule Rule_1197_triggered {
	meta: description = "Rule # 1197 Suspicious String function madafuck triggered"
	strings: $suspicious_string = "function madafuck"
	condition: $suspicious_string
}
rule Rule_1198_triggered {
	meta: description = "Rule # 1198 Suspicious String fwso shell triggered"
	strings: $suspicious_string = "fwso shell"
	condition: $suspicious_string
}
rule Rule_1199_triggered {
	meta: description = "Rule # 1199 Suspicious String gabkinihun@gmail.com triggered"
	strings: $suspicious_string = "gabkinihun@gmail.com"
	condition: $suspicious_string
}
rule Rule_1200_triggered {
	meta: description = "Rule # 1200 Suspicious String geraldineb1963@hotmail.com triggered"
	strings: $suspicious_string = "geraldineb1963@hotmail.com"
	condition: $suspicious_string
}
rule Rule_1201_triggered {
	meta: description = "Rule # 1201 Suspicious String ggmail.html triggered"
	strings: $suspicious_string = "ggmail.html"
	condition: $suspicious_string
}
rule Rule_1202_triggered {
	meta: description = "Rule # 1202 Suspicious String gh0st triggered"
	strings: $suspicious_string = "gh0st"
	condition: $suspicious_string
}
rule Rule_1203_triggered {
	meta: description = "Rule # 1203 Suspicious String gif89a<?php triggered"
	strings: $suspicious_string = "gif89a<?php"
	condition: $suspicious_string
}
rule Rule_1204_triggered {
	meta: description = "Rule # 1204 Suspicious String gmbpr triggered"
	strings: $suspicious_string = "gmbpr"
	condition: $suspicious_string
}
rule Rule_1205_triggered {
	meta: description = "Rule # 1205 Suspicious String goldmanagement2@gmail.com triggered"
	strings: $suspicious_string = "goldmanagement2@gmail.com"
	condition: $suspicious_string
}
rule Rule_1206_triggered {
	meta: description = "Rule # 1206 Suspicious String golr.us.to triggered"
	strings: $suspicious_string = "golr.us.to"
	condition: $suspicious_string
}
rule Rule_1207_triggered {
	meta: description = "Rule # 1207 Suspicious String goodnewsyeso@gmail.com triggered"
	strings: $suspicious_string = "goodnewsyeso@gmail.com"
	condition: $suspicious_string
}
rule Rule_1208_triggered {
	meta: description = "Rule # 1208 Suspicious String goodslife201 triggered"
	strings: $suspicious_string = "goodslife201"
	condition: $suspicious_string
}
rule Rule_1209_triggered {
	meta: description = "Rule # 1209 Suspicious String google.ssl.info.cc triggered"
	strings: $suspicious_string = "google.ssl.info.cc"
	condition: $suspicious_string
}
rule Rule_1210_triggered {
	meta: description = "Rule # 1210 Suspicious String google_warrior triggered"
	strings: $suspicious_string = "google_warrior"
	condition: $suspicious_string
}
rule Rule_1211_triggered {
	meta: description = "Rule # 1211 Suspicious String grav3 triggered"
	strings: $suspicious_string = "grav3"
	condition: $suspicious_string
}
rule Rule_1212_triggered {
	meta: description = "Rule # 1212 Suspicious String guardservices triggered"
	strings: $suspicious_string = "guardservices"
	condition: $suspicious_string
}
rule Rule_1213_triggered {
	meta: description = "Rule # 1213 Suspicious String gujj4rPcP triggered"
	strings: $suspicious_string = "gujj4rPcP"
	condition: $suspicious_string
}
rule Rule_1214_triggered {
	meta: description = "Rule # 1214 Suspicious String h4xc0rp triggered"
	strings: $suspicious_string = "h4xc0rp"
	condition: $suspicious_string
}
rule Rule_1215_triggered {
	meta: description = "Rule # 1215 Suspicious String hack-back triggered"
	strings: $suspicious_string = "hack-back"
	condition: $suspicious_string
}
rule Rule_1216_triggered {
	meta: description = "Rule # 1216 Suspicious String hackattackdude@gmail.com triggered"
	strings: $suspicious_string = "hackattackdude@gmail.com"
	condition: $suspicious_string
}
rule Rule_1217_triggered {
	meta: description = "Rule # 1217 Suspicious String hacked By Chinafans triggered"
	strings: $suspicious_string = "hacked By Chinafans"
	condition: $suspicious_string
}
rule Rule_1218_triggered {
	meta: description = "Rule # 1218 Suspicious String hacked By Fallag Gassrini triggered"
	strings: $suspicious_string = "hacked By Fallag Gassrini"
	condition: $suspicious_string
}
rule Rule_1219_triggered {
	meta: description = "Rule # 1219 Suspicious String hacked by ./zar0us triggered"
	strings: $suspicious_string = "hacked by ./zar0us"
	condition: $suspicious_string
}
rule Rule_1220_triggered {
	meta: description = "Rule # 1220 Suspicious String hacked by MRH.404 triggered"
	strings: $suspicious_string = "hacked by MRH.404"
	condition: $suspicious_string
}
rule Rule_1221_triggered {
	meta: description = "Rule # 1221 Suspicious String hacked by NG689Skw triggered"
	strings: $suspicious_string = "hacked by NG689Skw"
	condition: $suspicious_string
}
rule Rule_1222_triggered {
	meta: description = "Rule # 1222 Suspicious String hackmeplz triggered"
	strings: $suspicious_string = "hackmeplz"
	condition: $suspicious_string
}
rule Rule_1223_triggered {
	meta: description = "Rule # 1223 Suspicious String hamzabkr40@gmail.com triggered"
	strings: $suspicious_string = "hamzabkr40@gmail.com"
	condition: $suspicious_string
}
rule Rule_1224_triggered {
	meta: description = "Rule # 1224 Suspicious String haxor wibu triggered"
	strings: $suspicious_string = "haxor wibu"
	condition: $suspicious_string
}
rule Rule_1225_triggered {
	meta: description = "Rule # 1225 Suspicious String heihei triggered"
	strings: $suspicious_string = "heihei"
	condition: $suspicious_string
}
rule Rule_1226_triggered {
	meta: description = "Rule # 1226 Suspicious String helegedada triggered"
	strings: $suspicious_string = "helegedada"
	condition: $suspicious_string
}
rule Rule_1227_triggered {
	meta: description = "Rule # 1227 Suspicious String hfbakhsh.com triggered"
	strings: $suspicious_string = "hfbakhsh.com"
	condition: $suspicious_string
}
rule Rule_1228_triggered {
	meta: description = "Rule # 1228 Suspicious String hidden uploader triggered"
	strings: $suspicious_string = "hidden uploader"
	condition: $suspicious_string
}
rule Rule_1229_triggered {
	meta: description = "Rule # 1229 Suspicious String homeaway.com triggered"
	strings: $suspicious_string = "homeaway.com"
	condition: $suspicious_string
}
rule Rule_1230_triggered {
	meta: description = "Rule # 1230 Suspicious String horneymace@gmail.com triggered"
	strings: $suspicious_string = "horneymace@gmail.com"
	condition: $suspicious_string
}
rule Rule_1231_triggered {
	meta: description = "Rule # 1231 Suspicious String hrhbox2015@gmail.com triggered"
	strings: $suspicious_string = "hrhbox2015@gmail.com"
	condition: $suspicious_string
}
rule Rule_1232_triggered {
	meta: description = "Rule # 1232 Suspicious String http://3.bp.blogspot.com triggered"
	strings: $suspicious_string = "http://3.bp.blogspot.com"
	condition: $suspicious_string
}
rule Rule_1233_triggered {
	meta: description = "Rule # 1233 Suspicious String http://PaLteam.Org triggered"
	strings: $suspicious_string = "http://PaLteam.Org"
	condition: $suspicious_string
}
rule Rule_1234_triggered {
	meta: description = "Rule # 1234 Suspicious String http://a1b2cd.club/ triggered"
	strings: $suspicious_string = "http://a1b2cd.club/"
	condition: $suspicious_string
}
rule Rule_1235_triggered {
	meta: description = "Rule # 1235 Suspicious String http://fb.com/AyyildizTim1919 triggered"
	strings: $suspicious_string = "http://fb.com/AyyildizTim1919"
	condition: $suspicious_string
}
rule Rule_1236_triggered {
	meta: description = "Rule # 1236 Suspicious String http://fb.com/CazanovaHaxorStore triggered"
	strings: $suspicious_string = "http://fb.com/CazanovaHaxorStore"
	condition: $suspicious_string
}
rule Rule_1237_triggered {
	meta: description = "Rule # 1237 Suspicious String http://ghc.ru triggered"
	strings: $suspicious_string = "http://ghc.ru"
	condition: $suspicious_string
}
rule Rule_1238_triggered {
	meta: description = "Rule # 1238 Suspicious String http://rst.void.ru triggered"
	strings: $suspicious_string = "http://rst.void.ru"
	condition: $suspicious_string
}
rule Rule_1239_triggered {
	meta: description = "Rule # 1239 Suspicious String http://www.sa-hacker.com/vb triggered"
	strings: $suspicious_string = "http://www.sa-hacker.com/vb"
	condition: $suspicious_string
}
rule Rule_1240_triggered {
	meta: description = "Rule # 1240 Suspicious String http://yourservices.live/include.js triggered"
	strings: $suspicious_string = "http://yourservices.live/include.js"
	condition: $suspicious_string
}
rule Rule_1241_triggered {
	meta: description = "Rule # 1241 Suspicious String https://fb.com/Jokr.H4xor triggered"
	strings: $suspicious_string = "https://fb.com/Jokr.H4xor"
	condition: $suspicious_string
}
rule Rule_1242_triggered {
	meta: description = "Rule # 1242 Suspicious String https://fb.com/fir3.hawk5 triggered"
	strings: $suspicious_string = "https://fb.com/fir3.hawk5"
	condition: $suspicious_string
}
rule Rule_1243_triggered {
	meta: description = "Rule # 1243 Suspicious String https://firefart.at triggered"
	strings: $suspicious_string = "https://firefart.at"
	condition: $suspicious_string
}
rule Rule_1244_triggered {
	meta: description = "Rule # 1244 Suspicious String https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c triggered"
	strings: $suspicious_string = "https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c"
	condition: $suspicious_string
}
rule Rule_1245_triggered {
	meta: description = "Rule # 1245 Suspicious String https://twitter.com/nilotpalhacker triggered"
	strings: $suspicious_string = "https://twitter.com/nilotpalhacker"
	condition: $suspicious_string
}
rule Rule_1246_triggered {
	meta: description = "Rule # 1246 Suspicious String https://www.facebook.com/nilotpal.biswas.73 triggered"
	strings: $suspicious_string = "https://www.facebook.com/nilotpal.biswas.73"
	condition: $suspicious_string
}
rule Rule_1247_triggered {
	meta: description = "Rule # 1247 Suspicious String https://www.facebook.com/xaisyndicate triggered"
	strings: $suspicious_string = "https://www.facebook.com/xaisyndicate"
	condition: $suspicious_string
}
rule Rule_1248_triggered {
	meta: description = "Rule # 1248 Suspicious String huken90@gmail.com triggered"
	strings: $suspicious_string = "huken90@gmail.com"
	condition: $suspicious_string
}
rule Rule_1249_triggered {
	meta: description = "Rule # 1249 Suspicious String hussin_v@ymail.com triggered"
	strings: $suspicious_string = "hussin_v@ymail.com"
	condition: $suspicious_string
}
rule Rule_1250_triggered {
	meta: description = "Rule # 1250 Suspicious String i129648e triggered"
	strings: $suspicious_string = "i129648e"
	condition: $suspicious_string
}
rule Rule_1251_triggered {
	meta: description = "Rule # 1251 Suspicious String iLL Skillz triggered"
	strings: $suspicious_string = "iLL Skillz"
	condition: $suspicious_string
}
rule Rule_1252_triggered {
	meta: description = "Rule # 1252 Suspicious String iMHATiMi.ORG triggered"
	strings: $suspicious_string = "iMHATiMi.ORG"
	condition: $suspicious_string
}
rule Rule_1253_triggered {
	meta: description = "Rule # 1253 Suspicious String iamtriumphant07@gmail.com triggered"
	strings: $suspicious_string = "iamtriumphant07@gmail.com"
	condition: $suspicious_string
}
rule Rule_1254_triggered {
	meta: description = "Rule # 1254 Suspicious String if do you want rezultaa text in html file triggered"
	strings: $suspicious_string = "if do you want rezultaa text in html file"
	condition: $suspicious_string
}
rule Rule_1255_triggered {
	meta: description = "Rule # 1255 Suspicious String if you want to victem showed bank page triggered"
	strings: $suspicious_string = "if you want to victem showed bank page"
	condition: $suspicious_string
}
rule Rule_1256_triggered {
	meta: description = "Rule # 1256 Suspicious String imprisond triggered"
	strings: $suspicious_string = "imprisond"
	condition: $suspicious_string
}
rule Rule_1257_triggered {
	meta: description = "Rule # 1257 Suspicious String indoxploit.or.id triggered"
	strings: $suspicious_string = "indoxploit.or.id"
	condition: $suspicious_string
}
rule Rule_1258_triggered {
	meta: description = "Rule # 1258 Suspicious String info@el-nacional.com triggered"
	strings: $suspicious_string = "info@el-nacional.com"
	condition: $suspicious_string
}
rule Rule_1259_triggered {
	meta: description = "Rule # 1259 Suspicious String info@xsender.com triggered"
	strings: $suspicious_string = "info@xsender.com"
	condition: $suspicious_string
}
rule Rule_1260_triggered {
	meta: description = "Rule # 1260 Suspicious String infoicb76@gmail.com triggered"
	strings: $suspicious_string = "infoicb76@gmail.com"
	condition: $suspicious_string
}
rule Rule_1261_triggered {
	meta: description = "Rule # 1261 Suspicious String infos@Aguda.ng triggered"
	strings: $suspicious_string = "infos@Aguda.ng"
	condition: $suspicious_string
}
rule Rule_1262_triggered {
	meta: description = "Rule # 1262 Suspicious String injectoDaher triggered"
	strings: $suspicious_string = "injectoDaher"
	condition: $suspicious_string
}
rule Rule_1263_triggered {
	meta: description = "Rule # 1263 Suspicious String inspiredlean@gmai.com triggered"
	strings: $suspicious_string = "inspiredlean@gmai.com"
	condition: $suspicious_string
}
rule Rule_1264_triggered {
	meta: description = "Rule # 1264 Suspicious String intuit.com triggered"
	strings: $suspicious_string = "intuit.com"
	condition: $suspicious_string
}
rule Rule_1265_triggered {
	meta: description = "Rule # 1265 Suspicious String isek500@aol.com triggered"
	strings: $suspicious_string = "isek500@aol.com"
	condition: $suspicious_string
}
rule Rule_1266_triggered {
	meta: description = "Rule # 1266 Suspicious String iskorpitx triggered"
	strings: $suspicious_string = "iskorpitx"
	condition: $suspicious_string
}
rule Rule_1267_triggered {
	meta: description = "Rule # 1267 Suspicious String itu dosa gan triggered"
	strings: $suspicious_string = "itu dosa gan"
	condition: $suspicious_string
}
rule Rule_1268_triggered {
	meta: description = "Rule # 1268 Suspicious String jacGX triggered"
	strings: $suspicious_string = "jacGX"
	condition: $suspicious_string
}
rule Rule_1269_triggered {
	meta: description = "Rule # 1269 Suspicious String jacksmith3811@gmail.com triggered"
	strings: $suspicious_string = "jacksmith3811@gmail.com"
	condition: $suspicious_string
}
rule Rule_1270_triggered {
	meta: description = "Rule # 1270 Suspicious String jamesmathinsclaims@gmail.com triggered"
	strings: $suspicious_string = "jamesmathinsclaims@gmail.com"
	condition: $suspicious_string
}
rule Rule_1271_triggered {
	meta: description = "Rule # 1271 Suspicious String jancok torok empek asooooooh triggered"
	strings: $suspicious_string = "jancok torok empek asooooooh"
	condition: $suspicious_string
}
rule Rule_1272_triggered {
	meta: description = "Rule # 1272 Suspicious String jbossass.war triggered"
	strings: $suspicious_string = "jbossass.war"
	condition: $suspicious_string
}
rule Rule_1273_triggered {
	meta: description = "Rule # 1273 Suspicious String je253824 triggered"
	strings: $suspicious_string = "je253824"
	condition: $suspicious_string
}
rule Rule_1274_triggered {
	meta: description = "Rule # 1274 Suspicious String jeff4r-partner@tutanota.com triggered"
	strings: $suspicious_string = "jeff4r-partner@tutanota.com"
	condition: $suspicious_string
}
rule Rule_1275_triggered {
	meta: description = "Rule # 1275 Suspicious String jem.smith@yandex.com triggered"
	strings: $suspicious_string = "jem.smith@yandex.com"
	condition: $suspicious_string
}
rule Rule_1276_triggered {
	meta: description = "Rule # 1276 Suspicious String jepry_vuln  triggered"
	strings: $suspicious_string = "jepry_vuln "
	condition: $suspicious_string
}
rule Rule_1277_triggered {
	meta: description = "Rule # 1277 Suspicious String jessica_biel_naked_in_my_bed.c triggered"
	strings: $suspicious_string = "jessica_biel_naked_in_my_bed.c"
	condition: $suspicious_string
}
rule Rule_1278_triggered {
	meta: description = "Rule # 1278 Suspicious String jexboss triggered"
	strings: $suspicious_string = "jexboss"
	condition: $suspicious_string
}
rule Rule_1279_triggered {
	meta: description = "Rule # 1279 Suspicious String jo mass info changer triggered"
	strings: $suspicious_string = "jo mass info changer"
	condition: $suspicious_string
}
rule Rule_1280_triggered {
	meta: description = "Rule # 1280 Suspicious String joaomatosf.com triggered"
	strings: $suspicious_string = "joaomatosf.com"
	condition: $suspicious_string
}
rule Rule_1281_triggered {
	meta: description = "Rule # 1281 Suspicious String johnsonjames002dc@outlook.com triggered"
	strings: $suspicious_string = "johnsonjames002dc@outlook.com"
	condition: $suspicious_string
}
rule Rule_1282_triggered {
	meta: description = "Rule # 1282 Suspicious String jugaad XD triggered"
	strings: $suspicious_string = "jugaad XD"
	condition: $suspicious_string
}
rule Rule_1283_triggered {
	meta: description = "Rule # 1283 Suspicious String junglesec@anonymousspeech.com triggered"
	strings: $suspicious_string = "junglesec@anonymousspeech.com"
	condition: $suspicious_string
}
rule Rule_1284_triggered {
	meta: description = "Rule # 1284 Suspicious String jwcucfcqiqs triggered"
	strings: $suspicious_string = "jwcucfcqiqs"
	condition: $suspicious_string
}
rule Rule_1285_triggered {
	meta: description = "Rule # 1285 Suspicious String jweyc triggered"
	strings: $suspicious_string = "jweyc"
	condition: $suspicious_string
}
rule Rule_1286_triggered {
	meta: description = "Rule # 1286 Suspicious String k2ll33d triggered"
	strings: $suspicious_string = "k2ll33d"
	condition: $suspicious_string
}
rule Rule_1287_triggered {
	meta: description = "Rule # 1287 Suspicious String k2ll33d shell triggered"
	strings: $suspicious_string = "k2ll33d shell"
	condition: $suspicious_string
}
rule Rule_1288_triggered {
	meta: description = "Rule # 1288 Suspicious String k3y r3ZulT triggered"
	strings: $suspicious_string = "k3y r3ZulT"
	condition: $suspicious_string
}
rule Rule_1289_triggered {
	meta: description = "Rule # 1289 Suspicious String k4l0nk triggered"
	strings: $suspicious_string = "k4l0nk"
	condition: $suspicious_string
}
rule Rule_1290_triggered {
	meta: description = "Rule # 1290 Suspicious String kaMtiEz triggered"
	strings: $suspicious_string = "kaMtiEz"
	condition: $suspicious_string
}
rule Rule_1291_triggered {
	meta: description = "Rule # 1291 Suspicious String kefiex404    triggered"
	strings: $suspicious_string = "kefiex404   "
	condition: $suspicious_string
}
rule Rule_1292_triggered {
	meta: description = "Rule # 1292 Suspicious String kerde khaat khadi triggered"
	strings: $suspicious_string = "kerde khaat khadi"
	condition: $suspicious_string
}
rule Rule_1293_triggered {
	meta: description = "Rule # 1293 Suspicious String ki739937@gmail.com triggered"
	strings: $suspicious_string = "ki739937@gmail.com"
	condition: $suspicious_string
}
rule Rule_1294_triggered {
	meta: description = "Rule # 1294 Suspicious String kid Security Team triggered"
	strings: $suspicious_string = "kid Security Team"
	condition: $suspicious_string
}
rule Rule_1295_triggered {
	meta: description = "Rule # 1295 Suspicious String kid Si Vip Security Team triggered"
	strings: $suspicious_string = "kid Si Vip Security Team"
	condition: $suspicious_string
}
rule Rule_1296_triggered {
	meta: description = "Rule # 1296 Suspicious String kinbokun2234@gmail.com triggered"
	strings: $suspicious_string = "kinbokun2234@gmail.com"
	condition: $suspicious_string
}
rule Rule_1297_triggered {
	meta: description = "Rule # 1297 Suspicious String kntnight@gmail.com triggered"
	strings: $suspicious_string = "kntnight@gmail.com"
	condition: $suspicious_string
}
rule Rule_1298_triggered {
	meta: description = "Rule # 1298 Suspicious String kohehasa@gmail.com triggered"
	strings: $suspicious_string = "kohehasa@gmail.com"
	condition: $suspicious_string
}
rule Rule_1299_triggered {
	meta: description = "Rule # 1299 Suspicious String koneksi eror     triggered"
	strings: $suspicious_string = "koneksi eror    "
	condition: $suspicious_string
}
rule Rule_1300_triggered {
	meta: description = "Rule # 1300 Suspicious String krad.c triggered"
	strings: $suspicious_string = "krad.c"
	condition: $suspicious_string
}
rule Rule_1301_triggered {
	meta: description = "Rule # 1301 Suspicious String kunlexy triggered"
	strings: $suspicious_string = "kunlexy"
	condition: $suspicious_string
}
rule Rule_1302_triggered {
	meta: description = "Rule # 1302 Suspicious String l14deaad triggered"
	strings: $suspicious_string = "l14deaad"
	condition: $suspicious_string
}
rule Rule_1303_triggered {
	meta: description = "Rule # 1303 Suspicious String l2ncbf06ku_1psr8yxia triggered"
	strings: $suspicious_string = "l2ncbf06ku_1psr8yxia"
	condition: $suspicious_string
}
rule Rule_1304_triggered {
	meta: description = "Rule # 1304 Suspicious String lalabitch.php triggered"
	strings: $suspicious_string = "lalabitch.php"
	condition: $suspicious_string
}
rule Rule_1305_triggered {
	meta: description = "Rule # 1305 Suspicious String lassp2030@gmail.com triggered"
	strings: $suspicious_string = "lassp2030@gmail.com"
	condition: $suspicious_string
}
rule Rule_1306_triggered {
	meta: description = "Rule # 1306 Suspicious String laterain testin9 triggered"
	strings: $suspicious_string = "laterain testin9"
	condition: $suspicious_string
}
rule Rule_1307_triggered {
	meta: description = "Rule # 1307 Suspicious String leahmc1@rocketmail.com triggered"
	strings: $suspicious_string = "leahmc1@rocketmail.com"
	condition: $suspicious_string
}
rule Rule_1308_triggered {
	meta: description = "Rule # 1308 Suspicious String legend.rocks triggered"
	strings: $suspicious_string = "legend.rocks"
	condition: $suspicious_string
}
rule Rule_1309_triggered {
	meta: description = "Rule # 1309 Suspicious String linus.danny@outlook.com triggered"
	strings: $suspicious_string = "linus.danny@outlook.com"
	condition: $suspicious_string
}
rule Rule_1310_triggered {
	meta: description = "Rule # 1310 Suspicious String linusdanny7@gmail.com triggered"
	strings: $suspicious_string = "linusdanny7@gmail.com"
	condition: $suspicious_string
}
rule Rule_1311_triggered {
	meta: description = "Rule # 1311 Suspicious String linux-op.com triggered"
	strings: $suspicious_string = "linux-op.com"
	condition: $suspicious_string
}
rule Rule_1312_triggered {
	meta: description = "Rule # 1312 Suspicious String lithest triggered"
	strings: $suspicious_string = "lithest"
	condition: $suspicious_string
}
rule Rule_1313_triggered {
	meta: description = "Rule # 1313 Suspicious String localhost_80@hotmail.com triggered"
	strings: $suspicious_string = "localhost_80@hotmail.com"
	condition: $suspicious_string
}
rule Rule_1314_triggered {
	meta: description = "Rule # 1314 Suspicious String login.yahoo.com triggered"
	strings: $suspicious_string = "login.yahoo.com"
	condition: $suspicious_string
}
rule Rule_1315_triggered {
	meta: description = "Rule # 1315 Suspicious String lovetherisk<br>Suriya Prakash triggered"
	strings: $suspicious_string = "lovetherisk<br>Suriya Prakash"
	condition: $suspicious_string
}
rule Rule_1316_triggered {
	meta: description = "Rule # 1316 Suspicious String lt@mac.hush.com triggered"
	strings: $suspicious_string = "lt@mac.hush.com"
	condition: $suspicious_string
}
rule Rule_1317_triggered {
	meta: description = "Rule # 1317 Suspicious String luis.arnold12@yahoo.com triggered"
	strings: $suspicious_string = "luis.arnold12@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1318_triggered {
	meta: description = "Rule # 1318 Suspicious String luxury handbags triggered"
	strings: $suspicious_string = "luxury handbags"
	condition: $suspicious_string
}
rule Rule_1319_triggered {
	meta: description = "Rule # 1319 Suspicious String lymanlymco triggered"
	strings: $suspicious_string = "lymanlymco"
	condition: $suspicious_string
}
rule Rule_1320_triggered {
	meta: description = "Rule # 1320 Suspicious String m0rtix triggered"
	strings: $suspicious_string = "m0rtix"
	condition: $suspicious_string
}
rule Rule_1321_triggered {
	meta: description = "Rule # 1321 Suspicious String m2118d22d991cc8bfb66304d5bd2ee973 triggered"
	strings: $suspicious_string = "m2118d22d991cc8bfb66304d5bd2ee973"
	condition: $suspicious_string
}
rule Rule_1322_triggered {
	meta: description = "Rule # 1322 Suspicious String m@db100d  triggered"
	strings: $suspicious_string = "m@db100d "
	condition: $suspicious_string
}
rule Rule_1323_triggered {
	meta: description = "Rule # 1323 Suspicious String madubueze.simon@yahoo.com triggered"
	strings: $suspicious_string = "madubueze.simon@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1324_triggered {
	meta: description = "Rule # 1324 Suspicious String mageonline.net/js/mage.js triggered"
	strings: $suspicious_string = "mageonline.net/js/mage.js"
	condition: $suspicious_string
}
rule Rule_1325_triggered {
	meta: description = "Rule # 1325 Suspicious String mahdi WAS HERE triggered"
	strings: $suspicious_string = "mahdi WAS HERE"
	condition: $suspicious_string
}
rule Rule_1326_triggered {
	meta: description = "Rule # 1326 Suspicious String mahmud.ghazni.1 triggered"
	strings: $suspicious_string = "mahmud.ghazni.1"
	condition: $suspicious_string
}
rule Rule_1327_triggered {
	meta: description = "Rule # 1327 Suspicious String mahmud.ghazni@yahoo.com triggered"
	strings: $suspicious_string = "mahmud.ghazni@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1328_triggered {
	meta: description = "Rule # 1328 Suspicious String makman.php triggered"
	strings: $suspicious_string = "makman.php"
	condition: $suspicious_string
}
rule Rule_1329_triggered {
	meta: description = "Rule # 1329 Suspicious String managedforexaccount triggered"
	strings: $suspicious_string = "managedforexaccount"
	condition: $suspicious_string
}
rule Rule_1330_triggered {
	meta: description = "Rule # 1330 Suspicious String marli.vianna00@gmail.com triggered"
	strings: $suspicious_string = "marli.vianna00@gmail.com"
	condition: $suspicious_string
}
rule Rule_1331_triggered {
	meta: description = "Rule # 1331 Suspicious String mass defacer and log eraser triggered"
	strings: $suspicious_string = "mass defacer and log eraser"
	condition: $suspicious_string
}
rule Rule_1332_triggered {
	meta: description = "Rule # 1332 Suspicious String matamu picek triggered"
	strings: $suspicious_string = "matamu picek"
	condition: $suspicious_string
}
rule Rule_1333_triggered {
	meta: description = "Rule # 1333 Suspicious String mauritania attacker triggered"
	strings: $suspicious_string = "mauritania attacker"
	condition: $suspicious_string
}
rule Rule_1334_triggered {
	meta: description = "Rule # 1334 Suspicious String md5decrpter triggered"
	strings: $suspicious_string = "md5decrpter"
	condition: $suspicious_string
}
rule Rule_1335_triggered {
	meta: description = "Rule # 1335 Suspicious String me@faialahmed.me triggered"
	strings: $suspicious_string = "me@faialahmed.me"
	condition: $suspicious_string
}
rule Rule_1336_triggered {
	meta: description = "Rule # 1336 Suspicious String mer4en7y triggered"
	strings: $suspicious_string = "mer4en7y"
	condition: $suspicious_string
}
rule Rule_1337_triggered {
	meta: description = "Rule # 1337 Suspicious String mercychase1@gmail.com triggered"
	strings: $suspicious_string = "mercychase1@gmail.com"
	condition: $suspicious_string
}
rule Rule_1338_triggered {
	meta: description = "Rule # 1338 Suspicious String mesaegs triggered"
	strings: $suspicious_string = "mesaegs"
	condition: $suspicious_string
}
rule Rule_1339_triggered {
	meta: description = "Rule # 1339 Suspicious String mhmadmasrwe triggered"
	strings: $suspicious_string = "mhmadmasrwe"
	condition: $suspicious_string
}
rule Rule_1340_triggered {
	meta: description = "Rule # 1340 Suspicious String micheal5ur3@gmail.com triggered"
	strings: $suspicious_string = "micheal5ur3@gmail.com"
	condition: $suspicious_string
}
rule Rule_1341_triggered {
	meta: description = "Rule # 1341 Suspicious String micr0s0flt.acc0unt@hotmail.com triggered"
	strings: $suspicious_string = "micr0s0flt.acc0unt@hotmail.com"
	condition: $suspicious_string
}
rule Rule_1342_triggered {
	meta: description = "Rule # 1342 Suspicious String mike waals triggered"
	strings: $suspicious_string = "mike waals"
	condition: $suspicious_string
}
rule Rule_1343_triggered {
	meta: description = "Rule # 1343 Suspicious String milw0rm triggered"
	strings: $suspicious_string = "milw0rm"
	condition: $suspicious_string
}
rule Rule_1344_triggered {
	meta: description = "Rule # 1344 Suspicious String minexmr triggered"
	strings: $suspicious_string = "minexmr"
	condition: $suspicious_string
}
rule Rule_1345_triggered {
	meta: description = "Rule # 1345 Suspicious String monoki.atspace.com triggered"
	strings: $suspicious_string = "monoki.atspace.com"
	condition: $suspicious_string
}
rule Rule_1346_triggered {
	meta: description = "Rule # 1346 Suspicious String mooremoney1900@gmail.com triggered"
	strings: $suspicious_string = "mooremoney1900@gmail.com"
	condition: $suspicious_string
}
rule Rule_1347_triggered {
	meta: description = "Rule # 1347 Suspicious String morganstanley.com triggered"
	strings: $suspicious_string = "morganstanley.com"
	condition: $suspicious_string
}
rule Rule_1348_triggered {
	meta: description = "Rule # 1348 Suspicious String mr.cookie_302 triggered"
	strings: $suspicious_string = "mr.cookie_302"
	condition: $suspicious_string
}
rule Rule_1349_triggered {
	meta: description = "Rule # 1349 Suspicious String mtwer.com triggered"
	strings: $suspicious_string = "mtwer.com"
	condition: $suspicious_string
}
rule Rule_1350_triggered {
	meta: description = "Rule # 1350 Suspicious String mugiwaranoluffy@fastmail.com triggered"
	strings: $suspicious_string = "mugiwaranoluffy@fastmail.com"
	condition: $suspicious_string
}
rule Rule_1351_triggered {
	meta: description = "Rule # 1351 Suspicious String mvp.collinsrobinson@mail.ru triggered"
	strings: $suspicious_string = "mvp.collinsrobinson@mail.ru"
	condition: $suspicious_string
}
rule Rule_1352_triggered {
	meta: description = "Rule # 1352 Suspicious String myrealday1@gmail.com triggered"
	strings: $suspicious_string = "myrealday1@gmail.com"
	condition: $suspicious_string
}
rule Rule_1353_triggered {
	meta: description = "Rule # 1353 Suspicious String n5c098ab8546b2 triggered"
	strings: $suspicious_string = "n5c098ab8546b2"
	condition: $suspicious_string
}
rule Rule_1354_triggered {
	meta: description = "Rule # 1354 Suspicious String n96I4A33EYNVO71FC.Program triggered"
	strings: $suspicious_string = "n96I4A33EYNVO71FC.Program"
	condition: $suspicious_string
}
rule Rule_1355_triggered {
	meta: description = "Rule # 1355 Suspicious String n9nj2.X triggered"
	strings: $suspicious_string = "n9nj2.X"
	condition: $suspicious_string
}
rule Rule_1356_triggered {
	meta: description = "Rule # 1356 Suspicious String neighborer triggered"
	strings: $suspicious_string = "neighborer"
	condition: $suspicious_string
}
rule Rule_1357_triggered {
	meta: description = "Rule # 1357 Suspicious String netjackal.by.ru triggered"
	strings: $suspicious_string = "netjackal.by.ru"
	condition: $suspicious_string
}
rule Rule_1358_triggered {
	meta: description = "Rule # 1358 Suspicious String newCredentials triggered"
	strings: $suspicious_string = "newCredentials"
	condition: $suspicious_string
}
rule Rule_1359_triggered {
	meta: description = "Rule # 1359 Suspicious String newbie patah hati  triggered"
	strings: $suspicious_string = "newbie patah hati "
	condition: $suspicious_string
}
rule Rule_1360_triggered {
	meta: description = "Rule # 1360 Suspicious String neweggstats.com triggered"
	strings: $suspicious_string = "neweggstats.com"
	condition: $suspicious_string
}
rule Rule_1361_triggered {
	meta: description = "Rule # 1361 Suspicious String newlife1470@gmail.com triggered"
	strings: $suspicious_string = "newlife1470@gmail.com"
	condition: $suspicious_string
}
rule Rule_1362_triggered {
	meta: description = "Rule # 1362 Suspicious String newmeak@gmail.com triggered"
	strings: $suspicious_string = "newmeak@gmail.com"
	condition: $suspicious_string
}
rule Rule_1363_triggered {
	meta: description = "Rule # 1363 Suspicious String newsupdate@servicedrive.com triggered"
	strings: $suspicious_string = "newsupdate@servicedrive.com"
	condition: $suspicious_string
}
rule Rule_1364_triggered {
	meta: description = "Rule # 1364 Suspicious String newsupdate@servisdropbox.com triggered"
	strings: $suspicious_string = "newsupdate@servisdropbox.com"
	condition: $suspicious_string
}
rule Rule_1365_triggered {
	meta: description = "Rule # 1365 Suspicious String newsupdated@servisd.com triggered"
	strings: $suspicious_string = "newsupdated@servisd.com"
	condition: $suspicious_string
}
rule Rule_1366_triggered {
	meta: description = "Rule # 1366 Suspicious String nginx1337 triggered"
	strings: $suspicious_string = "nginx1337"
	condition: $suspicious_string
}
rule Rule_1367_triggered {
	meta: description = "Rule # 1367 Suspicious String nighttgr33n triggered"
	strings: $suspicious_string = "nighttgr33n"
	condition: $suspicious_string
}
rule Rule_1368_triggered {
	meta: description = "Rule # 1368 Suspicious String ninja_1263 triggered"
	strings: $suspicious_string = "ninja_1263"
	condition: $suspicious_string
}
rule Rule_1369_triggered {
	meta: description = "Rule # 1369 Suspicious String notification.job@gmail.com triggered"
	strings: $suspicious_string = "notification.job@gmail.com"
	condition: $suspicious_string
}
rule Rule_1370_triggered {
	meta: description = "Rule # 1370 Suspicious String o8aedac7 triggered"
	strings: $suspicious_string = "o8aedac7"
	condition: $suspicious_string
}
rule Rule_1371_triggered {
	meta: description = "Rule # 1371 Suspicious String oalah asoooooooooooh triggered"
	strings: $suspicious_string = "oalah asoooooooooooh"
	condition: $suspicious_string
}
rule Rule_1372_triggered {
	meta: description = "Rule # 1372 Suspicious String oficeofthe@gmail.com triggered"
	strings: $suspicious_string = "oficeofthe@gmail.com"
	condition: $suspicious_string
}
rule Rule_1373_triggered {
	meta: description = "Rule # 1373 Suspicious String online encode by cha88.cn triggered"
	strings: $suspicious_string = "online encode by cha88.cn"
	condition: $suspicious_string
}
rule Rule_1374_triggered {
	meta: description = "Rule # 1374 Suspicious String owhggiku triggered"
	strings: $suspicious_string = "owhggiku"
	condition: $suspicious_string
}
rule Rule_1375_triggered {
	meta: description = "Rule # 1375 Suspicious String ownersdirectorsintl@gmail.com triggered"
	strings: $suspicious_string = "ownersdirectorsintl@gmail.com"
	condition: $suspicious_string
}
rule Rule_1376_triggered {
	meta: description = "Rule # 1376 Suspicious String ozcanlesbigboss@hotmail.fr triggered"
	strings: $suspicious_string = "ozcanlesbigboss@hotmail.fr"
	condition: $suspicious_string
}
rule Rule_1377_triggered {
	meta: description = "Rule # 1377 Suspicious String ozlok  triggered"
	strings: $suspicious_string = "ozlok "
	condition: $suspicious_string
}
rule Rule_1378_triggered {
	meta: description = "Rule # 1378 Suspicious String p0wny@shell triggered"
	strings: $suspicious_string = "p0wny@shell"
	condition: $suspicious_string
}
rule Rule_1379_triggered {
	meta: description = "Rule # 1379 Suspicious String p1mmaxweel@gmail.com triggered"
	strings: $suspicious_string = "p1mmaxweel@gmail.com"
	condition: $suspicious_string
}
rule Rule_1380_triggered {
	meta: description = "Rule # 1380 Suspicious String p4rs.net triggered"
	strings: $suspicious_string = "p4rs.net"
	condition: $suspicious_string
}
rule Rule_1381_triggered {
	meta: description = "Rule # 1381 Suspicious String p62a2e triggered"
	strings: $suspicious_string = "p62a2e"
	condition: $suspicious_string
}
rule Rule_1382_triggered {
	meta: description = "Rule # 1382 Suspicious String pOcOpOcO triggered"
	strings: $suspicious_string = "pOcOpOcO"
	condition: $suspicious_string
}
rule Rule_1383_triggered {
	meta: description = "Rule # 1383 Suspicious String passwbypass triggered"
	strings: $suspicious_string = "passwbypass"
	condition: $suspicious_string
}
rule Rule_1384_triggered {
	meta: description = "Rule # 1384 Suspicious String paulodadaj1@gmail.com triggered"
	strings: $suspicious_string = "paulodadaj1@gmail.com"
	condition: $suspicious_string
}
rule Rule_1385_triggered {
	meta: description = "Rule # 1385 Suspicious String php SSH triggered"
	strings: $suspicious_string = "php SSH"
	condition: $suspicious_string
}
rule Rule_1386_triggered {
	meta: description = "Rule # 1386 Suspicious String php_ini@126.com triggered"
	strings: $suspicious_string = "php_ini@126.com"
	condition: $suspicious_string
}
rule Rule_1387_triggered {
	meta: description = "Rule # 1387 Suspicious String phpremoteview triggered"
	strings: $suspicious_string = "phpremoteview"
	condition: $suspicious_string
}
rule Rule_1388_triggered {
	meta: description = "Rule # 1388 Suspicious String phpshell triggered"
	strings: $suspicious_string = "phpshell"
	condition: $suspicious_string
}
rule Rule_1389_triggered {
	meta: description = "Rule # 1389 Suspicious String phpsploitclass.php triggered"
	strings: $suspicious_string = "phpsploitclass.php"
	condition: $suspicious_string
}
rule Rule_1390_triggered {
	meta: description = "Rule # 1390 Suspicious String phpspypass triggered"
	strings: $suspicious_string = "phpspypass"
	condition: $suspicious_string
}
rule Rule_1391_triggered {
	meta: description = "Rule # 1391 Suspicious String pokemon exploit triggered"
	strings: $suspicious_string = "pokemon exploit"
	condition: $suspicious_string
}
rule Rule_1392_triggered {
	meta: description = "Rule # 1392 Suspicious String portal-f triggered"
	strings: $suspicious_string = "portal-f"
	condition: $suspicious_string
}
rule Rule_1393_triggered {
	meta: description = "Rule # 1393 Suspicious String poti.sadz@gmail.com triggered"
	strings: $suspicious_string = "poti.sadz@gmail.com"
	condition: $suspicious_string
}
rule Rule_1394_triggered {
	meta: description = "Rule # 1394 Suspicious String powered by os comerce triggered"
	strings: $suspicious_string = "powered by os comerce"
	condition: $suspicious_string
}
rule Rule_1395_triggered {
	meta: description = "Rule # 1395 Suspicious String prappo-prince.me triggered"
	strings: $suspicious_string = "prappo-prince.me"
	condition: $suspicious_string
}
rule Rule_1396_triggered {
	meta: description = "Rule # 1396 Suspicious String prepare_the_exploit triggered"
	strings: $suspicious_string = "prepare_the_exploit"
	condition: $suspicious_string
}
rule Rule_1397_triggered {
	meta: description = "Rule # 1397 Suspicious String psherwoodmarketing@gmail.com triggered"
	strings: $suspicious_string = "psherwoodmarketing@gmail.com"
	condition: $suspicious_string
}
rule Rule_1398_triggered {
	meta: description = "Rule # 1398 Suspicious String psybnc triggered"
	strings: $suspicious_string = "psybnc"
	condition: $suspicious_string
}
rule Rule_1399_triggered {
	meta: description = "Rule # 1399 Suspicious String ptrace_pokedata triggered"
	strings: $suspicious_string = "ptrace_pokedata"
	condition: $suspicious_string
}
rule Rule_1400_triggered {
	meta: description = "Rule # 1400 Suspicious String pw/XcTyTp triggered"
	strings: $suspicious_string = "pw/XcTyTp"
	condition: $suspicious_string
}
rule Rule_1401_triggered {
	meta: description = "Rule # 1401 Suspicious String pw/bash/include/xtaccess triggered"
	strings: $suspicious_string = "pw/bash/include/xtaccess"
	condition: $suspicious_string
}
rule Rule_1402_triggered {
	meta: description = "Rule # 1402 Suspicious String pwned triggered"
	strings: $suspicious_string = "pwned"
	condition: $suspicious_string
}
rule Rule_1403_triggered {
	meta: description = "Rule # 1403 Suspicious String python connect-back door triggered"
	strings: $suspicious_string = "python connect-back door"
	condition: $suspicious_string
}
rule Rule_1404_triggered {
	meta: description = "Rule # 1404 Suspicious String qusckboendqg triggered"
	strings: $suspicious_string = "qusckboendqg"
	condition: $suspicious_string
}
rule Rule_1405_triggered {
	meta: description = "Rule # 1405 Suspicious String r00txxPcP triggered"
	strings: $suspicious_string = "r00txxPcP"
	condition: $suspicious_string
}
rule Rule_1406_triggered {
	meta: description = "Rule # 1406 Suspicious String r0nin triggered"
	strings: $suspicious_string = "r0nin"
	condition: $suspicious_string
}
rule Rule_1407_triggered {
	meta: description = "Rule # 1407 Suspicious String r3coded by Kerupuk triggered"
	strings: $suspicious_string = "r3coded by Kerupuk"
	condition: $suspicious_string
}
rule Rule_1408_triggered {
	meta: description = "Rule # 1408 Suspicious String r3v3ng4ns triggered"
	strings: $suspicious_string = "r3v3ng4ns"
	condition: $suspicious_string
}
rule Rule_1409_triggered {
	meta: description = "Rule # 1409 Suspicious String r57 triggered"
	strings: $suspicious_string = "r57"
	condition: $suspicious_string
}
rule Rule_1410_triggered {
	meta: description = "Rule # 1410 Suspicious String rEd X triggered"
	strings: $suspicious_string = "rEd X"
	condition: $suspicious_string
}
rule Rule_1411_triggered {
	meta: description = "Rule # 1411 Suspicious String rOx triggered"
	strings: $suspicious_string = "rOx"
	condition: $suspicious_string
}
rule Rule_1412_triggered {
	meta: description = "Rule # 1412 Suspicious String rWmpisiBWQglW/n3OBtqwt8T0NwjeiW+8Kd9N triggered"
	strings: $suspicious_string = "rWmpisiBWQglW/n3OBtqwt8T0NwjeiW+8Kd9N"
	condition: $suspicious_string
}
rule Rule_1413_triggered {
	meta: description = "Rule # 1413 Suspicious String rab3oun.net triggered"
	strings: $suspicious_string = "rab3oun.net"
	condition: $suspicious_string
}
rule Rule_1414_triggered {
	meta: description = "Rule # 1414 Suspicious String rad paul triggered"
	strings: $suspicious_string = "rad paul"
	condition: $suspicious_string
}
rule Rule_1415_triggered {
	meta: description = "Rule # 1415 Suspicious String ransomeware@Lalabitch.today triggered"
	strings: $suspicious_string = "ransomeware@Lalabitch.today"
	condition: $suspicious_string
}
rule Rule_1416_triggered {
	meta: description = "Rule # 1416 Suspicious String raslan58 triggered"
	strings: $suspicious_string = "raslan58"
	condition: $suspicious_string
}
rule Rule_1417_triggered {
	meta: description = "Rule # 1417 Suspicious String recaptcha-in triggered"
	strings: $suspicious_string = "recaptcha-in"
	condition: $suspicious_string
}
rule Rule_1418_triggered {
	meta: description = "Rule # 1418 Suspicious String rednoize triggered"
	strings: $suspicious_string = "rednoize"
	condition: $suspicious_string
}
rule Rule_1419_triggered {
	meta: description = "Rule # 1419 Suspicious String regions.com triggered"
	strings: $suspicious_string = "regions.com"
	condition: $suspicious_string
}
rule Rule_1420_triggered {
	meta: description = "Rule # 1420 Suspicious String renownd triggered"
	strings: $suspicious_string = "renownd"
	condition: $suspicious_string
}
rule Rule_1421_triggered {
	meta: description = "Rule # 1421 Suspicious String reply@result.com triggered"
	strings: $suspicious_string = "reply@result.com"
	condition: $suspicious_string
}
rule Rule_1422_triggered {
	meta: description = "Rule # 1422 Suspicious String reputable3811@yandex.com triggered"
	strings: $suspicious_string = "reputable3811@yandex.com"
	condition: $suspicious_string
}
rule Rule_1423_triggered {
	meta: description = "Rule # 1423 Suspicious String resultbox99999@gmail.com triggered"
	strings: $suspicious_string = "resultbox99999@gmail.com"
	condition: $suspicious_string
}
rule Rule_1424_triggered {
	meta: description = "Rule # 1424 Suspicious String resultshere2@gmail.com triggered"
	strings: $suspicious_string = "resultshere2@gmail.com"
	condition: $suspicious_string
}
rule Rule_1425_triggered {
	meta: description = "Rule # 1425 Suspicious String romio2_100@yahoo.com triggered"
	strings: $suspicious_string = "romio2_100@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1426_triggered {
	meta: description = "Rule # 1426 Suspicious String root@indoxploit triggered"
	strings: $suspicious_string = "root@indoxploit"
	condition: $suspicious_string
}
rule Rule_1427_triggered {
	meta: description = "Rule # 1427 Suspicious String root_devil triggered"
	strings: $suspicious_string = "root_devil"
	condition: $suspicious_string
}
rule Rule_1428_triggered {
	meta: description = "Rule # 1428 Suspicious String roottn@vodka triggered"
	strings: $suspicious_string = "roottn@vodka"
	condition: $suspicious_string
}
rule Rule_1429_triggered {
	meta: description = "Rule # 1429 Suspicious String rosekellymsk2@gmail.com triggered"
	strings: $suspicious_string = "rosekellymsk2@gmail.com"
	condition: $suspicious_string
}
rule Rule_1430_triggered {
	meta: description = "Rule # 1430 Suspicious String royalbank.com triggered"
	strings: $suspicious_string = "royalbank.com"
	condition: $suspicious_string
}
rule Rule_1431_triggered {
	meta: description = "Rule # 1431 Suspicious String s3a8ece triggered"
	strings: $suspicious_string = "s3a8ece"
	condition: $suspicious_string
}
rule Rule_1432_triggered {
	meta: description = "Rule # 1432 Suspicious String s3cre3t    triggered"
	strings: $suspicious_string = "s3cre3t   "
	condition: $suspicious_string
}
rule Rule_1433_triggered {
	meta: description = "Rule # 1433 Suspicious String s3n4t00r triggered"
	strings: $suspicious_string = "s3n4t00r"
	condition: $suspicious_string
}
rule Rule_1434_triggered {
	meta: description = "Rule # 1434 Suspicious String sHaf00n triggered"
	strings: $suspicious_string = "sHaf00n"
	condition: $suspicious_string
}
rule Rule_1435_triggered {
	meta: description = "Rule # 1435 Suspicious String saatchiart.com triggered"
	strings: $suspicious_string = "saatchiart.com"
	condition: $suspicious_string
}
rule Rule_1436_triggered {
	meta: description = "Rule # 1436 Suspicious String safecheck1.net triggered"
	strings: $suspicious_string = "safecheck1.net"
	condition: $suspicious_string
}
rule Rule_1437_triggered {
	meta: description = "Rule # 1437 Suspicious String sandranix001@hotmail.com triggered"
	strings: $suspicious_string = "sandranix001@hotmail.com"
	condition: $suspicious_string
}
rule Rule_1438_triggered {
	meta: description = "Rule # 1438 Suspicious String sant.marasliyanziylan@gmail.com triggered"
	strings: $suspicious_string = "sant.marasliyanziylan@gmail.com"
	condition: $suspicious_string
}
rule Rule_1439_triggered {
	meta: description = "Rule # 1439 Suspicious String sc.imp.live.com triggered"
	strings: $suspicious_string = "sc.imp.live.com"
	condition: $suspicious_string
}
rule Rule_1440_triggered {
	meta: description = "Rule # 1440 Suspicious String scotiabank.com triggered"
	strings: $suspicious_string = "scotiabank.com"
	condition: $suspicious_string
}
rule Rule_1441_triggered {
	meta: description = "Rule # 1441 Suspicious String sec-w.com triggered"
	strings: $suspicious_string = "sec-w.com"
	condition: $suspicious_string
}
rule Rule_1442_triggered {
	meta: description = "Rule # 1442 Suspicious String semi-priv8 triggered"
	strings: $suspicious_string = "semi-priv8"
	condition: $suspicious_string
}
rule Rule_1443_triggered {
	meta: description = "Rule # 1443 Suspicious String send an report to  triggered"
	strings: $suspicious_string = "send an report to "
	condition: $suspicious_string
}
rule Rule_1444_triggered {
	meta: description = "Rule # 1444 Suspicious String serjoi.colmadory@gmail.com triggered"
	strings: $suspicious_string = "serjoi.colmadory@gmail.com"
	condition: $suspicious_string
}
rule Rule_1445_triggered {
	meta: description = "Rule # 1445 Suspicious String sgtdennisnathan@gmail.com triggered"
	strings: $suspicious_string = "sgtdennisnathan@gmail.com"
	condition: $suspicious_string
}
rule Rule_1446_triggered {
	meta: description = "Rule # 1446 Suspicious String sh3LL triggered"
	strings: $suspicious_string = "sh3LL"
	condition: $suspicious_string
}
rule Rule_1447_triggered {
	meta: description = "Rule # 1447 Suspicious String shad0wLin3 triggered"
	strings: $suspicious_string = "shad0wLin3"
	condition: $suspicious_string
}
rule Rule_1448_triggered {
	meta: description = "Rule # 1448 Suspicious String shawnphill77345@aol.in triggered"
	strings: $suspicious_string = "shawnphill77345@aol.in"
	condition: $suspicious_string
}
rule Rule_1449_triggered {
	meta: description = "Rule # 1449 Suspicious String shellbot triggered"
	strings: $suspicious_string = "shellbot"
	condition: $suspicious_string
}
rule Rule_1450_triggered {
	meta: description = "Rule # 1450 Suspicious String shellchk triggered"
	strings: $suspicious_string = "shellchk"
	condition: $suspicious_string
}
rule Rule_1451_triggered {
	meta: description = "Rule # 1451 Suspicious String shellinvoker triggered"
	strings: $suspicious_string = "shellinvoker"
	condition: $suspicious_string
}
rule Rule_1452_triggered {
	meta: description = "Rule # 1452 Suspicious String shellololol triggered"
	strings: $suspicious_string = "shellololol"
	condition: $suspicious_string
}
rule Rule_1453_triggered {
	meta: description = "Rule # 1453 Suspicious String shellw0rm triggered"
	strings: $suspicious_string = "shellw0rm"
	condition: $suspicious_string
}
rule Rule_1454_triggered {
	meta: description = "Rule # 1454 Suspicious String shl-ed1 triggered"
	strings: $suspicious_string = "shl-ed1"
	condition: $suspicious_string
}
rule Rule_1455_triggered {
	meta: description = "Rule # 1455 Suspicious String silent hacker triggered"
	strings: $suspicious_string = "silent hacker"
	condition: $suspicious_string
}
rule Rule_1456_triggered {
	meta: description = "Rule # 1456 Suspicious String skyline@cash4u.com triggered"
	strings: $suspicious_string = "skyline@cash4u.com"
	condition: $suspicious_string
}
rule Rule_1457_triggered {
	meta: description = "Rule # 1457 Suspicious String slac4ever@gmail.com triggered"
	strings: $suspicious_string = "slac4ever@gmail.com"
	condition: $suspicious_string
}
rule Rule_1458_triggered {
	meta: description = "Rule # 1458 Suspicious String solevisible@gmail.com triggered"
	strings: $suspicious_string = "solevisible@gmail.com"
	condition: $suspicious_string
}
rule Rule_1459_triggered {
	meta: description = "Rule # 1459 Suspicious String spKINGS.com triggered"
	strings: $suspicious_string = "spKINGS.com"
	condition: $suspicious_string
}
rule Rule_1460_triggered {
	meta: description = "Rule # 1460 Suspicious String spam_rezult@spammerindo.com triggered"
	strings: $suspicious_string = "spam_rezult@spammerindo.com"
	condition: $suspicious_string
}
rule Rule_1461_triggered {
	meta: description = "Rule # 1461 Suspicious String spendit.laulau@yahoo.co triggered"
	strings: $suspicious_string = "spendit.laulau@yahoo.co"
	condition: $suspicious_string
}
rule Rule_1462_triggered {
	meta: description = "Rule # 1462 Suspicious String spymeta triggered"
	strings: $suspicious_string = "spymeta"
	condition: $suspicious_string
}
rule Rule_1463_triggered {
	meta: description = "Rule # 1463 Suspicious String starktomtht triggered"
	strings: $suspicious_string = "starktomtht"
	condition: $suspicious_string
}
rule Rule_1464_triggered {
	meta: description = "Rule # 1464 Suspicious String startonthisfuckingpoint triggered"
	strings: $suspicious_string = "startonthisfuckingpoint"
	condition: $suspicious_string
}
rule Rule_1465_triggered {
	meta: description = "Rule # 1465 Suspicious String stat-dns.com  triggered"
	strings: $suspicious_string = "stat-dns.com "
	condition: $suspicious_string
}
rule Rule_1466_triggered {
	meta: description = "Rule # 1466 Suspicious String stayinfranschhoek.co.za triggered"
	strings: $suspicious_string = "stayinfranschhoek.co.za"
	condition: $suspicious_string
}
rule Rule_1467_triggered {
	meta: description = "Rule # 1467 Suspicious String storesbrown147@gmail.com triggered"
	strings: $suspicious_string = "storesbrown147@gmail.com"
	condition: $suspicious_string
}
rule Rule_1468_triggered {
	meta: description = "Rule # 1468 Suspicious String sub attacker triggered"
	strings: $suspicious_string = "sub attacker"
	condition: $suspicious_string
}
rule Rule_1469_triggered {
	meta: description = "Rule # 1469 Suspicious String susanalbert1980@gmail.com triggered"
	strings: $suspicious_string = "susanalbert1980@gmail.com"
	condition: $suspicious_string
}
rule Rule_1470_triggered {
	meta: description = "Rule # 1470 Suspicious String suthallen@gmail.com triggered"
	strings: $suspicious_string = "suthallen@gmail.com"
	condition: $suspicious_string
}
rule Rule_1471_triggered {
	meta: description = "Rule # 1471 Suspicious String svtpdagx triggered"
	strings: $suspicious_string = "svtpdagx"
	condition: $suspicious_string
}
rule Rule_1472_triggered {
	meta: description = "Rule # 1472 Suspicious String symlinker triggered"
	strings: $suspicious_string = "symlinker"
	condition: $suspicious_string
}
rule Rule_1473_triggered {
	meta: description = "Rule # 1473 Suspicious String sysctl -n kern triggered"
	strings: $suspicious_string = "sysctl -n kern"
	condition: $suspicious_string
}
rule Rule_1474_triggered {
	meta: description = "Rule # 1474 Suspicious String tHAnks tO Sir ShOcKs triggered"
	strings: $suspicious_string = "tHAnks tO Sir ShOcKs"
	condition: $suspicious_string
}
rule Rule_1475_triggered {
	meta: description = "Rule # 1475 Suspicious String tHAnks tO Timeless triggered"
	strings: $suspicious_string = "tHAnks tO Timeless"
	condition: $suspicious_string
}
rule Rule_1476_triggered {
	meta: description = "Rule # 1476 Suspicious String tafiki triggered"
	strings: $suspicious_string = "tafiki"
	condition: $suspicious_string
}
rule Rule_1477_triggered {
	meta: description = "Rule # 1477 Suspicious String tds-narod.ru triggered"
	strings: $suspicious_string = "tds-narod.ru"
	condition: $suspicious_string
}
rule Rule_1478_triggered {
	meta: description = "Rule # 1478 Suspicious String tesemelgan@gmail.com triggered"
	strings: $suspicious_string = "tesemelgan@gmail.com"
	condition: $suspicious_string
}
rule Rule_1479_triggered {
	meta: description = "Rule # 1479 Suspicious String tl4s.com.sa triggered"
	strings: $suspicious_string = "tl4s.com.sa"
	condition: $suspicious_string
}
rule Rule_1480_triggered {
	meta: description = "Rule # 1480 Suspicious String toolzmorathy1 triggered"
	strings: $suspicious_string = "toolzmorathy1"
	condition: $suspicious_string
}
rule Rule_1481_triggered {
	meta: description = "Rule # 1481 Suspicious String totallyfreecursors.com triggered"
	strings: $suspicious_string = "totallyfreecursors.com"
	condition: $suspicious_string
}
rule Rule_1482_triggered {
	meta: description = "Rule # 1482 Suspicious String try.ciela.co triggered"
	strings: $suspicious_string = "try.ciela.co"
	condition: $suspicious_string
}
rule Rule_1483_triggered {
	meta: description = "Rule # 1483 Suspicious String try.ucr.news triggered"
	strings: $suspicious_string = "try.ucr.news"
	condition: $suspicious_string
}
rule Rule_1484_triggered {
	meta: description = "Rule # 1484 Suspicious String tujuanmail triggered"
	strings: $suspicious_string = "tujuanmail"
	condition: $suspicious_string
}
rule Rule_1485_triggered {
	meta: description = "Rule # 1485 Suspicious String turkblackhats triggered"
	strings: $suspicious_string = "turkblackhats"
	condition: $suspicious_string
}
rule Rule_1486_triggered {
	meta: description = "Rule # 1486 Suspicious String turkishkebab00@gmail.com triggered"
	strings: $suspicious_string = "turkishkebab00@gmail.com"
	condition: $suspicious_string
}
rule Rule_1487_triggered {
	meta: description = "Rule # 1487 Suspicious String tvweipud triggered"
	strings: $suspicious_string = "tvweipud"
	condition: $suspicious_string
}
rule Rule_1488_triggered {
	meta: description = "Rule # 1488 Suspicious String ubhteam.org triggered"
	strings: $suspicious_string = "ubhteam.org"
	condition: $suspicious_string
}
rule Rule_1489_triggered {
	meta: description = "Rule # 1489 Suspicious String uon7bHxvy09 triggered"
	strings: $suspicious_string = "uon7bHxvy09"
	condition: $suspicious_string
}
rule Rule_1490_triggered {
	meta: description = "Rule # 1490 Suspicious String upl0ad triggered"
	strings: $suspicious_string = "upl0ad"
	condition: $suspicious_string
}
rule Rule_1491_triggered {
	meta: description = "Rule # 1491 Suspicious String upload shell and manage site or server using console :D, happy hacking ;) triggered"
	strings: $suspicious_string = "upload shell and manage site or server using console :D, happy hacking ;)"
	condition: $suspicious_string
}
rule Rule_1492_triggered {
	meta: description = "Rule # 1492 Suspicious String upload.sa3eka.com triggered"
	strings: $suspicious_string = "upload.sa3eka.com"
	condition: $suspicious_string
}
rule Rule_1493_triggered {
	meta: description = "Rule # 1493 Suspicious String usaa.com triggered"
	strings: $suspicious_string = "usaa.com"
	condition: $suspicious_string
}
rule Rule_1494_triggered {
	meta: description = "Rule # 1494 Suspicious String usta upload basarili olmadi.Baska siteye dal!! triggered"
	strings: $suspicious_string = "usta upload basarili olmadi.Baska siteye dal!!"
	condition: $suspicious_string
}
rule Rule_1495_triggered {
	meta: description = "Rule # 1495 Suspicious String vSDzq3Md triggered"
	strings: $suspicious_string = "vSDzq3Md"
	condition: $suspicious_string
}
rule Rule_1496_triggered {
	meta: description = "Rule # 1496 Suspicious String van1lle triggered"
	strings: $suspicious_string = "van1lle"
	condition: $suspicious_string
}
rule Rule_1497_triggered {
	meta: description = "Rule # 1497 Suspicious String var miner=new WMP.User triggered"
	strings: $suspicious_string = "var miner=new WMP.User"
	condition: $suspicious_string
}
rule Rule_1498_triggered {
	meta: description = "Rule # 1498 Suspicious String vecweb.net.ua triggered"
	strings: $suspicious_string = "vecweb.net.ua"
	condition: $suspicious_string
}
rule Rule_1499_triggered {
	meta: description = "Rule # 1499 Suspicious String victim@host.com triggered"
	strings: $suspicious_string = "victim@host.com"
	condition: $suspicious_string
}
rule Rule_1500_triggered {
	meta: description = "Rule # 1500 Suspicious String vinsm0ke_id triggered"
	strings: $suspicious_string = "vinsm0ke_id"
	condition: $suspicious_string
}
rule Rule_1501_triggered {
	meta: description = "Rule # 1501 Suspicious String vito-RawckerheaD triggered"
	strings: $suspicious_string = "vito-RawckerheaD"
	condition: $suspicious_string
}
rule Rule_1502_triggered {
	meta: description = "Rule # 1502 Suspicious String void.ru triggered"
	strings: $suspicious_string = "void.ru"
	condition: $suspicious_string
}
rule Rule_1503_triggered {
	meta: description = "Rule # 1503 Suspicious String vulns could lead to total disaters triggered"
	strings: $suspicious_string = "vulns could lead to total disaters"
	condition: $suspicious_string
}
rule Rule_1504_triggered {
	meta: description = "Rule # 1504 Suspicious String vulnscan triggered"
	strings: $suspicious_string = "vulnscan"
	condition: $suspicious_string
}
rule Rule_1505_triggered {
	meta: description = "Rule # 1505 Suspicious String w00t triggered"
	strings: $suspicious_string = "w00t"
	condition: $suspicious_string
}
rule Rule_1506_triggered {
	meta: description = "Rule # 1506 Suspicious String w0lgix-tool triggered"
	strings: $suspicious_string = "w0lgix-tool"
	condition: $suspicious_string
}
rule Rule_1507_triggered {
	meta: description = "Rule # 1507 Suspicious String w4ck1ng triggered"
	strings: $suspicious_string = "w4ck1ng"
	condition: $suspicious_string
}
rule Rule_1508_triggered {
	meta: description = "Rule # 1508 Suspicious String w7h7j7c57.homepage.t-online.de triggered"
	strings: $suspicious_string = "w7h7j7c57.homepage.t-online.de"
	condition: $suspicious_string
}
rule Rule_1509_triggered {
	meta: description = "Rule # 1509 Suspicious String w7sh.syria triggered"
	strings: $suspicious_string = "w7sh.syria"
	condition: $suspicious_string
}
rule Rule_1510_triggered {
	meta: description = "Rule # 1510 Suspicious String walemilton003@gmail.com triggered"
	strings: $suspicious_string = "walemilton003@gmail.com"
	condition: $suspicious_string
}
rule Rule_1511_triggered {
	meta: description = "Rule # 1511 Suspicious String webconsole.php triggered"
	strings: $suspicious_string = "webconsole.php"
	condition: $suspicious_string
}
rule Rule_1512_triggered {
	meta: description = "Rule # 1512 Suspicious String webmaster@altavistadelago.com triggered"
	strings: $suspicious_string = "webmaster@altavistadelago.com"
	condition: $suspicious_string
}
rule Rule_1513_triggered {
	meta: description = "Rule # 1513 Suspicious String webminepool.com triggered"
	strings: $suspicious_string = "webminepool.com"
	condition: $suspicious_string
}
rule Rule_1514_triggered {
	meta: description = "Rule # 1514 Suspicious String weevely backdoor triggered"
	strings: $suspicious_string = "weevely backdoor"
	condition: $suspicious_string
}
rule Rule_1515_triggered {
	meta: description = "Rule # 1515 Suspicious String wellsfargo.com triggered"
	strings: $suspicious_string = "wellsfargo.com"
	condition: $suspicious_string
}
rule Rule_1516_triggered {
	meta: description = "Rule # 1516 Suspicious String wfagoss@gmail.com triggered"
	strings: $suspicious_string = "wfagoss@gmail.com"
	condition: $suspicious_string
}
rule Rule_1517_triggered {
	meta: description = "Rule # 1517 Suspicious String wi.na  triggered"
	strings: $suspicious_string = "wi.na "
	condition: $suspicious_string
}
rule Rule_1518_triggered {
	meta: description = "Rule # 1518 Suspicious String williambell101@yahoo.com triggered"
	strings: $suspicious_string = "williambell101@yahoo.com"
	condition: $suspicious_string
}
rule Rule_1519_triggered {
	meta: description = "Rule # 1519 Suspicious String williambell1233@gmail.com triggered"
	strings: $suspicious_string = "williambell1233@gmail.com"
	condition: $suspicious_string
}
rule Rule_1520_triggered {
	meta: description = "Rule # 1520 Suspicious String wkendy76@blumail.org triggered"
	strings: $suspicious_string = "wkendy76@blumail.org"
	condition: $suspicious_string
}
rule Rule_1521_triggered {
	meta: description = "Rule # 1521 Suspicious String wolu yb dekcah triggered"
	strings: $suspicious_string = "wolu yb dekcah"
	condition: $suspicious_string
}
rule Rule_1522_triggered {
	meta: description = "Rule # 1522 Suspicious String wonderfulboy01@gmai.com triggered"
	strings: $suspicious_string = "wonderfulboy01@gmai.com"
	condition: $suspicious_string
}
rule Rule_1523_triggered {
	meta: description = "Rule # 1523 Suspicious String wp mass info changer triggered"
	strings: $suspicious_string = "wp mass info changer"
	condition: $suspicious_string
}
rule Rule_1524_triggered {
	meta: description = "Rule # 1524 Suspicious String wrgggthhd triggered"
	strings: $suspicious_string = "wrgggthhd"
	condition: $suspicious_string
}
rule Rule_1525_triggered {
	meta: description = "Rule # 1525 Suspicious String wso@protonmail.com triggered"
	strings: $suspicious_string = "wso@protonmail.com"
	condition: $suspicious_string
}
rule Rule_1526_triggered {
	meta: description = "Rule # 1526 Suspicious String www.adobe.com.zip triggered"
	strings: $suspicious_string = "www.adobe.com.zip"
	condition: $suspicious_string
}
rule Rule_1527_triggered {
	meta: description = "Rule # 1527 Suspicious String www.ahdal.com triggered"
	strings: $suspicious_string = "www.ahdal.com"
	condition: $suspicious_string
}
rule Rule_1528_triggered {
	meta: description = "Rule # 1528 Suspicious String www.ayyildiz.org triggered"
	strings: $suspicious_string = "www.ayyildiz.org"
	condition: $suspicious_string
}
rule Rule_1529_triggered {
	meta: description = "Rule # 1529 Suspicious String www.c99.me triggered"
	strings: $suspicious_string = "www.c99.me"
	condition: $suspicious_string
}
rule Rule_1530_triggered {
	meta: description = "Rule # 1530 Suspicious String www.gudangkesehatan.com triggered"
	strings: $suspicious_string = "www.gudangkesehatan.com"
	condition: $suspicious_string
}
rule Rule_1531_triggered {
	meta: description = "Rule # 1531 Suspicious String www.sec-krb.org triggered"
	strings: $suspicious_string = "www.sec-krb.org"
	condition: $suspicious_string
}
rule Rule_1532_triggered {
	meta: description = "Rule # 1532 Suspicious String x shell triggered"
	strings: $suspicious_string = "x shell"
	condition: $suspicious_string
}
rule Rule_1533_triggered {
	meta: description = "Rule # 1533 Suspicious String x'1n73ct  triggered"
	strings: $suspicious_string = "x'1n73ct "
	condition: $suspicious_string
}
rule Rule_1534_triggered {
	meta: description = "Rule # 1534 Suspicious String x1.minerxmr.ru triggered"
	strings: $suspicious_string = "x1.minerxmr.ru"
	condition: $suspicious_string
}
rule Rule_1535_triggered {
	meta: description = "Rule # 1535 Suspicious String x@erebor.dwarfpool.com triggered"
	strings: $suspicious_string = "x@erebor.dwarfpool.com"
	condition: $suspicious_string
}
rule Rule_1536_triggered {
	meta: description = "Rule # 1536 Suspicious String x@moria.dwarfpool.com triggered"
	strings: $suspicious_string = "x@moria.dwarfpool.com"
	condition: $suspicious_string
}
rule Rule_1537_triggered {
	meta: description = "Rule # 1537 Suspicious String xCut10n  triggered"
	strings: $suspicious_string = "xCut10n "
	condition: $suspicious_string
}
rule Rule_1538_triggered {
	meta: description = "Rule # 1538 Suspicious String xLon3ly triggered"
	strings: $suspicious_string = "xLon3ly"
	condition: $suspicious_string
}
rule Rule_1539_triggered {
	meta: description = "Rule # 1539 Suspicious String xXEz triggered"
	strings: $suspicious_string = "xXEz"
	condition: $suspicious_string
}
rule Rule_1540_triggered {
	meta: description = "Rule # 1540 Suspicious String xbgbkyqvqgwu triggered"
	strings: $suspicious_string = "xbgbkyqvqgwu"
	condition: $suspicious_string
}
rule Rule_1541_triggered {
	meta: description = "Rule # 1541 Suspicious String xplOi73r triggered"
	strings: $suspicious_string = "xplOi73r"
	condition: $suspicious_string
}
rule Rule_1542_triggered {
	meta: description = "Rule # 1542 Suspicious String xrob0t.cpanels@gmail.com triggered"
	strings: $suspicious_string = "xrob0t.cpanels@gmail.com"
	condition: $suspicious_string
}
rule Rule_1543_triggered {
	meta: description = "Rule # 1543 Suspicious String xtases no-life triggered"
	strings: $suspicious_string = "xtases no-life"
	condition: $suspicious_string
}
rule Rule_1544_triggered {
	meta: description = "Rule # 1544 Suspicious String y2Google triggered"
	strings: $suspicious_string = "y2Google"
	condition: $suspicious_string
}
rule Rule_1545_triggered {
	meta: description = "Rule # 1545 Suspicious String yahoopassword triggered"
	strings: $suspicious_string = "yahoopassword"
	condition: $suspicious_string
}
rule Rule_1546_triggered {
	meta: description = "Rule # 1546 Suspicious String yang8559420 triggered"
	strings: $suspicious_string = "yang8559420"
	condition: $suspicious_string
}
rule Rule_1547_triggered {
	meta: description = "Rule # 1547 Suspicious String ydteam triggered"
	strings: $suspicious_string = "ydteam"
	condition: $suspicious_string
}
rule Rule_1548_triggered {
	meta: description = "Rule # 1548 Suspicious String youngbloodcharlesx@gmail.com triggered"
	strings: $suspicious_string = "youngbloodcharlesx@gmail.com"
	condition: $suspicious_string
}
rule Rule_1549_triggered {
	meta: description = "Rule # 1549 Suspicious String zPayPal_2018 triggered"
	strings: $suspicious_string = "zPayPal_2018"
	condition: $suspicious_string
}
rule Rule_1550_triggered {
	meta: description = "Rule # 1550 Suspicious String zen.co.uk triggered"
	strings: $suspicious_string = "zen.co.uk"
	condition: $suspicious_string
}
rule Rule_1551_triggered {
	meta: description = "Rule # 1551 Suspicious String zetas.oujda triggered"
	strings: $suspicious_string = "zetas.oujda"
	condition: $suspicious_string
}
rule Rule_1552_triggered {
	meta: description = "Rule # 1552 Suspicious String zhikou.yo2.cn triggered"
	strings: $suspicious_string = "zhikou.yo2.cn"
	condition: $suspicious_string
}
rule Rule_1553_triggered {
	meta: description = "Rule # 1553 Suspicious String zigw triggered"
	strings: $suspicious_string = "zigw"
	condition: $suspicious_string
}
rule Rule_1554_triggered {
	meta: description = "Rule # 1554 Suspicious String ziteditora.com.br triggered"
	strings: $suspicious_string = "ziteditora.com.br"
	condition: $suspicious_string
}
rule Rule_1555_triggered {
	meta: description = "Rule # 1555 Suspicious String zoozoo triggered"
	strings: $suspicious_string = "zoozoo"
	condition: $suspicious_string
}
rule Rule_1556_triggered {
	meta: description = "Rule # 1556 Suspicious String 互相伤害啊 triggered"
	strings: $suspicious_string = "互相伤害啊"
	condition: $suspicious_string
}
rule Rule_1557_triggered {
	meta: description = "Rule # 1557 Suspicious String watchd0g.sh triggered"
	strings: $suspicious_string = "watchd0g.sh"
	condition: $suspicious_string
}
rule Rule_1558_triggered {
	meta: description = "Rule # 1558 Suspicious String systemdo triggered"
	strings: $suspicious_string = "systemdo"
	condition: $suspicious_string
}
rule Rule_1559_triggered {
	meta: description = "Rule # 1559 Suspicious String 222.184.79.11 triggered"
	strings: $suspicious_string = "222.184.79.11"
	condition: $suspicious_string
}
rule Rule_1560_triggered {
	meta: description = "Rule # 1560 Suspicious String dada.x86_64 triggered"
	strings: $suspicious_string = "dada.x86_64"
	condition: $suspicious_string
}
rule Rule_1561_triggered {
	meta: description = "Rule # 1561 Suspicious String bbc.servehalflife.com triggered"
	strings: $suspicious_string = "bbc.servehalflife.com"
	condition: $suspicious_string
}
rule Rule_1562_triggered {
	meta: description = "Rule # 1562 Suspicious String 190.60.206.11 triggered"
	strings: $suspicious_string = "190.60.206.11"
	condition: $suspicious_string
}
rule Rule_1563_triggered {
	meta: description = "Rule # 1563 Suspicious String 182.18.8.69 triggered"
	strings: $suspicious_string = "182.18.8.69"
	condition: $suspicious_string
}
rule Rule_1564_triggered {
	meta: description = "Rule # 1564 Suspicious String jbos.7766.org triggered"
	strings: $suspicious_string = "jbos.7766.org"
	condition: $suspicious_string
}
rule Rule_1565_triggered {
	meta: description = "Rule # 1565 Suspicious String 115.231.218.38 triggered"
	strings: $suspicious_string = "115.231.218.38"
	condition: $suspicious_string
}
rule Rule_1566_triggered {
	meta: description = "Rule # 1566 Suspicious String zayaflowers.ru/3.03_conf triggered"
	strings: $suspicious_string = "zayaflowers.ru/3.03_conf"
	condition: $suspicious_string
}
rule Rule_1567_triggered {
	meta: description = "Rule # 1567 Suspicious String 3.03_config triggered"
	strings: $suspicious_string = "3.03_config"
	condition: $suspicious_string
}
rule Rule_1568_triggered {
	meta: description = "Rule # 1568 Suspicious String gsqdecfoo triggered"
	strings: $suspicious_string = "gsqdecfoo"
	condition: $suspicious_string
}
rule Rule_1569_triggered {
	meta: description = "Rule # 1569 Suspicious String dydwfdnuls triggered"
	strings: $suspicious_string = "dydwfdnuls"
	condition: $suspicious_string
}
rule Rule_1570_triggered {
	meta: description = "Rule # 1570 Suspicious String rqutuvbow triggered"
	strings: $suspicious_string = "rqutuvbow"
	condition: $suspicious_string
}
rule Rule_1571_triggered {
	meta: description = "Rule # 1571 Suspicious String osvbkai triggered"
	strings: $suspicious_string = "osvbkai"
	condition: $suspicious_string
}
rule Rule_1572_triggered {
	meta: description = "Rule # 1572 Suspicious String fwaywusurl triggered"
	strings: $suspicious_string = "fwaywusurl"
	condition: $suspicious_string
}
rule Rule_1573_triggered {
	meta: description = "Rule # 1573 Suspicious String O7JBlDzqAkyShKcoEsTQSmtQHEM4aY0G triggered"
	strings: $suspicious_string = "O7JBlDzqAkyShKcoEsTQSmtQHEM4aY0G"
	condition: $suspicious_string
}
rule Rule_1574_triggered {
	meta: description = "Rule # 1574 Suspicious String RsyncWeakCheck triggered"
	strings: $suspicious_string = "RsyncWeakCheck"
	condition: $suspicious_string
}
rule Rule_1575_triggered {
	meta: description = "Rule # 1575 Suspicious String WScript.shell triggered"
	strings: $suspicious_string = "WScript.shell"
	condition: $suspicious_string
}
rule Rule_1576_triggered {
	meta: description = "Rule # 1576 Suspicious String WSHShell triggered"
	strings: $suspicious_string = "WSHShell"
	condition: $suspicious_string
}
rule Rule_1577_triggered {
	meta: description = "Rule # 1577 Suspicious String Stager uploaded successfully triggered"
	strings: $suspicious_string = "Stager uploaded successfully"
	condition: $suspicious_string
}
rule Rule_1578_triggered {
	meta: description = "Rule # 1578 Suspicious String chpasswd.sh triggered"
	strings: $suspicious_string = "chpasswd.sh"
	condition: $suspicious_string
}
rule Rule_1579_triggered {
	meta: description = "Rule # 1579 Suspicious String Mr Secretz Shell triggered"
	strings: $suspicious_string = "Mr Secretz Shell"
	condition: $suspicious_string
}
rule Rule_1580_triggered {
	meta: description = "Rule # 1580 Suspicious String CloudNine hehe triggered"
	strings: $suspicious_string = "CloudNine hehe"
	condition: $suspicious_string
}
rule Rule_1581_triggered {
	meta: description = "Rule # 1581 Suspicious String Boycot israel triggered"
	strings: $suspicious_string = "Boycot israel"
	condition: $suspicious_string
}
rule Rule_1582_triggered {
	meta: description = "Rule # 1582 Suspicious String Hacked By faisalr triggered"
	strings: $suspicious_string = "Hacked By faisalr"
	condition: $suspicious_string
}
rule Rule_1583_triggered {
	meta: description = "Rule # 1583 Suspicious String hfwG2jBM827zx triggered"
	strings: $suspicious_string = "hfwG2jBM827zx"
	condition: $suspicious_string
}
rule Rule_1584_triggered {
	meta: description = "Rule # 1584 Suspicious String googletagmanaaer.com triggered"
	strings: $suspicious_string = "googletagmanaaer.com"
	condition: $suspicious_string
}
rule Rule_1585_triggered {
	meta: description = "Rule # 1585 Suspicious String prizehdru triggered"
	strings: $suspicious_string = "prizehdru"
	condition: $suspicious_string
}
rule Rule_1586_triggered {
	meta: description = "Rule # 1586 Suspicious String Mister Spy & Souheyl Bypass Shell triggered"
	strings: $suspicious_string = "Mister Spy & Souheyl Bypass Shell"
	condition: $suspicious_string
}
rule Rule_1587_triggered {
	meta: description = "Rule # 1587 Suspicious String Welcome To Our Shell triggered"
	strings: $suspicious_string = "Welcome To Our Shell"
	condition: $suspicious_string
}
rule Rule_1588_triggered {
	meta: description = "Rule # 1588 Suspicious String WSCRIPT.SHELL triggered"
	strings: $suspicious_string = "WSCRIPT.SHELL"
	condition: $suspicious_string
}
rule Rule_1589_triggered {
	meta: description = "Rule # 1589 Suspicious String One_LAYS triggered"
	strings: $suspicious_string = "One_LAYS"
	condition: $suspicious_string
}
rule Rule_1590_triggered {
	meta: description = "Rule # 1590 Suspicious String PHP Encode v1.0 by zeura.com triggered"
	strings: $suspicious_string = "PHP Encode v1.0 by zeura.com"
	condition: $suspicious_string
}
rule Rule_1591_triggered {
	meta: description = "Rule # 1591 Suspicious String LUL404 triggered"
	strings: $suspicious_string = "LUL404"
	condition: $suspicious_string
}
rule Rule_1592_triggered {
	meta: description = "Rule # 1592 Suspicious String Bersih PAK! triggered"
	strings: $suspicious_string = "Bersih PAK!"
	condition: $suspicious_string
}
rule Rule_1593_triggered {
	meta: description = "Rule # 1593 Suspicious String Gagal PAK!!! triggered"
	strings: $suspicious_string = "Gagal PAK!!!"
	condition: $suspicious_string
}
rule Rule_1594_triggered {
	meta: description = "Rule # 1594 Suspicious String W3LL SQUAD triggered"
	strings: $suspicious_string = "W3LL SQUAD"
	condition: $suspicious_string
}
rule Rule_1595_triggered {
	meta: description = "Rule # 1595 Suspicious String dl/nygt.whiqp_c triggered"
	strings: $suspicious_string = "dl/nygt.whiqp_c"
	condition: $suspicious_string
}
rule Rule_1596_triggered {
	meta: description = "Rule # 1596 Suspicious String mdXfyCGA8070 triggered"
	strings: $suspicious_string = "mdXfyCGA8070"
	condition: $suspicious_string
}
rule Rule_1597_triggered {
	meta: description = "Rule # 1597 Suspicious String MzcoOhsRdQ9rY0RVPSEeZR0RJABRc3VIFB8vPyB triggered"
	strings: $suspicious_string = "MzcoOhsRdQ9rY0RVPSEeZR0RJABRc3VIFB8vPyB"
	condition: $suspicious_string
}
rule Rule_1598_triggered {
	meta: description = "Rule # 1598 Suspicious String ooRKSGZh2631 triggered"
	strings: $suspicious_string = "ooRKSGZh2631"
	condition: $suspicious_string
}
rule Rule_1599_triggered {
	meta: description = "Rule # 1599 Suspicious String dxNNrWQccDmaVMALjoEPDAXpoqCRbaTBbwTVbXc triggered"
	strings: $suspicious_string = "dxNNrWQccDmaVMALjoEPDAXpoqCRbaTBbwTVbXc"
	condition: $suspicious_string
}
rule Rule_1600_triggered {
	meta: description = "Rule # 1600 Suspicious String c4a4629314f86e064c94188729fcdf1cc4a4629 triggered"
	strings: $suspicious_string = "c4a4629314f86e064c94188729fcdf1cc4a4629"
	condition: $suspicious_string
}
rule Rule_1601_triggered {
	meta: description = "Rule # 1601 Suspicious String UcpEVe6863 triggered"
	strings: $suspicious_string = "UcpEVe6863"
	condition: $suspicious_string
}
rule Rule_1602_triggered {
	meta: description = "Rule # 1602 Suspicious String YwmI1780 triggered"
	strings: $suspicious_string = "YwmI1780"
	condition: $suspicious_string
}
rule Rule_1603_triggered {
	meta: description = "Rule # 1603 Suspicious String <h1>#p@$c@#</h1> triggered"
	strings: $suspicious_string = "<h1>#p@$c@#</h1>"
	condition: $suspicious_string
}
rule Rule_1604_triggered {
	meta: description = "Rule # 1604 Suspicious String HUSA triggered"
	strings: $suspicious_string = "HUSA"
	condition: $suspicious_string
}
rule Rule_1605_triggered {
	meta: description = "Rule # 1605 Suspicious String Shabab Hacker triggered"
	strings: $suspicious_string = "Shabab Hacker"
	condition: $suspicious_string
}
rule Rule_1606_triggered {
	meta: description = "Rule # 1606 Suspicious String scripts.trasnaltemyrecords.com triggered"
	strings: $suspicious_string = "scripts.trasnaltemyrecords.com"
	condition: $suspicious_string
}
rule Rule_1607_triggered {
	meta: description = "Rule # 1607 Suspicious String by aDriv4 triggered"
	strings: $suspicious_string = "by aDriv4"
	condition: $suspicious_string
}
rule Rule_1608_triggered {
	meta: description = "Rule # 1608 Suspicious String xNot_RespondinGx Gans triggered"
	strings: $suspicious_string = "xNot_RespondinGx Gans"
	condition: $suspicious_string
}
rule Rule_1609_triggered {
	meta: description = "Rule # 1609 Suspicious String extremecrew triggered"
	strings: $suspicious_string = "extremecrew"
	condition: $suspicious_string
}
rule Rule_1610_triggered {
	meta: description = "Rule # 1610 Suspicious String Hajar Goblok!!! triggered"
	strings: $suspicious_string = "Hajar Goblok!!!"
	condition: $suspicious_string
}
rule Rule_1611_triggered {
	meta: description = "Rule # 1611 Suspicious String cek Disini goblok!!! triggered"
	strings: $suspicious_string = "cek Disini goblok!!!"
	condition: $suspicious_string
}
rule Rule_1612_triggered {
	meta: description = "Rule # 1612 Suspicious String PRO Mailer V2 triggered"
	strings: $suspicious_string = "PRO Mailer V2"
	condition: $suspicious_string
}
rule Rule_1613_triggered {
	meta: description = "Rule # 1613 Suspicious String Mailer Inbox Sender triggered"
	strings: $suspicious_string = "Mailer Inbox Sender"
	condition: $suspicious_string
}
rule Rule_1614_triggered {
	meta: description = "Rule # 1614 Suspicious String MAILER IS UNABLE TO CONNECT SMTP !! triggered"
	strings: $suspicious_string = "MAILER IS UNABLE TO CONNECT SMTP !!"
	condition: $suspicious_string
}
rule Rule_1615_triggered {
	meta: description = "Rule # 1615 Suspicious String RECEPIENT CAN'T RECEIVE MESSAGE triggered"
	strings: $suspicious_string = "RECEPIENT CAN'T RECEIVE MESSAGE"
	condition: $suspicious_string
}
rule Rule_1616_triggered {
	meta: description = "Rule # 1616 Suspicious String adriv4 triggered"
	strings: $suspicious_string = "adriv4"
	condition: $suspicious_string
}
rule Rule_1617_triggered {
	meta: description = "Rule # 1617 Suspicious String Leaf PHP Mailer by [leafmailer.pw] triggered"
	strings: $suspicious_string = "Leaf PHP Mailer by [leafmailer.pw]"
	condition: $suspicious_string
}
rule Rule_1618_triggered {
	meta: description = "Rule # 1618 Suspicious String 6319a819898755e8.paste.se triggered"
	strings: $suspicious_string = "6319a819898755e8.paste.se"
	condition: $suspicious_string
}
rule Rule_1619_triggered {
	meta: description = "Rule # 1619 Suspicious String pastebin.com/raw/3ByK3R00 triggered"
	strings: $suspicious_string = "pastebin.com/raw/3ByK3R00"
	condition: $suspicious_string
}
rule Rule_1620_triggered {
	meta: description = "Rule # 1620 Suspicious String smevkpathan triggered"
	strings: $suspicious_string = "smevkpathan"
	condition: $suspicious_string
}
rule Rule_1621_triggered {
	meta: description = "Rule # 1621 Suspicious String SmEvK_PaThAn Shell v3 Coded by Kashif Khan triggered"
	strings: $suspicious_string = "SmEvK_PaThAn Shell v3 Coded by Kashif Khan"
	condition: $suspicious_string
}
rule Rule_1622_triggered {
	meta: description = "Rule # 1622 Suspicious String Edit Shell according to your choice. triggered"
	strings: $suspicious_string = "Edit Shell according to your choice."
	condition: $suspicious_string
}
rule Rule_1623_triggered {
	meta: description = "Rule # 1623 Suspicious String Symlink Bypassed Successfully! triggered"
	strings: $suspicious_string = "Symlink Bypassed Successfully!"
	condition: $suspicious_string
}
rule Rule_1624_triggered {
	meta: description = "Rule # 1624 Suspicious String Symlink Bypass 2014 by Mindless Injector triggered"
	strings: $suspicious_string = "Symlink Bypass 2014 by Mindless Injector"
	condition: $suspicious_string
}
rule Rule_1625_triggered {
	meta: description = "Rule # 1625 Suspicious String Pak Cyber Skullz triggered"
	strings: $suspicious_string = "Pak Cyber Skullz"
	condition: $suspicious_string
}
rule Rule_1626_triggered {
	meta: description = "Rule # 1626 Suspicious String Symlink Bypass 2017 triggered"
	strings: $suspicious_string = "Symlink Bypass 2017"
	condition: $suspicious_string
}
rule Rule_1627_triggered {
	meta: description = "Rule # 1627 Suspicious String Recoded By Con7ext triggered"
	strings: $suspicious_string = "Recoded By Con7ext"
	condition: $suspicious_string
}
rule Rule_1628_triggered {
	meta: description = "Rule # 1628 Suspicious String Not 404 Found Cyber Team triggered"
	strings: $suspicious_string = "Not 404 Found Cyber Team"
	condition: $suspicious_string
}
rule Rule_1629_triggered {
	meta: description = "Rule # 1629 Suspicious String Hacked By White System triggered"
	strings: $suspicious_string = "Hacked By White System"
	condition: $suspicious_string
}
rule Rule_1630_triggered {
	meta: description = "Rule # 1630 Suspicious String TurkicHackersRulez triggered"
	strings: $suspicious_string = "TurkicHackersRulez"
	condition: $suspicious_string
}
rule Rule_1631_triggered {
	meta: description = "Rule # 1631 Suspicious String 1lHfauyg874i6k triggered"
	strings: $suspicious_string = "1lHfauyg874i6k"
	condition: $suspicious_string
}
rule Rule_1632_triggered {
	meta: description = "Rule # 1632 Suspicious String 4_pkgndolc9eyfst triggered"
	strings: $suspicious_string = "4_pkgndolc9eyfst"
	condition: $suspicious_string
}
rule Rule_1633_triggered {
	meta: description = "Rule # 1633 Suspicious String function mjfub triggered"
	strings: $suspicious_string = "function mjfub"
	condition: $suspicious_string
}
rule Rule_1634_triggered {
	meta: description = "Rule # 1634 Suspicious String Symlink based cpanel cracking wala jugaad XD triggered"
	strings: $suspicious_string = "Symlink based cpanel cracking wala jugaad XD"
	condition: $suspicious_string
}
rule Rule_1635_triggered {
	meta: description = "Rule # 1635 Suspicious String cpanel cracker triggered"
	strings: $suspicious_string = "cpanel cracker"
	condition: $suspicious_string
}
rule Rule_1636_triggered {
	meta: description = "Rule # 1636 Suspicious String cpanelcracking triggered"
	strings: $suspicious_string = "cpanelcracking"
	condition: $suspicious_string
}
rule Rule_1637_triggered {
	meta: description = "Rule # 1637 Suspicious String Hacker Indonesia triggered"
	strings: $suspicious_string = "Hacker Indonesia"
	condition: $suspicious_string
}
rule Rule_1638_triggered {
	meta: description = "Rule # 1638 Suspicious String Indonesian Hacker triggered"
	strings: $suspicious_string = "Indonesian Hacker"
	condition: $suspicious_string
}
rule Rule_1639_triggered {
	meta: description = "Rule # 1639 Suspicious String Hacker Rohil triggered"
	strings: $suspicious_string = "Hacker Rohil"
	condition: $suspicious_string
}
rule Rule_1640_triggered {
	meta: description = "Rule # 1640 Suspicious String Hacker Riau triggered"
	strings: $suspicious_string = "Hacker Riau"
	condition: $suspicious_string
}
rule Rule_1641_triggered {
	meta: description = "Rule # 1641 Suspicious String Hacker Pekanbaru triggered"
	strings: $suspicious_string = "Hacker Pekanbaru"
	condition: $suspicious_string
}
rule Rule_1642_triggered {
	meta: description = "Rule # 1642 Suspicious String Hacker 2018 triggered"
	strings: $suspicious_string = "Hacker 2018"
	condition: $suspicious_string
}
rule Rule_1643_triggered {
	meta: description = "Rule # 1643 Suspicious String Defacer Terbaru triggered"
	strings: $suspicious_string = "Defacer Terbaru"
	condition: $suspicious_string
}
rule Rule_1644_triggered {
	meta: description = "Rule # 1644 Suspicious String Rohil Cyber Army triggered"
	strings: $suspicious_string = "Rohil Cyber Army"
	condition: $suspicious_string
}
rule Rule_1645_triggered {
	meta: description = "Rule # 1645 Suspicious String RCA TEAM triggered"
	strings: $suspicious_string = "RCA TEAM"
	condition: $suspicious_string
}
rule Rule_1646_triggered {
	meta: description = "Rule # 1646 Suspicious String PANTESTER triggered"
	strings: $suspicious_string = "PANTESTER"
	condition: $suspicious_string
}
rule Rule_1647_triggered {
	meta: description = "Rule # 1647 Suspicious String PANTESTED triggered"
	strings: $suspicious_string = "PANTESTED"
	condition: $suspicious_string
}
rule Rule_1648_triggered {
	meta: description = "Rule # 1648 Suspicious String Hacker Dunia triggered"
	strings: $suspicious_string = "Hacker Dunia"
	condition: $suspicious_string
}
rule Rule_1649_triggered {
	meta: description = "Rule # 1649 Suspicious String Hack Website triggered"
	strings: $suspicious_string = "Hack Website"
	condition: $suspicious_string
}
rule Rule_1650_triggered {
	meta: description = "Rule # 1650 Suspicious String Hack System triggered"
	strings: $suspicious_string = "Hack System"
	condition: $suspicious_string
}
rule Rule_1651_triggered {
	meta: description = "Rule # 1651 Suspicious String System Hacked triggered"
	strings: $suspicious_string = "System Hacked"
	condition: $suspicious_string
}
rule Rule_1652_triggered {
	meta: description = "Rule # 1652 Suspicious String Mr.4JIE triggered"
	strings: $suspicious_string = "Mr.4JIE"
	condition: $suspicious_string
}
rule Rule_1653_triggered {
	meta: description = "Rule # 1653 Suspicious String Jakarta Paranoid triggered"
	strings: $suspicious_string = "Jakarta Paranoid"
	condition: $suspicious_string
}
rule Rule_1654_triggered {
	meta: description = "Rule # 1654 Suspicious String Mr.Onion triggered"
	strings: $suspicious_string = "Mr.Onion"
	condition: $suspicious_string
}
rule Rule_1655_triggered {
	meta: description = "Rule # 1655 Suspicious String Mr.Tahusumedang triggered"
	strings: $suspicious_string = "Mr.Tahusumedang"
	condition: $suspicious_string
}
rule Rule_1656_triggered {
	meta: description = "Rule # 1656 Suspicious String Mr.satsat triggered"
	strings: $suspicious_string = "Mr.satsat"
	condition: $suspicious_string
}
rule Rule_1657_triggered {
	meta: description = "Rule # 1657 Suspicious String Cemen Kun triggered"
	strings: $suspicious_string = "Cemen Kun"
	condition: $suspicious_string
}
rule Rule_1658_triggered {
	meta: description = "Rule # 1658 Suspicious String Mr.IX triggered"
	strings: $suspicious_string = "Mr.IX"
	condition: $suspicious_string
}
rule Rule_1659_triggered {
	meta: description = "Rule # 1659 Suspicious String Infinity Cyber Team triggered"
	strings: $suspicious_string = "Infinity Cyber Team"
	condition: $suspicious_string
}
rule Rule_1660_triggered {
	meta: description = "Rule # 1660 Suspicious String Mr.Donut's triggered"
	strings: $suspicious_string = "Mr.Donut's"
	condition: $suspicious_string
}
rule Rule_1661_triggered {
	meta: description = "Rule # 1661 Suspicious String Evil-net triggered"
	strings: $suspicious_string = "Evil-net"
	condition: $suspicious_string
}
rule Rule_1662_triggered {
	meta: description = "Rule # 1662 Suspicious String M3T4L triggered"
	strings: $suspicious_string = "M3T4L"
	condition: $suspicious_string
}
rule Rule_1663_triggered {
	meta: description = "Rule # 1663 Suspicious String CasusParmak triggered"
	strings: $suspicious_string = "CasusParmak"
	condition: $suspicious_string
}
rule Rule_1664_triggered {
	meta: description = "Rule # 1664 Suspicious String MixPr0 triggered"
	strings: $suspicious_string = "MixPr0"
	condition: $suspicious_string
}
rule Rule_1665_triggered {
	meta: description = "Rule # 1665 Suspicious String ByIllegaL triggered"
	strings: $suspicious_string = "ByIllegaL"
	condition: $suspicious_string
}
rule Rule_1666_triggered {
	meta: description = "Rule # 1666 Suspicious String Raiz0WorM triggered"
	strings: $suspicious_string = "Raiz0WorM"
	condition: $suspicious_string
}
rule Rule_1667_triggered {
	meta: description = "Rule # 1667 Suspicious String eXploiting Done triggered"
	strings: $suspicious_string = "eXploiting Done"
	condition: $suspicious_string
}
rule Rule_1668_triggered {
	meta: description = "Rule # 1668 Suspicious String gaza_hacker triggered"
	strings: $suspicious_string = "gaza_hacker"
	condition: $suspicious_string
}
rule Rule_1669_triggered {
	meta: description = "Rule # 1669 Suspicious String gaza_mysql_file triggered"
	strings: $suspicious_string = "gaza_mysql_file"
	condition: $suspicious_string
}
rule Rule_1670_triggered {
	meta: description = "Rule # 1670 Suspicious String Coded By TKL triggered"
	strings: $suspicious_string = "Coded By TKL"
	condition: $suspicious_string
}
rule Rule_1671_triggered {
	meta: description = "Rule # 1671 Suspicious String Mr.Alsa3ek triggered"
	strings: $suspicious_string = "Mr.Alsa3ek"
	condition: $suspicious_string
}
rule Rule_1672_triggered {
	meta: description = "Rule # 1672 Suspicious String TeaM HacKer Egypt triggered"
	strings: $suspicious_string = "TeaM HacKer Egypt"
	condition: $suspicious_string
}
rule Rule_1673_triggered {
	meta: description = "Rule # 1673 Suspicious String Mr.SaFa7 triggered"
	strings: $suspicious_string = "Mr.SaFa7"
	condition: $suspicious_string
}
rule Rule_1674_triggered {
	meta: description = "Rule # 1674 Suspicious String v4-team.com triggered"
	strings: $suspicious_string = "v4-team.com"
	condition: $suspicious_string
}
rule Rule_1675_triggered {
	meta: description = "Rule # 1675 Suspicious String evil files created succes triggered"
	strings: $suspicious_string = "evil files created succes"
	condition: $suspicious_string
}
rule Rule_1676_triggered {
	meta: description = "Rule # 1676 Suspicious String exploited by success! triggered"
	strings: $suspicious_string = "exploited by success!"
	condition: $suspicious_string
}
rule Rule_1677_triggered {
	meta: description = "Rule # 1677 Suspicious String djekmani4ever triggered"
	strings: $suspicious_string = "djekmani4ever"
	condition: $suspicious_string
}
rule Rule_1678_triggered {
	meta: description = "Rule # 1678 Suspicious String ghost hacker triggered"
	strings: $suspicious_string = "ghost hacker"
	condition: $suspicious_string
}
rule Rule_1679_triggered {
	meta: description = "Rule # 1679 Suspicious String Str0ke triggered"
	strings: $suspicious_string = "Str0ke"
	condition: $suspicious_string
}
rule Rule_1680_triggered {
	meta: description = "Rule # 1680 Suspicious String ShAfEKo4EvEr triggered"
	strings: $suspicious_string = "ShAfEKo4EvEr"
	condition: $suspicious_string
}
rule Rule_1681_triggered {
	meta: description = "Rule # 1681 Suspicious String Mr.Mn7oS triggered"
	strings: $suspicious_string = "Mr.Mn7oS"
	condition: $suspicious_string
}
rule Rule_1682_triggered {
	meta: description = "Rule # 1682 Suspicious String 2b432a58d113cc6c4c108b30f176f5e1 triggered"
	strings: $suspicious_string = "2b432a58d113cc6c4c108b30f176f5e1"
	condition: $suspicious_string
}
rule Rule_1683_triggered {
	meta: description = "Rule # 1683 Suspicious String Coded By Mr.SaHr triggered"
	strings: $suspicious_string = "Coded By Mr.SaHr"
	condition: $suspicious_string
}
rule Rule_1684_triggered {
	meta: description = "Rule # 1684 Suspicious String q6asmr-hiyjd3lz9ovn71wxbc4et058p2k_guf triggered"
	strings: $suspicious_string = "q6asmr-hiyjd3lz9ovn71wxbc4et058p2k_guf"
	condition: $suspicious_string
}
rule Rule_1685_triggered {
	meta: description = "Rule # 1685 Suspicious String Vuln!! patch it Now! triggered"
	strings: $suspicious_string = "Vuln!! patch it Now!"
	condition: $suspicious_string
}
rule Rule_1686_triggered {
	meta: description = "Rule # 1686 Suspicious String vuln.php triggered"
	strings: $suspicious_string = "vuln.php"
	condition: $suspicious_string
}
rule Rule_1687_triggered {
	meta: description = "Rule # 1687 Suspicious String vuln.htm triggered"
	strings: $suspicious_string = "vuln.htm"
	condition: $suspicious_string
}
rule Rule_1688_triggered {
	meta: description = "Rule # 1688 Suspicious String admarketlocation.com triggered"
	strings: $suspicious_string = "admarketlocation.com"
	condition: $suspicious_string
}
rule Rule_1689_triggered {
	meta: description = "Rule # 1689 Suspicious String admarketsearch.xyz triggered"
	strings: $suspicious_string = "admarketsearch.xyz"
	condition: $suspicious_string
}
rule Rule_1690_triggered {
	meta: description = "Rule # 1690 Suspicious String adsformarket.com triggered"
	strings: $suspicious_string = "adsformarket.com"
	condition: $suspicious_string
}
rule Rule_1691_triggered {
	meta: description = "Rule # 1691 Suspicious String gotosecond2.com triggered"
	strings: $suspicious_string = "gotosecond2.com"
	condition: $suspicious_string
}
rule Rule_1692_triggered {
	meta: description = "Rule # 1692 Suspicious String Tn.Deep7 triggered"
	strings: $suspicious_string = "Tn.Deep7"
	condition: $suspicious_string
}
rule Rule_1693_triggered {
	meta: description = "Rule # 1693 Suspicious String Cyber Team Official triggered"
	strings: $suspicious_string = "Cyber Team Official"
	condition: $suspicious_string
}
rule Rule_1694_triggered {
	meta: description = "Rule # 1694 Suspicious String Liosion_team triggered"
	strings: $suspicious_string = "Liosion_team"
	condition: $suspicious_string
}
rule Rule_1695_triggered {
	meta: description = "Rule # 1695 Suspicious String Mrb3hz4d triggered"
	strings: $suspicious_string = "Mrb3hz4d"
	condition: $suspicious_string
}
rule Rule_1696_triggered {
	meta: description = "Rule # 1696 Suspicious String Iranian_Hackers triggered"
	strings: $suspicious_string = "Iranian_Hackers"
	condition: $suspicious_string
}
rule Rule_1697_triggered {
	meta: description = "Rule # 1697 Suspicious String H43ER triggered"
	strings: $suspicious_string = "H43ER"
	condition: $suspicious_string
}
rule Rule_1698_triggered {
	meta: description = "Rule # 1698 Suspicious String T4arik[J3N] triggered"
	strings: $suspicious_string = "T4arik[J3N]"
	condition: $suspicious_string
}
rule Rule_1699_triggered {
	meta: description = "Rule # 1699 Suspicious String NikbinHK triggered"
	strings: $suspicious_string = "NikbinHK"
	condition: $suspicious_string
}
rule Rule_1700_triggered {
	meta: description = "Rule # 1700 Suspicious String ImanGorji triggered"
	strings: $suspicious_string = "ImanGorji"
	condition: $suspicious_string
}
rule Rule_1701_triggered {
	meta: description = "Rule # 1701 Suspicious String EbRaHiM-VaKeR triggered"
	strings: $suspicious_string = "EbRaHiM-VaKeR"
	condition: $suspicious_string
}
rule Rule_1702_triggered {
	meta: description = "Rule # 1702 Suspicious String Perilous Man triggered"
	strings: $suspicious_string = "Perilous Man"
	condition: $suspicious_string
}
rule Rule_1703_triggered {
	meta: description = "Rule # 1703 Suspicious String BigNorouzi triggered"
	strings: $suspicious_string = "BigNorouzi"
	condition: $suspicious_string
}
rule Rule_1704_triggered {
	meta: description = "Rule # 1704 Suspicious String Storm Security Team triggered"
	strings: $suspicious_string = "Storm Security Team"
	condition: $suspicious_string
}
rule Rule_1705_triggered {
	meta: description = "Rule # 1705 Suspicious String Liosion Team triggered"
	strings: $suspicious_string = "Liosion Team"
	condition: $suspicious_string
}
rule Rule_1706_triggered {
	meta: description = "Rule # 1706 Suspicious String Hackeado por el Team Hack Hispano triggered"
	strings: $suspicious_string = "Hackeado por el Team Hack Hispano"
	condition: $suspicious_string
}
rule Rule_1707_triggered {
	meta: description = "Rule # 1707 Suspicious String TEAMHACKHISPANO triggered"
	strings: $suspicious_string = "TEAMHACKHISPANO"
	condition: $suspicious_string
}
