#!/bin/bash

if [ $# -lt 1 ]
then
echo "Scan iOS Source for Vulns"
echo "Usage: `basename $0` project_path"
exit 1
fi

pp=$1

echo "Ghetto iOS Source Scanner by Jason Haddix"
echo ""
echo ""
echo ""
echo "#######################################################################"
echo "# HTTP(s) Calls:                                                      #"
echo "#######################################################################"
echo ""
grep -r -a "://" $pp | awk -F "http" '{print $2}'|grep -a -v 'svn' |sort -u
grep -H -i -n -r -C2 "openUrl\|handleOpenURL" $pp
echo ""
echo "#######################################################################"
echo "# Project Calls or Imports sqlite in the following files:             #"
echo "#######################################################################"
echo ""
grep -r -a -F "sqlite" $pp |grep -a -v 'svn'|cut -d ":" -f1| sort -u
echo ""
echo "#######################################################################"
echo "# Check for SQLi (%@ and no ? in SQL Statement):             #"
echo "#######################################################################"
echo ""
grep -r -H -i -n  -e "insert" $pp
grep -r -H -i -n -e "delete" $pp
grep -r -H -i -n  -e "select" $pp
grep -r -H -i -n  -e "table" $pp
grep -r -H -i -n -e "cursor" $pp
grep -r -H -i -n -e "import" $pp
echo ""
echo "#######################################################################"
echo "# Password References:                                                #"
echo "#######################################################################"
echo ""
grep -r -F 'password' $pp |grep -a -v svn| sort -u
echo ""
echo "#######################################################################"
echo "# Logging:                                                            #"
echo "#######################################################################"
echo ""
grep -r -F 'NSLog' $pp |grep -a -v svn| sort -u
echo ""
echo "#######################################################################"
echo "# Encryption/Encoding Checks                                          #"
echo "#######################################################################"
echo ""
echo "******Is 3rd party database encryption used?******"
echo ""
grep -r -a -F 'sqlcipher' $pp |grep -a -v 'svn'|sort -u
grep -r -a -F 'CEROD' $pp |grep -a -v 'svn'|sort -u
echo ""
echo "******Keychain used in: ******"
echo ""
grep -r -a -F 'kSecASttr' $pp |grep -a -v 'svn'|cut -d ":" -f1| sort -u
grep -r -a -F 'SFHFKkey' $pp |grep -a -v 'svn'|cut -d ":" -f1| sort -u
echo ""
echo "******Weak SSL Configuration******"
echo ""
grep -r -a -F "setAllowsAnyHTTPSCertificate" $pp
grep -r -a -F "continueWithoutCredentialForAuthenticationChallenge" $pp
grep -r -a -F "kCFStreamSSLAllowsExpiredCertificates" $pp
grep -r -a -F "kCFStreamSSLAllowsExpiredRoots" $pp
grep -r -a -F "kCFStreamSSLAllowsAnyRoot" $pp
echo ""
echo "******Data over HTTP******"
echo ""
grep -H -i -n -e "http://" -r $pp
grep -H -i -n -e "NSURL" -r $pp
grep -H -i -n  -e "URL" -r $pp
grep -H -i -n  -e "writeToUrl" -r $pp
grep -H -i -n  -e "NSURLConnection" -r $pp
grep -H -i -n -C2 "CFStream" -r $pp
grep -H -i -n  -C2 "NSStreamin" -r $pp
echo ""
echo "******Handling queries with sqlite3_prepare()******"
grep -r -a "sqlite3_prepare(" $pp
echo ""
echo "******Base64, MD5 Encoding******"
grep -r -F "base64" $pp |sort -u
grep -H -i -n  -e "MD5" -r $pp
echo ""
echo "#######################################################################"
echo "# Vuln C calls or functions to avoid:                                 #"
echo "#######################################################################"
echo ""
grep -r -F 'strcat' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'strcpy' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'strncat' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'strncpy' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'sprintf' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'vsprintf' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'fopen ' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'gets(' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'chmod' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F -w 'stat(' $pp |grep -a -v 'svn'|grep -v binary|sort -u
grep -r -F 'mktemp' $pp |grep -a -v 'svn'|grep -v binary|sort -u
echo ""
echo "#######################################################################"
echo "# File Handling:                                                      #"
echo "#######################################################################"
echo ""
grep -r -F 'NSFile' $pp |grep -a -v 'svn'|sort -u
grep -r -F 'writeToFile' $pp |grep -a -v 'svn'|sort -u
echo ""
echo "#######################################################################"
echo "# Possible Obj-C Format String methods in:                            #"
echo "#######################################################################"
echo ""
egrep -r "NSLog[^\"']*(,|\))" $pp |grep -a -v 'svn'|grep -a -v 'Binary'|sort -u
egrep -r "stringWithFormat[^\"']*(,|])" $pp |grep -a -v 'svn'|grep -a -v 'Binary'|sort -u
egrep -r "initWithFormat[^\"']*(,|\])" $pp |grep -a -v 'svn'|grep -v 'Binary'|sort -u
egrep -r "appendFormat[^\"']*(,|\])" $pp |grep -a -v 'svn'|grep -a -v 'Binary'|sort -u
egrep -r "informativeTextWithFormat[^\"']*(,|\])" $pp |grep -a -v 'svn'|grep -a -v 'Binary'|sort -u
egrep -r "predicateWithFormat[^\"']*(,|\])" $pp |grep -a -v 'svn'|grep -a -v 'Binary'|sort -u
egrep -r "stringByAppendingFormat[^\"']*(,|\])" $pp |grep -a -v 'svn'|grep -a -v 'Binary'|sort -u
egrep -r "alertWithMessageText[^\"']*(,|\])" $pp |grep -a -v 'svn'|grep -a -v 'Binary'|sort -u
egrep -r "NSException +format[^\"']*(,|\])" $pp |grep -a -v 'svn'|grep -a -v 'Binary'|sort -u
grep -r -F "NSRunAlertPanel" $pp |grep -a -v 'svn'|sort -u
echo ""
