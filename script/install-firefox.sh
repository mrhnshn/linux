#!/bin/bash
umask 022
clear
###variables###
LOCKFILE="/tmp/install-firefox.lock"


###lock file###
if [ -e "$LOCKFILE" ]; then
  echo "| ERROR | Another 'install-firefox.sh' process is currently running."
  exit 2
fi

echo "| INFO  | Script Started - $(date +'%F %T')"
touch "$LOCKFILE"


###functions###
exit_script() {
  rm -f $LOCKFILE 2>/dev/null
  echo "| INFO  | Script Finished - $(date +'%F %T')"
}


###check requirements###
#check effective user id
if [[ $EUID -eq 0 ]]
then
  echo "| OK    | Check Effective User ID"
else
  echo "| ERROR | Check Effective User ID"
  echo "|       | This script must be run as root."
  exit_script
  exit 2
fi

#check internet connection
if [[ -x $(command -v ping) ]]
then
  if ping -c1 -4 -q google.com &>/dev/null
  then
    echo "| OK    | Check Internet Connection"
  else
    echo "| ERROR | Check Internet Connection"
    echo "|       | Internet connection is not available."
    exit_script
  fi
fi

#check 'bzip2' command availability
if [[ -x $(command -v bzip2) ]]
then
  echo "| OK    | Check 'bzip2' Command Availability"
else
  echo "| ERROR | Check 'bzip2' Command Availability"
  echo "|       | 'bzip2' command is missing or not configured/installed properly."
  exit_script
  exit 2
fi

#check 'wget' command availability
if [[ -x $(command -v wget) ]]
then
  echo "| OK    | Check 'wget' Command Availability"
else
  echo "| ERROR | Check 'wget' Command Availability"
  echo "|       | 'wget' command is missing or not configured/installed properly."
  exit_script
  exit 2
fi

#check 'firefox' installation
if [ -f "/opt/firefox/firefox" ]
then
  echo "| INFO  | Firefox is already installed on the system. It will be updated."
  VERSION=$(grep Milestone /opt/firefox/platform.ini | cut -d'=' -f2)
  if [ -z "$VERSION" ]
  then
    echo "|       | The installed version of Firefox could not be determined."
  else
    echo "|       | The current installed version of Firefox is: $VERSION"
  fi
else
  echo "| INFO  | Firefox is not installed on the system. It will be installed."
fi


wget -q -O /tmp/firefox.tar.bz2 "https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-GB"
bzip2 -f -d /tmp/firefox.tar.bz2
tar -xf /tmp/firefox.tar -C /opt

ln -sf /opt/firefox/firefox /usr/local/bin/firefox
echo "
[Desktop Entry]
Version=1.0
Name=Firefox Web Browser
Keywords=Internet;WWW;Browser;Web;Explorer
Exec=firefox %u
Terminal=false
X-MultipleArgs=false
Type=Application
Icon=/opt/firefox/browser/chrome/icons/default/default128.png
Categories=GNOME;GTK;Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;application/xml;application/rss+xml;application/rdf+xml;image/gif;image/jpeg;image/png;x-scheme-handler/http;x-scheme-handler/https;x-scheme-handler/ftp;x-scheme-handler/chrome;video/webm;application/x-xpinstall;
" > /usr/share/applications/firefox.desktop

VERSION=$(grep Milestone /opt/firefox/platform.ini | cut -d'=' -f2)
echo "| OK    | Installation/update process completed."
echo "|       | The current installed version of Firefox is: $VERSION"
exit_script
