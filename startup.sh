#/bin/bash
########################################
########## NEW SERVER SET UP ###########
########################################
set -e
#
######### VARIABLES #
#
### COLORS #
#
YLW="\033[0;33m"
ULINE_YLW="\033[4;33m"
GRN="\033[0;32m"
ULINE_GRN="\033[4;32m"
RED="\033[0;31m"
BLUE="\033[0;36m"
END="\033[0m"
#
### SYSTEM #
#
VER=$(cat /etc/debian_version)
INT_IP=$(ip -4 address show)
HOSTNAME=$(cat /etc/hostname)
DNS_IP=$(sed -e '/^$/d' /etc/resolv.conf | awk '{if (tolower($1)=="nameserver") print $2}')
NET_ROUTE=$(netstat -nr | column -t)
IFACE_TRAFFIC=$(netstat -i | column -t)
#
### ETC #
#
#
######### PRINT WELCOME #
#
echo -e "$ULINE_GRN########## HELLO $USER@$HOSTNAME ##########$END"
sleep 2
#
######### SYS INFO #
#
echo -e "$ULINE_GRN########## SYSTEM INFO ##########$END"
sleep 2
echo -e "$ULINE_GRN########## TODAYS DATE ##########$END"
echo -e "$BLUE########## $(date) ##########$END"
echo -e "$ULINE_GRN########## LOGGED IN NOW ##########$END"
echo -e "$BLUE##########\n$(who -H | column -t)\n##########$END"
echo -e $YLW"Press enter to continue."$END
  read
echo -e "$ULINE_GRN########## LAST 5 LOGINS ##########$END"
echo -e "$BLUE##########\n$(last -n 5 | column -t)\n##########$END"
echo -e $GRN"Press enter to continue."$END
  read
echo -e $ULINE_YLW"Kernel info:$END $BLUE$(uname -s -r)"$END
echo -e $ULINE_YLW"Version:$END $BLUE$VER$END"
echo -e $GRN"Press enter to continue."$END
  read
echo -e $ULINE_YLW"Free space:"$END
echo -e "$BLUE$(free | column -t)$END"
echo -e $GRN"Press enter to continue."$END
  read
echo -e $YLW"Retrieving external ip..."$END
wget -q wtfismyip.com/text -O /tmp/ip
sleep 1
echo -e $ULINE_YLW"External IP:$END $BLUE$(cat /tmp/ip)"$END
rm -f /tmp/ip
echo -e $ULINE_YLW"Internal IP:$END\n$BLUE$INT_IP"$END
echo -e $GRN"Press enter to continue."$END
  read
echo -e $ULINE_YLW"Network routing:"$END
sleep 1
echo -e "$BLUE$NET_ROUTE$END"
echo -e $GRN"Press enter to continue."$END
  read
echo -e $ULINE_YLW"Interface traffic:"$END
sleep 1
echo -e "$BLUE$IFACE_TRAFFIC$END"
echo -e $GRN"Press enter to continue."$END
  read
#
######### CHECK FOR ROOT #
#
if [ $UID -ne 0 ]; then
    echo -e $RED"This program must be run as root."$END
    sleep 2
    exit 0
fi
#
######### CHECK/UPDATE VERSION/SOURCES #
#
if [[ $VER < 8 ]]; then
    echo -e $YLW"Since your version is$END $BLUE$VER$END$YLW."$END
    echo -e $YLW"Do you want to upgrade to jessie(8) ?"$END
    echo -e $RED"This may break your system. Answer no if you're scared."$END
    echo -e $YLW"(Y/n)"$END
      read UPDATE_SOURCES
        if [[ $UPDATE_SOUECES = no ]]; then
              echo -e $YLW"Ok. Leaving your sources as they were.\nYour sources are:"$END
              echo -e $BLUE"$(cat /etc/apt/sources.list)"$END
          else
              echo -e $YLW"Updating sources to jessie, and backing up your old sources to:"$END
              echo -e $GRN"/etc/apt/sources.list.bak"$END
              sleep 3
              mv /etc/apt/sources.list /etc/apt/sources.list.bak
              echo -e "deb http://ftp.us.debian.org/debian jessie main non-free contrib\n" > /etc/apt/sources.list
              echo -e "\ndeb-src http://ftp.us.debian.org/debian jessie main non-free contrib\n" >> /etc/apt/sources.list
              echo -e "\ndeb http://security.debian.org/ jessie/updates main non-free contrib\n" >> /etc/apt/sources.list
              echo -e "\ndeb-src http://security.debian.org/ jessie/updates main non-free contrib\n" >> /etc/apt/sources.list
              sleep 3
              if [[ -e /etc/apt/preferences ]]; then
                  cp /etc/apt/preferences /etc/apt/preferences.bak
                  echo -e $YLW"Apt preferences has been backed up to:$END\n$GRN/etc/apt/preferences.bak"$END
                  sleep 3
              else
                  echo -e $YLW"Apt preferences has been created at:$END\n$GRN/etc/apt/preferences"$END
              fi
          fi
              echo -e "\nPackage: *\nPin: release o=Debian,n=jessie\nPin-Priority: 800\n\n" > /etc/apt/preferences
              echo -e "\nPackage: *\nPin: release o=Debian,n=jessie/updates\nPin-Priority: 850\n\n" >> /etc/apt/preferences
              echo -e $YLW"Current apt preferences settings:"$END
              echo -e $BLUE"$(cat /etc/apt/preferences)"$END
else
    echo -e $YLW"Your current sources are:"$END
    echo -e "$BLUE$(cat /etc/apt/sources.list | column -t)$END"
    sleep 5
    echo -e $YLW"Do you want to change them to:"$END
    echo -e $BLUE"deb http://ftp.us.debian.org/debian jessie main non-free contrib\ndeb-src http://ftp.us.debian.org/debian jessie main non-free contrib\ndeb http://security.debian.org/ jessie/updates main non-free contrib\ndeb-src http://security.debian.org/ jessie/updates main non-free contrib"$END
    echo -e $YLW"(Y/no)"$END
      read CHANGE_JESSIE_SOURCES
        if [[ $CHANGE_JESSIE_SOURCES = no ]]; then
            sleep 1
        else
            echo -e $YLW"Updating sources and backing up your old sources to:"$END
            echo -e $GRN"/etc/apt/sources.list.bak"$END
            sleep 3
            mv /etc/apt/sources.list /etc/apt/sources.list.bak
            echo -e "deb http://ftp.us.debian.org/debian jessie main non-free contrib\n" > /etc/apt/sources.list
            echo -e "\ndeb-src http://ftp.us.debian.org/debian jessie main non-free contrib\n" >> /etc/apt/sources.list
            echo -e "\ndeb http://security.debian.org/ jessie/updates main non-free contrib\n" >> /etc/apt/sources.list
            echo -e "\ndeb-src http://security.debian.org/ jessie/updates main non-free contrib\n" >> /etc/apt/sources.list
        fi
  if [[ -e /etc/apt/preferences ]]; then
      cp /etc/apt/preferences /etc/apt/preferences.bak
      echo -e $YLW"Apt preferences has been backed up to:$END\n$GRN/etc/apt/preferences.bak"$END
      sleep 3
  else
      echo -e $YLW"Apt preferences has been created at:$END\n$GRN/etc/apt/preferences"$END
  fi
echo -e "\nPackage: *\nPin: release o=Debian,n=jessie\nPin-Priority: 800\n\n" > /etc/apt/preferences
echo -e "\nPackage: *\nPin: release o=Debian,n=jessie/updates\nPin-Priority: 850\n\n" >> /etc/apt/preferences
echo -e $YLW"Current apt preferences settings:"$END
echo -e $BLUE"$(cat /etc/apt/preferences)"$END
sleep 5   
fi
#
######### UPGRADE PACKAGES #
#
apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y
#
######### HARDEN SSH #
#
SSH_CONF=/etc/ssh/sshd_config
mv $SSH_CONF /etc/ssh/sshd_config.bak
touch $SSH_CONF
echo -e $YLW"Time to harden ssh."$END; sleep 1 
echo -e $YLW"We will backup your original configuration file at:"$END
echo -e $GRN"/etc/ssh/sshd_config.bak"$END; sleep 2
echo -e $YLW"Please answer the following questions to populate the rest of your sshd_config."$END; sleep 1
echo -e $YLW"If you don't know the answers, I will always phrase the questions so that $(echo '"Y"') is the most sensible."$END; sleep 1
echo -e $YLW"You must spell the word $(echo '"no"') exactly or the script will assume a $(echo '"yes"') answer."$END
echo -e $GRN"Press enter to continue"$END
  read
#
### PORT #
#
echo -e $YLW"Please have your ssh-rsa pubkey ready (if you have one)."$END
sleep 2
echo -e $YLW"Please select the new port for ssh (default is 22).\nIt should be a number that is 5 digits."$END
  read SSH_PORT
      if [[ $SSH_PORT -ge 1 || $SSH_PORT -le 99999 ]]; then
          echo -e "\nPort $SSH_PORT\n" > $SSH_CONF
      elif [[ -z $SSH_PORT ]]; then
          echo -e $RED"THAT WAS NOT AN ACCEPTABLE PORT!!!! RE-RUN THE SCRIPT AND PUT SOMETHING SENSIBLE HERE BEFORE YOU LOCK YOURSELF OUT!!"$END
          exit 0
      fi
#
### SSH KEY #
#
echo -e $YLW"Do you have an ssh key? (Y/no)"$END
  read HAVE_KEY
    if [[ $HAVE_KEY = no ]]; then
        sleep 1
    else
        echo -e $YLW"Please paste your public key (beginning with ssh-rsa)."$END
          read SSH_KEY
            if [[ -e /"$USER"/.ssh ]]; then
                echo -e "$SSH_KEY" > /$USER/.ssh/authorized_keys
                echo -e $YLW"Your public key:$END\n$BLUE$(echo -e "$SSH_KEY")"$END
                echo -e $YLW"Has been added to$END $GRN/$USER/.ssh/authorized_keys$END"
                sleep 3
                echo -e $YLW"Would you like to turn off password authentication? (Y/no)"$END
                  read SSH_PASS_AUTH
                    if [[ $SSH_PASS_AUTH = no ]]; then
                        sleep 1
                    else
                        echo -e "\nPasswordAuthentication no\n" >> $SSH_CONF
                        echo -e "\nPubKeyAuthentication yes\n" >> $SSH_CONF
                        echo -e "\nAuthorizedKeysFile $USER/.ssh/authorized_keys\n" >> $SSH_CONF
                    fi
                echo -e $YLW"Permit root login only by ssh key? (Y/no)"$END
                  read SSH_ROOT_LOGIN
                    if [[ $SSH_ROOT_LOGIN = no ]]; then
                        sleep 1
                    else  
                        echo -e "\nPermitRootLogin without-password\n" >> $SSH_CONF
                    fi
            else
                mkdir /$USER/.ssh/
                echo -e "$SSH_KEY" > /$USER/.ssh/authorized_keys
                echo -e $YLW"Your public key:$END\n$BLUE$(echo -e "$SSH_KEY")"$END
                echo -e $YLW"Has been added to$END $GRN/$USER/.ssh/authorized_keys$END"
                sleep 3
                echo -e $YLW"Would you like to turn off password authentication? (Y/no)"$END
                  read SSH_PASS_AUTH
                    if [[ $SSH_PASS_AUTH = no ]]; then
                        sleep 1
                    else
                        echo -e "\nPasswordAuthentication no\n" >> $SSH_CONF
                        echo -e "\nPubKeyAuthentication yes\n" >> $SSH_CONF
                        echo -e "\nAuthorizedKeysFile $USER/.ssh/authorized_keys\n" >> $SSH_CONF
                    fi
                echo -e $YLW"Permit root login only by ssh key? (Y/no)"$END
                  read SSH_ROOT_LOGIN
                    if [[ $SSH_ROOT_LOGIN = no ]]; then
                        sleep 1
                    else  
                        echo -e "\nPermitRootLogin without-password\n" >> $SSH_CONF
                    fi
            fi
    fi
#
### POPULATE CONFIG #
#
echo -e $YLW"Set StrictModes to yes? (Y/no)"$END
  read SSH_STRICT_MODES
    if [[ $SSH_STRICT_MODES = no ]]; then
        sleep 1
    else
        echo -e "\nStrictModes yes\n" >> $SSH_CONF
    fi
echo -e $YLW"Set Protocol to 2? (Y/no)"$END
  read  SSH_PROT
    if [[ $SSH_PROT = no ]]; then
        sleep 1
    else
        echo -e "\nProtocol 2\n" >> $SSH_CONF
    fi
echo -e $YLW"Set IgnoreRhosts to yes? (Y/no)"$END
  read  SSH_IGN_RHOSTS
    if [[ $SSH_IGN_RHOST = no ]]; then
        sleep 1
    else
        echo -e "\nIgnoreRhosts yes\n" >> $SSH_CONF
    fi
echo -e $YLW"Set GSSAPIAuthentication to no? (Y/no)"$END
  read SSH_GSSAPI
    if [[ $SSH_GSSAPI = no ]]; then
        sleep 1
    else
        echo -e "\nGSSAPIAuthentication no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set ChallengeResponseAuthentication to no? (Y/no)"$END
  read SSH_CR_AUTH
    if [[ $SSH_CR_AUTH = no ]]; then
        sleep 1
    else
        echo -e "\nChallengeResponseAuthentication no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set KerberosAuthentication to no? (Y/no)"$END
  read SSH_KERB
    if  [[ $SSH_KERB = no ]]; then
        sleep 1
    else
        echo -e "\nKerberosAuthentication no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set HostbasedAuthentication to no? (Y/no)"$END
  read SSH_HOST_AUTH
    if [[ $SSH_HOST_AUTH = no ]]; then
        sleep 1
    else
        echo -e "\nHostbasedAuthentication no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set X11Forwarding to no? (Y/no)"$END
  read SSH_X11_FORWARD
    if [[ $SSH_X11_FORWARD = no ]]; then
        sleep1
    else
        echo -e "\nX11Forwarding no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set PrintLastLog to yes? (Y/no)"$END
  read SSH_PRINT_LASTLOG
    if  [[ $SSH_PRINT_LASTLOG = no ]]; then
        sleep 1
    else
        echo -e "\nPrintLastLog yes\n" >> $SSH_CONF
    fi
echo -e $YLW"Set PermitEmptyPasswords to no? (Y/no)"$END
  read SSH_EMPTY_PASS
    if [[ $SSH_EMPTY_PASS = no ]]; then
        sleep 1
    else
        echo -e "\nPermitEmptyPasswords no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set UsePriveledgeSeperation to yes? (Y/no)"$END
  read SSH_PRIV_SEP
    if [[ $SSH_PRIV_SEP = no ]]; then
        sleep 1
    else
        echo -e "\nUsePriveledgeSeperation yes\n" >> $SSH_CONF
    fi
echo -e $YLW"Set UseLogin to no? (yes/no)"$END
  read SSH_USELOGIN
    if  [[ $SSH_USELOGIN = no ]]; then
        sleep 1
    else
        echo -e "\nUseLogin no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set PermitUserEnvironment to no? (Y/no)"$END
  read SSH_USER_ENV
    if [[ $SSH_USER_ENV = no ]]; then
        sleep 1
    else
        echo -e "\nPermitUserEnvironment no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set UsePAM to no? (Y/no)"$END
  read SSH_USE_PAM
    if [[ $SSH_USE_PAM = no ]]; then
        sleep 1
    else
        echo -e "\nUsePAM no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set AllowTcpForwarding to no? (Y/no)"$END
  read SSH_TCP_FORW
    if [[ $SSH_TCP_FORW = no ]]; then
        sleep 1
    else
        echo -e "\nAllowTcpForwarding no\n" >> $SSH_CONF
    fi
echo -e $YLW"Set LoginGraceTime to 300? (yes/no)"$END
  read SSH_LOGIN_GRACE
    if  [[ $SSH_LOGIN_GRACE = no ]]; then
        sleep 1
    else
        echo -e "\nLoginGraceTime 300\n" >> $SSH_CONF
    fi
echo -e $YLW"Set MaxStartups to 2? (Y/no)"$END
  read SSH_MAX_STARTUPS
    if [[ $SSH_MAX_STARTUPS = no ]]; then
        sleep 1
    else
        echo -e "\nMaxStartups 2\n" >> $SSH_CONF
    fi
echo -e $YLW"Set the following Cipher:"$END
echo -e $YLW"aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128? (Y/no)"$END
  read SSH_CIPHERS
    if [[ $SSH_CIPHERS = no ]]; then
        sleep 1
    else
        echo -e "\nCiphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128\n"$END >> $SSH_CONF
    fi
mv $SSH_CONF /root/temp.sshconf
sed '/^$/d' /root/temp.sshconf > $SSH_CONF
rm -f /root/temp.sshconf
echo -e $YLW"This is your new ssh configuration. Please take a moment to review it and note your new port."$END
sleep 1
echo -e $BLUE"$(cat /etc/ssh/sshd_config)"$END
sleep 5
echo -e $YLW"If you are not happy please type $(echo '"no"') to end the script now. You can run it again and repopulate the config. If you are happy press enter to continue."$END
  read SSH_HAPPY
    if [[ $SSH_HAPPY = no ]]; then
        exit 0
    fi
#
########## INSTALLS #
#
##### GET DETAILS #
#
echo -e $YLW"Is this a headless (no gui) server? If you don't answer $(echo '"no"') here you will not be offered gui only packages. (Y/no)"$END
  read INSTALL_GUIS
      if [[ $INSTALL_GUIS = no ]]; then
#
### MOZILLA REPO#
#
          echo -e $YLW"Do you want to add the mozilla iceweasel repo? (Y/no)"$END
            read ADD_MOZ
              if [[ $ADD_MOZ = no ]]; then
                  sleep 1
              else
                  echo "deb http://mozilla.debian.net/ jessie-backports iceweasel-release" >> /etc/apt/sources.list
                  gpg --keyserver keys.gnupg.net --recv 85F06FBC75E067C3F305C3C985A3D26506C4AE2A
                  gpg --check-sigs 0x06C4AE2A
                  gpg --export -a 06C4AE2A | apt-key add -
                  echo -e "\nPackage: *\nPin: release o=Mozilla,n=jessie-backports\nPin-Priority: 860\n\n" > /etc/apt/preferences
              fi
              echo -e $YLW"Add iceweasel? (Y/no)"$END
                read INSTALL_ICEWSL
              if [[ $INSTALL_ICEWSL = no ]]; then
                  sleep 1
              else
                  apt-get update
                  apt-get install iceweasel -y
                  echo -e $YLW"Install sandfox? (Y/no)"$END
                    read INSTALL_SFOX
                      if [[ $INSTALL_SFOX = no ]]; then
                          sleep 1
                      else
                          echo -e "\ndeb http://ignorantguru.github.com/debian/ unstable main\n" >> /etc/apt/sources.list
                          gpg --keyserver keys.gnupg.net --recv-keys 7977070A723C6CCB696C0B0227A5AC5A01937621
                          gpg --check-sigs 0x01937621
                          gpg --export -a 01937621 | apt-key add -
                          apt-get update
                          apt-get install sandfox -y
                      fi
            fi
      echo -e $YLW"Install pidgin/otr? (Y/no)"$END
        read INSTALL_PIDGIN
            if [[ $INSTALL_PIDGIN = no ]]; then
                sleep 1
            else
                apt-get install pidgin pidgin-otr pidgin-plugin-pack pidgin-privacy-please -y
            fi
      echo -e $YLW"Install geany, keepassx, and claws-mail? (Y/n)"$END
        read INSTALL_SUGGESTED_GUIS
            if [[ $INSTALL_SUGGESTED_GUIS = no ]]; then
                sleep 1
            else
                apt-get install geany keepassx claws-mail -y
            fi
      fi
#
### TOR REPO #
#
echo -e $YLW"Do you want to add the torproject repos? (Y/no)"$END
  read TOR_REPO
    if [[ $TOR_REPO = no ]]; then
        sleep 1
    else
        echo "deb http://deb.torproject.org/torproject.org jessie main" >> /etc/apt/sources.list
        echo "deb-src http://deb.torproject.org/torproject.org jessie main" >> /etc/apt/sources.list
        gpg --keyserver keys.gnupg.net --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
        gpg --check-sigs 0x886DDD89
        gpg --export -a 886DDD89 | apt-key add -
        echo -e "\nPackage: *\nPin: release o=TorProject,n=jessie\nPin-Priority: 900\n\n" >> /etc/apt/preferences
        echo -e $YLW"Install tor, tor-arm, privoxy, and obfsproxy? (Y/no)"$END
          read INSTALL_TOR
            if [[ $INSTALL_TOR = no ]]; then
                sleep 1
            else
                apt-get update
                apt-get install deb.torproject.org -y; apt-get install tor privoxy obfsproxy tor-arm -y
            fi
    fi
echo -e $YLW"Install screen, git, haveged, curl, atop, pwgen, secure-delete, lvm2, cryptsetup, badblocks, ntp, and ntpdate? (Y/no)"$END
  read INSTALL_SUGGESTED_DEFAULTS
      if [[ $INSTALL_SUGGESTED_DEFAULTS = no ]]; then
          sleep 1
      else
          apt-get install ntp ntpdate screen git haveged curl atop pwgen secure-delete lvm2 cryptsetup -y
          service ntp stop
          ntpdate 0.europe.pool.ntp.org
          service ntp start
          echo -e "\nhardstatus on\nhardstatus alwayslastline\n$(echo 'hardstatus string "%{.bW}%-w%{.rW}%n %t%{-}%+w %=%{..G} %H %{..Y} %m/%d %C%a "')\n" >> /etc/screenrc
      fi
#
### BITCOIN #
#
echo -e $YLW"Are you a bitcoiner? (Y/no)"$END
  read BITCOINER
      if [[ $BITCOINER = no ]]; then
          sleep 1
      elif [[ $INSTALL_GUIS != no ]]; then
          echo -e $YLW"Install bitcoin-core? (Y/no)"$END
            read INSTALL_BTC_CORE
              if [[ $INSTALL_BTC_CORE = no ]]; then
                  sleep 1
              else
                  echo -e $YLW"What user will run bitcoin? If the user doesn't exist it will be created."$END
                    read BTC_USER
                    BTC_USER_EXIST=$(grep -ic "$BTC_USER" /etc/passwd)
                      if [[ $BTC_USER_EXIST = 0 ]]; then
                          adduser $BTC_USER
                          adduser $BTC_USER sudo
                          mkdir /home/$BTC_USER/.bitcoin
                      else
                          sleep 1
                      fi
                  echo $YLW"You can build from source or download from bitcoin.org.\n$REDBuilding from source takes a long time and may break this script.$END\n$YLWDo you want to download directly from bitcoin.org? (Y/no)"$END
                    read BTC_DIRECT_DL
                      if [[ $BTC_DIRECT_DL = no ]]; then
                          echo -e $YLW"Installing dependencies to build bitcoin core"$END
                          sleep 8
                          apt-get install automake pkg-config build-essential libtool autotools-dev autoconf libssl-dev libboost-all-dev libdb-dev libdb++-dev -y
                          mkdir /root/bitcoinsrc && cd /root/bitcoinsrc
                          echo -e $YLW"Getting source code from github."$END
                          sleep 8
                          git clone https://github.com/bitcoin/bitcoin
                          cd bitcoin
                          git checkout master
                          echo -e $YLW"Building/installing bitcoin core now. You may want to take a nap."$END
                          sleep 8
                          ./autogen.sh
                          ./configure
                          make
                          sudo make install
                      else
                          sleep 1
                      fi
              fi
      fi
                  
exit 0     
## To Do.
#  GPG
#  Crunchbang Paranoid Security
#  
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
