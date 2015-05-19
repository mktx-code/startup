#/bin/bash
########################################
########## NEW SERVER SET UP ###########
########################################
set -e
#
######### VARIABLES #
#
### COLORS #
YLW="\033[1;33m"
GRN="\033[01;32m"
RED="\033[1;31m"
BLUE="\033[1;34m"
END="\033[0m"
#
### SYSTEM #
VER=$(cat /etc/debian_version)
EXT_IP=$(wget wtfismyip.com/text)
HAS_APT_PREF=$(ls /etc/apt/ | grep -ic "preferences")
#
### ETC #
#
KWS=$(sed -i  '/^$/d' # To remove white spaces from files.
######### PRINT WELCOME #
#
echo -e $YLW"Welcome to the startup script,\n$BLUE$USER$END.\nYou are currently running $BLUE$(uname -s -r)\n$VAR$END"$END
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
if [[ $VER < 8 ]];
    echo -e $YLW"Since your version is$END $BLUE$VER$END$YLW."$END
    echo -e $YLW"Do you want to upgrade to jessie(8) ?"$END
    echo -e $RED"This may break your system. Answer no if you're scared."$END
    echo -e $YLW"(Y/n)"$END
      read UPDATE_SOURCES
          if [[ $UPDATE_SOURCES = Y || $UPDATE_SOURCES = y ]]; then
              echo -e $YLW"Updating sources to jessie, and backing up your old sources to:"$END
              echo -e $GRN"/etc/apt/sources.list.bak"$END
              sleep 2
              mv /etc/apt/sources.list /etc/apt/sources.list.bak
              echo -e "deb http://ftp.us.debian.org/debian jessie main non-free contrib\n" > /etc/apt/sources.list
              echo -e "deb-src http://ftp.us.debian.org/debian jessie main non-free contrib\n" >> /etc/apt/sources.list
              echo -e "\ndeb http://security.debian.org/ jessie/updates main non-free contrib\n" >> /etc/apt/sources.list
              echo -e "\ndeb-src http://security.debian.org/ jessie/updates main non-free contrib\n" >> /etc/apt/sources.list
          else
              echo -e $YLW"Ok. Leaving your sources as they were.\nYour sources are:"$END
              echo -e $BLUE"$(cat /etc/resolv.conf)"$END
              sleep 4
          fi
fi
if [[ $HAS_APT_PREF = 0 ]]; then
fi
#
######### UPGRADE PACKAGES #
#
apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y
#
######### HARDEN SSH #
#
### SSH KEY #
#
SSH_CONF=/etc/ssh/sshd_config
mv $SSH_CONF /etc/ssh/sshd_config.bak
touch $SSH_CONF
echo -e $YLW"Time to harden ssh. We will backup your original configuration file at:"$END
echo -e $GRN"/etc/ssh/sshd_config.bak"$END
echo -e $YLW"Do you have an ssh key? (Y/n)"$END
  read HAVE_KEY
    if [[ $HAVE_KEY = Y || $HAVE_KEY = y ]]; then
        echo -e $YLW"Please paste your public key (beginning with ssh-rsa)"$END
          read SSH_KEY
              mkdir $USER/.ssh
              cat $SSH_KEY > $USER/.ssh/authorized_keys
              echo -e $YLW"Your public key:$END\n$BLUE$(echo -e "$SSH_KEY")"$END
              sleep 1
              echo -e $YLW"Has been added to$END $GRN/$USER/.ssh/authorized_keys$END"
              sleep 2
              echo -e $YLW"Would you like to turn off password authentication? (Y/n)"$END
                read SSH_PASS_AUTH
                  if [[ $SSH_PASS_AUTH = Y || $SSH_PASS_AUTH = y ]]; then
                      echo -e "\nPasswordAuthentication no\n" >> $SSH_CONF
                      echo -e "\nPubKeyAuthentication yes\n" >> $SSH_CONF
                      echo -e "\nAuthorizedKeysFile $USER/.ssh/authorized_keys\n" >> $SSH_CONF
                  fi
              echo -e $YLW"Permit root login only by ssh key? (Y/n)"$END
                read SSH_ROOT_LOGIN
                  if [[ $SSH_ROOT_LOGIN = Y || $SSH_ROOT_LOGIN = y ]]; then  
                      echo -e "\nPermitRootLogin without-password\n" >> $SSH_CONF
                  fi
    fi
#
### POPULATE CONFIG #
#
echo -e $YLW"Please answer the following questions to populate the rest of your sshd_config. If you don't know the answers, I will always phrase the questions so that $(echo '"Y"') is the most sensible. You must spell the word $(echo '"no"') exactly or the script will assume a $(echo '"yes"') answer."$END
sleep 1
echo -e $YLW"Please select the new port for ssh (default is 22).\nIt should be a number that is 5 digits."$END
  read SSH_PORT
      if [[ $SSH_PORT > 1 || $SSH_PORT < 99999 ]]; then
          echo -e "\nPort $SSH_PORT\n" >> $SSH_CONF
      else
          echo -e $RED"THAT WAS NOT AN ACCEPTABLE PORT!!!! RE-RUN THE SCRIPT AND PUT SOMETHING SENSIBLE HERE BEFORE YOU LOCK YOURSELF OUT!!"$END
          exit 0
      fi
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
$KWS$SSH_CONFIG)
echo -e $YLW"This is your new ssh configuration. Please take a moment to review it and note your new port. If you are unhappy with this config please type $(echo '"no"') to end the script. You can run it again and repopulate the config. If you are happy press anything to continue."$END
sleep 10
echo -e $BLUE"$(cat /etc/ssh/sshd_config)"$END
  read SSH_HAPPY
    if [[ $SSH_HAPPY = no ]]; then
        exit 0
    fi
#
########## INSTALLS #
#
### TOR REPO#
#
echo -e $YLW"Do you want to add the torproject repos? (Y/no)"$END
  read TOR_REPO
    if [[ $TOR_REPO = no ]]; then
        sleep 1
    else
        echo "deb http://deb.torproject.org/torproject.org jessie main" >> /etc/apt/sources.list
        echo "deb-src http://deb.torproject.org/torproject.org jessie main" >> /etc/apt/sources.list
        echo "deb http://deb.torproject.org/torproject.org tor-experimental-0.2.6.x-jessie main" >> /etc/apt/sources.list
        echo "deb-src http://deb.torproject.org/torproject.org tor-experimental-0.2.6.x-jessie main" >> /etc/apt/sources.list
        gpg --keyserver keys.gnupg.net --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
        gpg --check-sigs 0x886DDD89
        gpg --export -a 886DDD89 | apt-key add -
        echo -e $YLW"Do you want to install tor, tor-arm, privoxy, and obfsproxy? (Y/no)"$END
          read INSTALL_TOR
            if [[ $INSTALL_TOR = no ]]; then
                sleep 1
            else
                apt-get update
                apt-get install -t tor-experimental-0.2.6.x-jessie deb.torproject.org -y; apt-get install -t tor-experimental-0.2.6.x-jessie tor privoxy obfsproxy tor-arm -y
            fi
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
    fi
echo -e $YLW"Add iceweasel? (Y/no)"$END
  read INSTALL_ICEWSL
    if [[ $INSTALL_ICEWSL = no ]]; then
        sleep 1
    else
        apt-get update
        apt-get install -t jessie-backports iceweasel -y
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
#apt-get ntp ntpdate install screen git haveged curl atop pwgen secure-delete lvm2 cryptsetup -y
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
