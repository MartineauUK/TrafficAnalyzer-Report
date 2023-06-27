#!/bin/sh
VER="v1.15"
#======================================================================================= © 2016-2023 Martineau v1.15
#
# Scan Traffic Analyzer database
#
#    TrafficAnalyzer     [help | -h] ['ip='{[ip_address[,...] | hostname[...]]}] ['app='{category_name[,...]}] ['app='{application_name[,...]}]
#                        ['date='[yyyy/mm/dd[,...]]] ['time='[hh:mm:ss[,...]]] ['sqldb='{database}] ['backup[=directory]'] ['nofilter'] ['email']  ['mode=or'] ['noscript']
#                        ['count'] ['sortby='column] ['trimdb[='max_sqldb_size]] ['mac='mac_address[,...]] ['report='{file_name}] [nodisplay] ['showsql']
#
#    TrafficAnalyzer
#                        Will list the script's DEFAULT Category entries in the Traffic Analyzer database containing 'Social' AND 'Instant'
#    TrafficAnalyzer     count
#                        Will count the script's DEFAULT Category entries in the Traffic Analyzer database containing 'Social' AND 'Instant'
#                        and will only display the result count. No records are displayed on screen.
#    TrafficAnalyzer     nofilter
#                        Will list ALL entries in the Traffic Analyzer database.
#    TrafficAnalyzer     nofilter sortby=app
#                        Will list ALL entries in the Traffic Analyzer database sorted by column Application name
#    TrafficAnalyzer     nofilter email
#                        Will list ALL entries in the Traffic Analyzer database and will send an email with the results
#    TrafficAnalyzer     nofilter report=Traffic.csv nodisplay
#                        Will list ALL entries in the Traffic Analyzer database and will write results to file 'Traffic.csv'
#                        and no records will be displayed on screen.
#    TrafficAnalyzer     cat=VoIP,Social
#                        Case sensitive; Will list Category entries in the Traffic Analyzer database for 'VoIP' AND 'Social'
#    TrafficAnalyzer     app=Facebook,Netflix mode=or
#                        Case sensitive; Will list Application entries in the Traffic Analyzer database containing either 'Facebook' OR 'Netflix'
#    TrafficAnalyzer     date=2017/02/30
#                        Will list entries in the Traffic Analyzer database created on '30th Feb 2017'
#                        NOTE: The date specification can be an abbreviation e.g. '2017/02' for records created in 'Feb 2017'
#    TrafficAnalyzer     ip=10.88.8.123,192.168.1.99
#                        Will list entries in database for two devices - either '10.88.8.123' or '192.168.1.99'
#                        NOTE: Only MAC addresses are stored in the database so if the devices are not 'reserved/static'
#                              then the report could be inaccurate.
#    TrafficAnalyzer     mac=de:ad:de:ad:de:ad
#                        Will list entries in databasefor MAC address 'de:ad:de:ad:de:ad'
#    TrafficAnalyzer     ip=10.88.8.123, 192.168.1.120-192.168.1.123, CAMERAS
#                        Will list database entries for five devices, plus all IPs for 'CAMERAS' entry in '/jffs/configs/IPGroups'
#    TrafficAnalyzer     time=09:
#                        Will list entries in the Traffic Analyzer database created between '09:00' to '09:59'
#                        NOTE: A full time specification can be used e.g. '12:05:30' but the report may never find a match!
#    TrafficAnalyzer     backup
#                        The current Traffic Analyzer database will be backed up to '/opt/var/Traffic Analyzer/'
#    TrafficAnalyzer     sqldb=/opt/var/TrafficAnalyzer/TrafficAnalyzer.db-Backup-20180401-060000
#                        The report/queries will be extracted from the archive/backup database '/opt/var/TrafficAnalyzer/TrafficAnalyzer.db-Backup-20180401-060000'
#    TrafficAnalyzer     purgeallreset
#                        The current Traffic Analyzer database is PURGED of ALL history!!!!! (NOTE: a backup is taken first ;-)
#    TrafficAnalyzer     trimdb
#                        The current Traffic Analyzer database is reduced to 30MB - ASUS recommended (NOTE: a backup is taken first ;-)
#    TrafficAnalyzer     trimdb=12m
#                        The current Traffic Analyzer database is reduced to 12MB (NOTE: a backup is taken first ;-)
#
#                           table_main-1: over size 12288, timestamp=1554073200
#                           start to delete some rules from /jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db because of over size
#    TrafficAnalyzer    showsql
#                       Debug the resulting filter(s) by showing the actual SQL query

# To filter by additional criteria just use grep/awk etc. to apply additional filters
#

# [URL="https://www.snbforums.com/threads/web-history-reporting-and-management-traffic-analyzer-aiprotection-monitor.49888/"]Web History Reporting and Management (Traffic Analyzer/Aiprotection Monitor)[/URL]

Say(){
   echo -e $$ $@ | logger -st "($(basename $0))"
}
SayT(){
   echo -e $$ $@ | logger -t "($(basename $0))"
}
#
# Print between line beginning with'#==' to first blank line inclusive
ShowHelp() {
    /usr/bin/awk '/^#==/{f=1} f{print; if (!NF) exit}' $0
}
# shellcheck disable=SC2034
ANSIColours () {
    cRESET="\e[0m";cBLA="\e[30m";cRED="\e[31m";cGRE="\e[32m";cYEL="\e[33m";cBLU="\e[34m";cMAG="\e[35m";cCYA="\e[36m";cGRA="\e[37m";cFGRESET="\e[39m"
    cBGRA="\e[90m";cBRED="\e[91m";cBGRE="\e[92m";cBYEL="\e[93m";cBBLU="\e[94m";cBMAG="\e[95m";cBCYA="\e[96m";cBWHT="\e[97m"
    aBOLD="\e[1m";aDIM="\e[2m";aUNDER="\e[4m";aBLINK="\e[5m";aREVERSE="\e[7m"
    aBOLDr="\e[21m";aDIMr="\e[22m";aUNDERr="\e[24m";aBLINKr="\e[25m";aREVERSEr="\e[27m"
    cWRED="\e[41m";cWGRE="\e[42m";cWYEL="\e[43m";cWBLU="\e[44m";cWMAG="\e[45m";cWCYA="\e[46m";cWGRA="\e[47m"
    cYBLU="\e[93;48;5;21m"
    xHOME="\e[H";xERASE="\e[K";xERASEDOWN="\e[J";xERASEUP="\e[1J";xCSRPOS="\e[s";xPOSCSR="\e[u"
}
StatusLine() {

    local ACTION=$1
    local FLASH="$aBLINK"

    if [ "${ACTION:0:7}" != "NoANSII" ];then

        [ "${ACTION:0:7}" == "NoFLASH" ] && local FLASH=

        local TEXT=$2

        echo -en $xCSRPOS                               # Save current cursor position

        case $ACTION in
            *Clear*)    echo -en ${xHOME}${cRESET}$xERASE;;
            *)          echo -en ${xHOME}${aBOLD}${FLASH}${xERASE}$TEXT;;
        esac

        echo -en $xPOSCSR                               # Restore previous cursor position
    fi

}
# Function Parse(String delimiter(s) variable_names)
Parse() {
    #
    #   Parse       "Word1,Word2|Word3" ",|" VAR1 VAR2 REST
    #               (Effectivley executes VAR1="Word1";VAR2="Word2";REST="Word3")

    local string IFS

    TEXT="$1"
    IFS="$2"
    shift 2
    read -r -- "$@" <<EOF
$TEXT
EOF
}
Chk_Entware() {

    # ARGS [wait attempts] [specific_entware_utility]

    local READY=1                  # Assume Entware Utilities are NOT available
    local ENTWARE="opkg"
    ENTWARE_UTILITY=                # Specific Entware utility to search for (Tacky GLOBAL variable returned!)

    local MAX_TRIES=30
    if [ -n "$2" ] && [ -n "$(echo $2 | grep -E '^[0-9]+$')" ];then
        local MAX_TRIES=$2
    fi

    if [ -n "$1" ] && [ -z "$(echo $1 | grep -E '^[0-9]+$')" ];then
        ENTWARE_UTILITY=$1
    else
        if [ -z "$2" ] && [ -n "$(echo $1 | grep -E '^[0-9]+$')" ];then
            MAX_TRIES=$1
        fi
    fi

   # Wait up to (default) 30 seconds to see if Entware utilities available.....
   local TRIES=0
   while [ $TRIES -lt $MAX_TRIES ];do
      if [ -n "$(which $ENTWARE)" ] && [ "$($ENTWARE -v | grep -o "version")" == "version" ];then       # Check Entware exists and it executes OK
         if [ -n "$ENTWARE_UTILITY" ];then                                      # Specific Entware utility installed?
            if [ -n "$($ENTWARE list-installed $ENTWARE_UTILITY)" ];then
                READY=0                                                         # Specific Entware utility found
            else
                # Not all Entware utilities exist as a stand-alone package e.g. 'find' is in package 'findutils'
                #   opkg files findutils
                #
                #   Package findutils (4.6.0-1) is installed on root and has the following files:
                #   /opt/bin/xargs
                #   /opt/bin/find
                # Add 'executable' as 'stubby' leaves behind two directories containing the string 'stubby'
                if [ "$(which find)" == "/opt/bin/find" ];then
                    if [ -d /opt ] && [ -n "$(find /opt/ -type f -executable -name $ENTWARE_UTILITY)" ];then
                        READY=0                                                     # Specific Entware utility found
                    fi
                else
                    logger -st "($(basename $0))" $$ "Unable to verify existence of Entware" $ENTWARE_UTILITY". Please install Entware 'find'"
                fi
            fi
         else
            READY=0                                                             # Entware utilities ready
         fi
         break
      fi
      sleep 1
      logger -st "($(basename $0))" $$ "Entware" $ENTWARE_UTILITY "not available - wait time" $((MAX_TRIES - TRIES-1))" secs left"
      local TRIES=$((TRIES + 1))
   done

   return $READY
}
SendMail(){

#=================================> Insert favorite routine here
#=================================> Insert favorite routine here
#=================================> Insert favorite routine here

    Say "You need to edit this script and add the Sendmail function first!"

    return 0

}
ExpandIPRange() {

    # '192.168.1.30 192.168.1.50-192.168.1.54' -> '192.168.1.30 192.168.1.50 192.168.1.51 192.168.1.52 192.168.1.53 192.168.1.54'

    local HOST_NAME=0                                   # Hostname found/returned
    local IP_LIST=
    local START_RANGE=
    local END_RANGE=
    local NUM=
    local MAX=

    local LANIPADDR=`nvram get lan_ipaddr`
    local LAN_PREFIX=${LANIPADDR%.*}                    # 1.2.3.99 -> 1.2.3

    for THIS in $@
        do

            if [ -n "$(echo "$THIS" | grep -E "^#")" ];then
                break               # Ignore comment
            fi

            # If any alphabetic characters then assume it is a name e.g. LIFX-Table_light
            if [ -z "$(echo $THIS | grep "[A-Za-z]")" ];then

                if [ -n "$(echo $THIS | grep "-")" ];then

                    Parse $THIS "-" START_RANGE END_RANGE               # 1.2.3.90-1.2.3.99 -> 1.2.3.90 1.2.3.99
                    local START_PREFIX=${START_RANGE%.*}                # 1.2.3.90 -> 1.2.3
                    local END_PREFIX=${END_RANGE%.*}                    # 1.2.3.99 -> 1.2.3

                    if [ "$START_PREFIX" != "$END_PREFIX" ];then        # Restrict range of devices to 254
                        Say "***ERROR*** invalid IP range" $THIS
                        echo ""
                        return 100
                    fi

                    NUM=${START_RANGE##*.}                              # Extract 4th octet 1.2.3.90 -> 90
                    MAX=${END_RANGE##*.}                                # Extract 4th octet 1.2.3.99 -> 99
                    while [ $NUM -le $MAX ]
                        do
                            IP_LIST=$IP_LIST" "$START_PREFIX"."$NUM
                            NUM=$(($NUM+1))
                        done
                else
                    local THIS_PREFIX=${THIS%.*}
                    if [ "$THIS_PREFIX" != "$LAN_PREFIX" ];then
                        Say "***ERROR '"$THIS"' is not on this LAN '"$LAN_PREFIX".0/24'"
                        echo ""
                        return 200
                    else
                        IP_LIST=$IP_LIST" "$THIS                        # Add to list
                    fi
                fi
            else
                # Let the caller ultimately decide if non-IP is valid!!!
                #Say  "**Warning non-IP" $THIS
                IP_LIST=$IP_LIST" "$THIS                                # Add to list
                HOST_NAME=1
            fi

            shift 1
        done

    echo $IP_LIST

    if [ $HOST_NAME -eq 1 ];then
        return 300
    else
        return 0
    fi
}
Convert_TO_IP () {

    # Perform a lookup if a hostname (or I/P address) is supplied and is not known to PING
    # NOTE: etc/host.dnsmasq is in format
    #
    #       I/P address    hostname
    #

    local USEPATH="/jffs/configs"

    if [ -n "$1" ];then

        if [ -z $2 ];then                                   # Name to IP Address
           local IP_NAME=$(echo $1 | tr '[a-z]' '[A-Z]')

           local IP_RANGE=$(ping -c1 -t1 -w1 $IP_NAME 2>&1 | tr -d '():' | awk '/^PING/{print $3}')

           # 127.0.53.53 for ANDROID? https://github.com/laravel/valet/issues/115
           if [ -n "$(echo $IP_RANGE | grep -E "^127")" ];then
              local IP_RANGE=
           fi

           if [ -z "$IP_RANGE" ];then       # Not PINGable so lookup static

              [ -f /etc/hosts.dnsmasq ] && IP_RANGE=$(grep -i "$IP_NAME" /etc/hosts.dnsmasq  | awk '{print $1}')	# v1.15

			  if [ -z "$IP_RANGE" ] && [ -f /jffs/addons/YazDHCP.d/.hostnames ];then								# v1.15
				IP_RANGE=$(grep -i "$IP_NAME" /jffs/addons/YazDHCP.d/.hostnames | awk '{print $1}')					# v1.15
			  fi

              #logger -s -t "($(basename $0))" $$ "Lookup '$IP_NAME' in DNSMASQ returned:>$IP_RANGE<"

              # If entry not matched in /etc /hosts.dnsmasq see if it exists in our IPGroups lookup file
              #
              #       KEY     I/P address[ {,|-} I/P address]
              #
              if [ -z "$IP_RANGE" ] && [ -f $USEPATH/IPGroups ];then
                 #IP_RANGE=$(grep -i "^$IP_NAME" $USEPATH/IPGroups | awk '{print $2}')
                 IP_RANGE=$(grep -i "^$IP_NAME" $USEPATH/IPGroups  | awk '{$1=""; print $0}')   # All columns except 1st to allow '#comments' and
    #                                                                                                   #     spaces and ',' between IPs v1.07
                 #logger -s -t "($(basename $0))" $$ "Lookup '$IP_NAME' in '$USEPATH/IPGroups' returned:>$IP_RANGE<"
              fi
           fi
        else                                                # IP Address to name
            IP_RANGE=$(nslookup $1 | grep "Address" | grep -v localhost | cut -d" " -f4)
        fi
    else
       local IP_RANGE=                                  # Return a default WiFi Client????
       #logger -s -t "($(basename $0))" $$ "DEFAULT '$IP_NAME' lookup returned:>$IP_RANGE<"
    fi

    echo $IP_RANGE
}
Hostname_from_IP () {

    local HOSTNAMES=

    for IP in $@
        do
            local HOSTNAME=$(Convert_TO_IP "$IP" "Reverse")
            HOSTNAMES=$HOSTNAMES" "$HOSTNAME
        done
    echo $HOSTNAMES
}
Is_Private_IPv4 () {
    # 127.  0.0.0 – 127.255.255.255     127.0.0.0 /8
    # 10.   0.0.0 –  10.255.255.255      10.0.0.0 /8
    # 172. 16.0.0 – 172. 31.255.255    172.16.0.0 /12
    # 192.168.0.0 – 192.168.255.255   192.168.0.0 /16
    #grep -oE "(^192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)|(^172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)|(^10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])$)"
    grep -oE "(^127\.)|(^(0)?10\.)|(^172\.(0)?1[6-9]\.)|(^172\.(0)?2[0-9]\.)|(^172\.(0)?3[0-1]\.)|(^169\.254\.)|(^192\.168\.)"
}
Is_MAC_Address() {
    grep -oE "([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}"
}
Filter_This(){
    grep -E "$1"
}
MAC_to_IP() {

        # Convert MAC into IP address
        local FN="/etc/ethers"

        local RESULT=

        if [ $FIRMWARE -gt 38201 ];then

			# Check if YazDHCP installed
			FN="/jffs/addons/YazDHCP.d/.staticlist"							# v1.15
			if [ -f "$FN" ];then											# v1.15
				local IP_ADDR=$(grep -iE "$MAC" "$FN" | cut -d',' -f3 )		# v1.15
				if [ -n "$IP_ADDR" ];then									# v1.15
					FN="/jffs/addons/YazDHCP.d/.hostnames"					# v1.15
					HOST_NAME=$(grep "^$IP_ADDR" "$FN" | cut -d' ' -f2)		# v1.15
					RESULT=$HOST_NAME" "$IP_ADDR							# v1.15
				fi															# v1.15
			else															# v1.15
				# etc/ethers no longer exists/used
				# Instead /etc/dnsmasq.conf contains
				#         dhcp-host=00:22:B0:B5:BB:1A,10.88.8.254
				# v386+
				#         dhcp-host=48:45:20:D7:A6:22,set:48:45:20:D7:A6:22,HP-Envy13,192.168.1.38
				FN="/etc/dnsmasq.conf"
				#local ADDR_LIST=$(grep -i "$MAC" "$FN" | awk 'BEGIN {FS=","} {print $2}')
				[ -z "ADDR_LIST" ] && local ADDR_LIST=$(grep -i "$MAC" "$FN" | awk 'BEGIN {FS=","} {print $4}')               # v1.15
			fi
        else
            local ADDR_LIST=$(grep -i "$MAC" "$FN" | awk '{print $2}')
        fi

		if [ -z "$RESULT" ];then																		# v1.15
			if [ -n "$ADDR_LIST" ];then
				IP_RANGE=$ADDR_LIST
				IP_ADDR=$(grep   -iE "$IP_RANGE" $FN | awk 'BEGIN {FS=","} {print $4}')                 # v1.15
				HOST_NAME=$(grep -iE "$IP_RANGE" $FN | awk 'BEGIN {FS=","} {print $3}')                 # v1.15
				RESULT=$HOST_NAME" "$IP_ADDR
			else
				ADDR_LIST="$(arp -a | awk '{print $2","$4","$1}' | tr -d '()' | grep -iF "$MAC")"       # v1.15
				if [ -n "$ADDR_LIST" ];then                                                             # v1.15
					IP_ADDR=$(echo "$ADDR_LIST" | awk 'BEGIN {FS=","} {print $1}')                      # v1.15
					HOST_NAME=$(echo "$ADDR_LIST" | awk 'BEGIN {FS=","} {print $3}')                    # v1.15
					RESULT=$HOST_NAME" "$IP_ADDR
				else
					RESULT="***ERROR MAC Address not on LAN ("$FN"): '"$2"'"
				fi
			fi
		fi

        echo "$RESULT"
}
Convert_1024KMG() {

    local NUM=$(echo "$1" | tr [a-z] [A-Z])

    if [ ! -z "$(echo $NUM | grep -oE "B|K|KB|M|MB|G|GB")" ];then
        case "$(echo $NUM | grep -oE "B|K|KB|M|MB|G|GB")" in
            M|MB)
                local NUM=$(echo "$NUM" | tr -d 'MB')
                local NUM=$((NUM*1024*1024))
                ;;
            G|GB)
                local NUM=$(echo "$NUM" | tr -d "GB")
                # local NUM=$((NUM*1024*1024*1024))
                local NUM=$(expr "$NUM" \* "1024" \* "1024" \* "1024")
                ;;
            K|KB)
                local NUM=$(echo "$NUM" | tr -d "KB")
                local NUM=$((NUM*1024))
                ;;
            B)
                local NUM=$(echo "$NUM" | tr -d "B")
                ;;
        esac
    else
        NUM=$(echo "$NUM" | tr -dc '0-9')
    fi

    echo $NUM
}
Size_Human() {

    local SIZE=$1
    if [ -z "$SIZE" ];then
        echo "N/A"
        return 1
    fi
    #echo $(echo $SIZE | awk '{ suffix=" KMGT"; for(i=1; $1>1024 && i < length(suffix); i++) $1/=1024; print int($1) substr(suffix, i, 1), $3; }')

    # if [ $SIZE -gt $((1024*1024*1024*1024)) ];then                                        # 1,099,511,627,776
        # printf "%2.2f TB\n" $(echo $SIZE | awk '{$1=$1/(1024^4); print $1;}')
    # else
        if [ $SIZE -gt $((1024*1024*1024)) ];then                                       # 1,073,741,824
            printf "%2.2f GB\n" $(echo $SIZE | awk '{$1=$1/(1024^3); print $1;}')
        else
            if [ $SIZE -gt $((1024*1024)) ];then                                        # 1,048,576
                printf "%2.2f MB\n" $(echo $SIZE | awk '{$1=$1/(1024^2);   print $1;}')
            else
                if [ $SIZE -gt $((1024)) ];then
                    printf "%2.2f KB\n" $(echo $SIZE | awk '{$1=$1/(1024);   print $1;}')
                else
                    printf "%d Bytes\n" $SIZE
                fi
            fi
        fi
    # fi

    return 0
}
Backup_DB() {

    local DB=$1

    local DBNAME=$(basename "$DB")

    local DB_DIR=${DBNAME%.*}

    local NOW=$(date +"%Y%m%d-%H%M%S")    # current date and time

    echo -en $cBRED >&2

    mkdir -p $BACKUP_DIR//$DB_DIR
    cp -p $DB $BACKUP_DIR//$DB_DIR/$DBNAME-Backup-$NOW
    RC=$?
    if [ $RC -eq 0 ];then
        echo -en $cBGRE >&2
        Say "'"$DB"' backup completed successfully to '"$BACKUP_DIR/$DB_DIR/$DBNAME-Backup-$NOW"'"	#v1.14
    else
        echo -e "\a"
        Say "***ERROR '"$DB"' backup FAILED!"
    fi

    return $RC

    echo -en $cRESET >&2

}
#########################################################Main#############################################
Main() { true; }            # Syntax that is Atom Shellchecker compatible!

ANSIColours

# v384.13+ NVRAM variable 'lan_hostname' supersedes 'computer_name'
[ -n "$(nvram get computer_name)" ] && MYROUTER=$(nvram get computer_name) || MYROUTER=$(nvram get lan_hostname)


FIRMWARE=$(echo $(nvram get buildno) | awk 'BEGIN { FS = "." } {printf("%03d%02d",$1,$2)}')

# Need assistance ?
if [ "$1" == "-h" ] || [ "$1" == "help" ];then
    echo -e $cBWHT
    ShowHelp
    echo -e $cRESET
    exit 0
fi

SQL_DB_DESC="Traffic Analyzer"
SQL_TABLE="traffic"
SQL_DATABASE=


# v384.11 now includes '/usr/sbin/sqlite3'              # v1.11
if [ -z "$(which sqlite3)" ];then
    Chk_Entware                'sqlite3'  || { echo -e $cBRED"\a\n\t\t***ERROR*** Entware" $ENTWARE_UTILITY "not available\n"$cRESET;exit 99; }
fi

TITLE=$SQL_DB_DESC" starting....."

FILTER_INUSE=
CMDNOFILTER=                                        # Use the default URL list
MODE="AND"                                          # v1.03 Default selection criteria 'AND' between filters
WHERE=                                              # v1.03 SQL WHERE clause
SEND_EMAIL=                                         # Don't send report via email
CMDNOSCRIPT=                                        # v1.03 Execute this script after SQL SELECT
SORTBY="time"                                       # Default sort column
SORTBY_DESC=                                        # Implied!
COLORTIME=$cBGRE                                    # Highlight Default sort column 'time'
COLORMAC="$cBCYA"
COLORIP="$cBCYA"
COLORCAT="$cBCYA"
COLORAPP="$cBCYA"
COLORTX="$cBCYA"
COLORRX="$cBCYA"
BACKUP_DIR="/opt/var"                               # v1.12 Default backup directory - i.e. Entware or can be overidded by commandline

USE_TODAYS_DATE=1                                   # v1.08
USE_CURRENT_HOUR=1                                  # v1.08
SHOWSQL=0                                           # v1.13 Debug i.e. show SQL query

# Check options
while [ $# -gt 0 ]; do    # Until you run out of parameters . . .       # v1.07
  case "$1" in
    mode=*)
            OPT=$(echo "$1" | sed -n "s/^.*mode=//p" | awk '{print $1}')
            case $OPT in
                "")         MODE=OR;;               # Override the default; 'mode=' is a shortcut!
                or|OR)      MODE=OR;;
                and|AND)    MODE=AND;;
                *)  echo -e $cBRED"\a\n\t\t***ERROR INVALID mode '$1'\n"$cRESET
                    exit 99
                    ;;
            esac
            echo $WHERE
            [ -n "$FILTER_INUSE" ] && { echo -e $cBRED"\a\n\t\t***ERROR '$1' MUST precede filter specification '$FILTER_INUSE'\n"$cRESET; exit 99;}
            ;;
    noscript)
            CMDNOSCRIPT="NoScript"
            ;;
    showsql)                                # v1.13
            CMDSHOWSQL="ShowSQL"
            SHOWSQL=1
            ;;
    count)
            CMDCOUNT="CountONLY"
            CMDCOUNT_DESC=$cBYEL"***Summary only;"$cRESET
            ;;
    nodisplay)                              # v1.12
            CMDNODISPLAY="NoDISPLAY"
            CMDNODISPLAY_DESC=$cBYEL"***No Display;"$cRESET
            ;;
    sqldb=*)                                    # Override default database
            SQL_DATABASE=$(echo "$1" | sed -n "s/^.*sqldb=//p" | awk '{print $1}')
            ;;
    email)
            SEND_EMAIL="SendEmail"
            MAILFILE="/tmp/TrafficAnalyzer.txt"
            EMAILACTION=" > "$MAILFILE
            EMAIL_DESC="E-mailing results,"
            echo -e > $MAILFILE
            ;;
    date=*)
            USE_TODAYS_DATE=0                               # v1.08

            DATE_LIST="$(echo "$1" | sed -n "s/^.*date=//p" | awk '{print $1}' | tr ',' ' ')"

            DATE_LIST="$(echo "$@" | sed -n "s/^.*date=//p" | awk '{print $1}' | tr ',' ' ')"

            if [ -n "$DATE_LIST" ];then                 # v1.08
                DATE_FILTER=            # Used for Display info
                DATE_CNT=0
                [ -z "$FILTER_INUSE" ] && FILTER_DESC="by Date" || FILTER_DESC=$FILTER_DESC", "$MODE" by Date"

                DATE_SQL=               # v1.04 SQL statement for multiple 'DATE match'
                for DATE in $DATE_LIST
                    do
                        # SQL format is YYYY-MM-DD so change YYYY/MM/DD ->YYYY-MM-DD
                        DATE=$(echo "$DATE" | tr '/' '-')
                        [ $DATE_CNT -eq 0 ] && DATE_FILTER=$DATE_FILTER""$DATE || DATE_FILTER=$DATE_FILTER"|"$DATE
                        DATE_CNT=$((DATE_CNT+1))
                        [ -z "$DATE_SQL" ] && DATE_SQL=$DATE_SQL"(time LIKE '"$DATE"%'" || DATE_SQL=$DATE_SQL" OR time LIKE '"$DATE"%'"
                    done
                [ -z "$FILTER_INUSE" ] && FILTER_INUSE=$DATE_FILTER || FILTER_INUSE=$FILTER_INUSE"|"$DATE_FILTER

                [ -z "$WHERE" ] && WHERE="WHERE ("$DATE_SQL")" || WHERE=$WHERE" "$MODE" "$DATE_SQL")"   # v1.04
            fi
            ;;
    time=*)
            USE_CURRENT_HOUR=0                              # v1.08

            TIME_LIST="$(echo "$1" | sed -n "s/^.*time=//p" | awk '{print $1}' | tr ',' ' ')"

            if [ -n "$TIME_LIST" ];then                 # v1.08
                TIME_FILTER=            # Used for Display info
                TIME_CNT=0
                [ -z "$FILTER_INUSE" ] && FILTER_DESC="by Time" || FILTER_DESC=$FILTER_DESC", "$MODE" by Time"

                TIME_SQL=               # v1.04 SQL statement for multiple 'TIME match'
                for TIME in $TIME_LIST
                    do
                        # Minimum must be 'nn' or 'HH:' or 'HH:MM' format                   # v1.07
                        # NOTE 'time=10' will match anywhere e.g. '10:01:02' (HH:) as expected but also '03:10:59' (MM:)
                        case "${#TIME}" in
                            2)  [ $(echo "$TIME" | grep -oE "^([0-1][0-9])|^(2[0-3])$") ]               || { echo -e $cBRED"\a\n\t\t***ERROR time='$TIME' (HH format) invalid\n"$cRESET;   exit 55; } ;;
                            3)  [ $(echo "$TIME" | grep -oE "^([0-1][0-9])|^(2[0-3])(:)?") ]            || { echo -e $cBRED"\a\n\t\t***ERROR time='$TIME' (HH: format) invalid\n"$cRESET;  exit 66; } ;;
                            5)  [ $(echo "$TIME" | grep -oE "^([0-1][0-9])|^(2[0-3]):[0-5][0-9]$") ]    || { echo -e $cBRED"\a\n\t\t***ERROR time='$TIME' (HH:MM format) invalid\n"$cRESET;exit 77; } ;;
                            *)  { echo -e $cBRED"\a\n\t\tSQL time='$TIME' invalid format (HH:MM:SS is deemed illogical for SQL requests)\n"$cRESET;exit 99; };;
                        esac

                        [ $TIME_CNT -eq 0 ] && TIME_FILTER=$TIME_FILTER""$TIME || TIME_FILTER=$TIME_FILTER"|"$TIME
                        TIME_CNT=$((TIME_CNT+1))
                        [ -z "$TIME_SQL" ] && TIME_SQL=$TIME_SQL"(time LIKE '% "$TIME"%'" || TIME_SQL=$TIME_SQL" OR time LIKE '% "$TIME"%'"
                    done
                [ -z "$FILTER_INUSE" ] && FILTER_INUSE=$TIME_FILTER || FILTER_INUSE=$FILTER_INUSE"|"$TIME_FILTER

                [ -z "$WHERE" ] && WHERE="WHERE ("$TIME_SQL")" || WHERE=$WHERE" "$MODE" "$TIME_SQL")"   # v1.04
            fi
            ;;
    mac=*)                              # v1.12
            # Whilst easier to filter on Hostname/IP, explicitly filter on MAC address
            CMDMAC=$(echo "$1" | sed -n "s/^.*mac=//p" | awk '{print $1}' | tr ',' ' ')
            MAC_LIST=$CMDMAC
            MAC_FILTER=             # Used for Display info
            MAC_CNT=0
            [ -z "$FILTER_INUSE" ] && FILTER_DESC="by MAC" || FILTER_DESC=$FILTER_DESC", "$MODE" by MAC"

            MAC_SQL=                # v1.04 SQL statement for multiple 'MAC match'



            LAN_MACS=$(echo "$LAN_MACS" | sed 's/^ //p')
            LAN_MACS=$(echo "$LAN_MACS" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')   # Remove duplicates

            for MAC in $MAC_LIST
                    do
                        if [ -n "$(echo "$MAC" | Is_MAC_Address )" ];then
                            [ $MAC_CNT -eq 0 ] && MAC_FILTER=$MAC_FILTER""$MAC || MAC_FILTER=$MAC_FILTER"|"$MAC
                            MAC_CNT=$((MAC_CNT+1))
                            [ -z "$MAC_SQL" ] && MAC_SQL=$MAC_SQL"(mac LIKE '"$MAC"%'" || MAC_SQL=$MAC_SQL" OR mac LIKE '"$MAC"%'"
                        else
                            echo -e $cBRED"\a\n\t\t***ERROR Invalid MAC address '"$MAC"' in 'mac="$CMDMAC"' filter\n"$cRESET
                            exit 99
                        fi
                    done

            [ -z "$FILTER_INUSE" ] && FILTER_INUSE=$MAC_FILTER || FILTER_INUSE=$FILTER_INUSE"|"$MAC_FILTER

            [ -z "$WHERE" ] && WHERE="WHERE ("$MAC_SQL")" || WHERE=$WHERE" "$MODE" "$MAC_SQL")"
            ;;
    ip=*)
            # If Hostname/IP then filter on MAC address
            CMDIP=$(echo "$1" | sed -n "s/^.*ip=//p" | awk '{print $1}' | tr ',' ' ')

            GROUP_FOUND=0
            IP_GROUP_LIST=$CMDIP
            while true;do                                       # Iterate to expand any Groups within a Group
                for ITEM in $IP_GROUP_LIST
                    do
                        if [ -z "$(echo "$ITEM" | Is_Private_IPv4 )" ];then
                            # Check for group names, and expand as necessary
                            #   e.g. '192.168.1.30,192.168.1.50-192.168.1.54' -> '192.168.1.30 192.168.1.50 192.168.1.51 192.168.1.52 192.168.1.53 192.168.1.54'
                            if [ -f "/jffs/configs/IPGroups" ];then     # '/jffs/configs/IPGroups' two columns
                                                                        # ID xxx.xxx.xxx.xxx[[,xxx.xxx.xxx.xxx][-xxx.xxx.xxx.xxx]
                                GROUP_IP=$(grep -iwE -m 1 "^$ITEM" /jffs/configs/IPGroups | awk '{$1=""; print $0}')
                                if [ -n "$GROUP_IP" ];then
                                    GROUP_FOUND=1
                                    # Expand the list of IPs as necessary
                                    #   e.g. '192.168.1.30,192.168.1.50-192.168.1.54' -> '192.168.1.30 192.168.1.50 192.168.1.51 192.168.1.52 192.168.1.53 192.168.1.54'
                                    GROUP_IP=$(echo $GROUP_IP | tr ',' ' ')         # CSVs ?
                                    GROUP_IP=$(echo $GROUP_IP | tr ':' '-')         # Alternative range spec xxx.xxx.xxx.xxx:xxx.xxx.xxx.xxx
                                else
                                    # Perform lookup
                                    GROUP_IP=$(nslookup "$ITEM" | grep -woE '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk 'NR>2')
                                    if [ -z "$GROUP_IP" ];then
                                        echo -e $cBRED"\a\n\t\t***ERROR Hostname '$1' INVALID\n"$cRESET
                                        exit 99
                                    fi
                                fi
                            else
                                GROUP_IP=$ITEM
                            fi

                            # Expand any ranges - allow Hostnames e.g. LIFX-Table_light to pass through
                            if [ -n "$(echo "$GROUP_IP" | grep "-")" ];then     # xxx-yyy range ?
                                GROUP_IP="$(ExpandIPRange "$GROUP_IP")"
                                RC=$?                                                   # Should really check
                            fi
                            [ -n "$GROUP_IP" ] && LAN_IPS=$LAN_IPS" "$GROUP_IP
                        else
                            LAN_IPS=$LAN_IPS" "$ITEM
                        fi
                    done

                    if [ $GROUP_FOUND -eq 0 ];then
                        break
                    fi

                    IP_GROUP_LIST=$LAN_IPS          # Keep expanding
                    LAN_IPS=
                    GROUP_FOUND=0
            done

            LAN_IPS=$(echo "$LAN_IPS" | sed 's/^ //p')
            LAN_IPS=$(echo "$LAN_IPS" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}') # Remove duplicates

            IP_FILTER=              # Used for Display info
            IP_CNT=0
            [ -z "$FILTER_INUSE" ] && FILTER_DESC="by IP" || FILTER_DESC=$FILTER_DESC", "$MODE" by IP"

            MAC_SQL=                # v1.04 SQL statement for multiple 'MAC match'
            for IP in $LAN_IPS
                do
                    # Convert IP to MAC
                    XIP=$(echo "$IP" | sed 's/\./\\\./g')
                    MAC=$(grep -i "${XIP}$" /etc/dnsmasq.conf | awk 'BEGIN {FS=","} {print $1}' | sed -n "s/^dhcp-host=//p")
                    [ $IP_CNT -eq 0 ] && IP_FILTER=$IP_FILTER""$IP || IP_FILTER=$IP_FILTER"|"$IP
                    IP_CNT=$((IP_CNT+1))
                    [ -z "$MAC_SQL" ] && MAC_SQL=$MAC_SQL"(mac LIKE '"$MAC"%'" || MAC_SQL=$MAC_SQL" OR mac LIKE '"$MAC"%'"
                done

            [ -z "$FILTER_INUSE" ] && FILTER_INUSE=$IP_FILTER || FILTER_INUSE=$FILTER_INUSE"|"$IP_FILTER

            [ -z "$WHERE" ] && WHERE="WHERE ("$MAC_SQL")" || WHERE=$WHERE" "$MODE" "$MAC_SQL")" # v1.04
            ;;
    cat=*)
            CAT_LIST="$(echo "$1" | sed -n "s/^.*cat=//p" | awk '{print $1}' | tr ',' ' ')"

            CAT_FILTER=             # Used for Display info
            CAT_CNT=0
            [ -z "$FILTER_INUSE" ] && FILTER_DESC="by Category" || FILTER_DESC=$FILTER_DESC", "$MODE" by Category"

            CAT_SQL=                # v1.04 SQL statement for multiple 'Category Name match'
            for CAT in $CAT_LIST
                do
                    [ $CAT_CNT -eq 0 ] && CAT_FILTER=$CAT_FILTER""$CAT || CAT_FILTER=$CAT_FILTER"|"$CAT
                    CAT_CNT=$((CAT_CNT+1))
                    [ -z "$CAT_SQL" ] && CAT_SQL=$CAT_SQL"(cat_name LIKE '%"$CAT"%'" || CAT_SQL=$CAT_SQL" OR cat_name LIKE '%"$CAT"%'"
                done
            [ -z "$FILTER_INUSE" ] && FILTER_INUSE=$CAT_FILTER || FILTER_INUSE=$FILTER_INUSE"|"$CAT_FILTER

            [ -z "$WHERE" ] && WHERE="WHERE ("$CAT_SQL")" || WHERE=$WHERE" "$MODE" "$CAT_SQL")"     # v1.04
            ;;
    app=*)
            APP_LIST="$(echo "$1" | sed -n "s/^.*app=//p" | awk '{print $1}' | tr ',' ' ')"


            APP_FILTER=             # Used for Display info
            APP_CNT=0
            [ -z "$FILTER_INUSE" ] && FILTER_DESC="by Application" || FILTER_DESC=$FILTER_DESC", "$MODE" by Application"

            APP_SQL=                # v1.04 SQL statement for multiple 'Application Name match'
            for APP in $APP_LIST
                do
                    [ $APP_CNT -eq 0 ] && APP_FILTER=$APP_FILTER""$APP || APP_FILTER=$APP_FILTER"|"$APP
                    APP_CNT=$((APP_CNT+1))
                    [ -z "$APP_SQL" ] && APP_SQL=$APP_SQL"(app_name LIKE '%"$APP"%'" || APP_SQL=$APP_SQL" OR app_name LIKE '%"$APP"%'"
                done
            [ -z "$FILTER_INUSE" ] && FILTER_INUSE=$APP_FILTER || FILTER_INUSE=$FILTER_INUSE"|"$APP_FILTER

            [ -z "$WHERE" ] && WHERE="WHERE ("$APP_SQL")" || WHERE=$WHERE" "$MODE" "$APP_SQL")"     # v1.04
            ;;
    nofilter)
            CMDNOFILTER="NoFilter"
            ;;
    backup|backup=*)                            # v1.12
            if [ "$1" = "backup" ];then
                CMDBACKUP="Backup"              # Use default '/opt/var/' Entware
            else
                CMDBACKUP="$(echo "$1" | sed -n "s/^.*backup=//p" | awk '{print $1}')"
                if [ "$CMDBACKUP" = "/tmp" ] || [ ! -d "$CMDBACKUP" ];then
                    echo -e $cBRED"\a\n\t***ERROR Backup location '"$1"' INVALID. e.g. use a permanent disk e.g. '/mnt/xxxx' but NOT simply '/tmp' or '/tmp/'\n"$cRESET
                    exit 99
                else
                    BACKUP_DIR=$CMDBACKUP
                    CMDBACKUP="Backup"
                fi
            fi
			;;
    purgeallreset)
            CMDPURGEALLRESET="PurgeAllReset"
            ;;
    noansii)
            CMDNOANSII="NoANSII"
            ;;
    noformat)
            CMDNOFORMAT="NoFormatNumbers"                           # v1.09
            ;;
    sortby=*)
            CMDSORTBY="$(echo "$1" | sed -n "s/^.*sortby=//p" | awk '{print $1}' | tr ',' ' ')"
            case $CMDSORTBY in
                time)   SORTBY="time";;
                mac)    SORTBY="mac";SORTBY_DESC="${cBGRE}Sorted by 'mac';";COLORTIME=$cBCYA;COLORMAC=$cBGRE;;
                cat)    SORTBY="cat_name";SORTBY_DESC="${cBGRE}Sorted by 'cat';";COLORTIME=$cBCYA;COLORCAT=$cBGRE;;
                app)    SORTBY="app_name";SORTBY_DESC="${cBGRE}Sorted by 'app';";COLORTIME=$cBCYA;COLORAPP=$cBGRE;;
                # Rx and Tx are from the router's perspective so appear to be reversed!!!!
                tx)     SORTBY="tx";SORTBY_DESC="${cBGRE}Sorted by 'Tx';";COLORTIME=$cBCYA;COLORRX=$cBGRE;;  # LAN->WAN
                rx)     SORTBY="rx";SORTBY_DESC="${cBGRE}Sorted by 'Rx';";COLORTIME=$cBCYA;COLORTX=$cBGRE;;  # WAN->LAN
                ip)     UNIXSORT="| sort -k 7";COLORTIME=$cBCYA;COLORIP=$cBGRE;;
                *)
                        echo -e $cBRED"\a\n\t***ERROR Sort column '"$1" INVALID '(time, mac, cat, app, tx, rx, ip)'\n"$cRESET
                        exit 99
                ;;
            esac
            ;;
    trimdb|trimdb=*)
            if [ "$1" == "trimdb" ] || [ "$1" == "trimdb=auto" ];then
                CMDTRIMDB="$1"
                TRIMDB=30720                    # Use ASUS recommended 30M maximum aka 30720KB
            else
                CMDTRIMDB=$(echo "$1" | sed -n "s/^.*trimdb=//p" | awk '{print $1}' | tr ',' ' ' | tr 'a-z' 'A-Z')
                # Asus recommend 30MB (30720) to be the max size.
                # [URL="https://www.snbforums.com/threads/corrupt-config.55569/#post-476775"]Corrupt Config[/URL]
                        if [ -z "$(echo "$CMDTRIMDB" | tr -dc '0-9')" ] || [ "$(echo "$CMDTRIMDB" | tr -dc '0-9')" -eq 0 ];then
                            echo -e $cBRED"\a\n\t***ERROR Trim SQL Database size '$1' cannot be 0/NULL\n"$cRESET
                            exit 99
                        else
                            TRIMDB=$(Convert_1024KMG "$CMDTRIMDB")
                            if [ $TRIMDB -gt 31457280  ];then
                                echo -e $cBRED"\a\n\t***ERROR Trim $SQL_DB_DESC size '$1' must be <=30M) \n"$cRESET
                                exit 99
                            fi
                            TRIMDB=$((TRIMDB/1024))             # Bytes back into KB as required by ASUS utility
                        fi
            fi
            # Check existing size of SQL database
            # Find appropriate database '/jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db'
            if [ -z $SQL_DATABASE ];then
                SQL_DATABASE="$(find /jffs/.sys/ -name TrafficAnalyzer.db)"
                if [ $(find /jffs/.sys -name TrafficAnalyzer.db | wc -l) -ne 1 ];then
                    if [ $(find /jffs/.sys -name TrafficAnalyzer.db | wc -l) -gt 1 ];then
                        echo -e $cBRED"\a\n\t\t***ERROR Multiple $SQL_DB_DESC databases '"$SQL_DATABASE"'found??!!\n"$cRESET
                        exit 99
                    fi
                fi
            fi

            # Validate $SQL_DB_DESC database
            if [ ! -f $SQL_DATABASE ];then
                echo -e $cBRED"\a\n\t\t***ERROR $SQL_DB_DESC database '"$SQL_DATABASE"' NOT found!\n"$cRESET
                exit 98
            fi
            SQLDB_SIZE="$(ls -l "$SQL_DATABASE" | awk '{print $5}')"
            if [ $((SQLDB_SIZE/1024)) -le $TRIMDB ];then
                echo -e $cBRED"\a\n\t\t***ERROR $SQL_DB_DESC database size '"$(Size_Human "$((SQLDB_SIZE))")"' already trimmed!\n"$cRESET
                exit 98
            fi
            ;;
    report=*)                               # v1.12
                REPORT_CSV=$(echo "$1" | sed -n "s/^.*report=//p" | awk '{print $1}')
                CMDREPORT="CreateCSV"
                ;;
    *)
            echo -e $cBRED"\a\n\t***ERROR unrecognised directive '"$1"'\n"$cRESET
            exit 99
            ;;
  esac
  shift       # Check next set of parameters.
done

# Use Today's date and current hour?
if [ $USE_TODAYS_DATE  -eq 1 ];then                                 # v1.08 Default is Todays's date
    DATE_FILTER=$(date "+%F")
    DATE_SQL="(time LIKE '"$DATE_FILTER"%'"
    [ -z "$FILTER_INUSE" ] && FILTER_DESC="by Today" || FILTER_DESC=$FILTER_DESC", "$MODE" by Today"
    [ -z "$WHERE" ] && WHERE="WHERE ("$DATE_SQL")" || WHERE=$WHERE" "$MODE" "$DATE_SQL")"
    [ -z "$FILTER_INUSE" ] && FILTER_INUSE=$DATE_FILTER || FILTER_INUSE=$FILTER_INUSE"|"$DATE_FILTER
fi
if [ $USE_CURRENT_HOUR -eq 1 ];then                                 # v1.08 Default is current hour
    TIME_FILTER=$(date "+%H")":"
    TIME_SQL="(time LIKE '% "$TIME_FILTER"%'"

    [ -z "$FILTER_INUSE" ] && FILTER_DESC="by current hour" || FILTER_DESC=$FILTER_DESC", "$MODE" by current hour"
    [ -z "$WHERE" ] && WHERE="WHERE ("$TIME_SQL")" || WHERE=$WHERE" "$MODE" "$TIME_SQL")"
    [ -z "$FILTER_INUSE" ] && FILTER_INUSE=$TIME_FILTER || FILTER_INUSE=$FILTER_INUSE"|"$TIME_FILTER
fi

# Remember to terminate the SQL 'WHERE' clause!
[ -n "$WHERE" ] && WHERE=$WHERE")"


if [ -z "$CMDNOFILTER" ];then
    # Default filter
    if [ -z "$FILTER_INUSE" ];then
        DATE_FILTER=$(date "+%F")
        CAT_FILTER="Instant|Social|Online"
        FILTER_INUSE=$DATE_FILTER"|"$CAT_FILTER
        if [ "$MODE" == "AND" ];then                                            # v1.07
            FILTER_DESC="by today's Instant Messenger OR Social Networks OR Online Categories"
            WHERE="WHERE (time LIKE '"$(date "+%F")"%' AND (cat_name LIKE 'Instant%' OR cat_name LIKE 'Social%' OR cat_name LIKE 'Online%'))"
        else
            FILTER_DESC="by today's activity and any previous Instant Messenger OR Social Networks OR Online Categories"
            WHERE="WHERE (time LIKE '"$(date "+%F")"%' OR cat_name LIKE 'Instant%' OR cat_name LIKE 'Social%' OR cat_name LIKE 'Online%')"
        fi
    fi
else
    FILTER_DESC="ALL i.e. no filter"
    WHERE=
fi


# Find appropriate database '/jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db'
if [ -z $SQL_DATABASE ];then
    SQL_DATABASE="$(find /jffs/.sys/ -name TrafficAnalyzer.db)"
    if [ $(find /jffs/.sys -name TrafficAnalyzer.db | wc -l) -ne 1 ];then
        if [ $(find /jffs/.sys -name TrafficAnalyzer.db | wc -l) -gt 1 ];then
            echo -e $cBRED"\a\n\t\t***ERROR Multiple $SQL_DB_DESC databases '"$SQL_DATABASE"'found??!!\n"$cRESET
            exit 99
        fi
    fi
fi

# Validate $SQL_DB_DESC database
if [ ! -f $SQL_DATABASE ];then
    echo -e $cBRED"\a\n\t\t***ERROR $SQL_DB_DESC database '"$SQL_DATABASE"' NOT found!\n"$cRESET
    exit 98
fi

[ -n "$CMDNOANSII" ] && SQLDB_TITLE="'"$SQL_DATABASE"'"

# Should the backup be performed?
if [ -n "$CMDBACKUP" ];then     # v1.06
    echo -e
    Backup_DB "$SQL_DATABASE"
    echo -e $cRESET
    exit 0
fi

if [ -n "$CMDPURGEALLRESET" ];then
    echo -e

    echo -en ${cBRED}$aBLINK"\a\n\t\t\t****** WARNING are you sure? ******\n\n\t\t\t"${cRESET}$cBYEL"Enter "$cBWHT"ContinueOK!"$cBYEL" or press "$cBWHT"ENTER"$CBYEL" key to"$cBYEL" ABORT\n\t\t\t    >>"$cRESET
    read OPT
    if [ -n "$(echo "$OPT" | grep -oF "ContinueOK!")" ];then
        echo -e
        Backup_DB "$SQL_DATABASE"

        /usr/sbin/TrafficAnalyzer -z
        /usr/sbin/TrafficAnalyzer -e
        Say $VER "'"$SQL_DATABASE"' PURGED and RESET."
    else
        echo -e $cBWHT"\n\t\t\tRequest cancelled!"
    fi
    echo -e $cRESET
    exit 0
fi

# Not sure of this i.e. 13MB file (13341KB) so attempt to trim it to 12MB (12288KB) and ends up ONLY 637KB!!! ???
#
#       ls -lh /jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db
#
#           -rw-rw-rw-    1 admin    root       13.0M Apr  2 11:00 /jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db
#
#       ./TrafficAnalyzer_Report.sh trimdb=12m
#
#           15:45:09 Resizing '/jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db' - this may take a while.....
#               + /usr/sbin/TrafficAnalyzer -d 12288
#               + /usr/sbin/TrafficAnalyzer -e
#           15:46:25 '/jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db' resizing request to 12288 completed.
#                    '/jffs/.sys/TrafficAnalyzer/TrafficAnalyzer.db' resized to 637.0K
#
#
if [ -n "$CMDTRIMDB" ];then
    echo -e
    DUMMY=$TRIMDB                               # Just a debug line...no doubt Atom Shellchecker will complain!!!
    if [ "$CMDTRIMDB" != "auto" ];then          # Assume interactive call rather than by cron
        echo -en ${cBRED}$aBLINK"\a\n\t\t\t****** WARNING are you sure? ******\n\n\t\t\t"${cRESET}$cBYEL"Enter "$cBWHT"ContinueOK!"$cBYEL" or press "$cBWHT"ENTER"$CBYEL" key to"$cBYEL" ABORT\n\t\t\t    >>"$cRESET
        read OPT
    else
        OPT="ContinueOK!"                       # Do not ask for confirmation e.g. by non-interactive cron
    fi
    if [ -n "$(echo "$OPT" | grep -oF "ContinueOK!")" ];then
        echo -e
        Backup_DB "$SQL_DATABASE"
        Say $(date  "+%T") "Resizing '"$SQL_DATABASE"' - this may take a while....."
        /usr/sbin/TrafficAnalyzer -d $TRIMDB >/dev/null             # Trim Size is in KB
        /usr/sbin/TrafficAnalyzer -e
        Say $(date  "+%T") "'"$SQL_DATABASE"' resizing request to" $TRIMDB "completed."
        SQLDB_SIZE="$(ls -lh "$SQL_DATABASE" | awk '{print $5}')"
        Say "'"$SQL_DATABASE"' resized to" $SQLDB_SIZE
    else
        echo -e $cBWHT"\n\t\t\tRequest cancelled!"
    fi
    echo -e $cRESET
    exit 0
fi

##################################################################Display#####################################################
clear

echo -e $cBWHT
Say $VER "$TITLE"$SQLDB_TITLE

# Hyperlink support is native under Xshell5/MobaXterm. (Xshell5 visually shows which text is URL clickable ;-)
# MobaXterm: CTRL+Click the URL (must be prefixed with 'http')
# PuTTY: https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/url-launching.html
#
# Prevent double spacing between report lines by changing font size
# MobaXTerm: CTRL+MouseScrollWheel
# PuTTY:     ClearType Andale Mono 9pt

echo -e $cBYEL"\tNOTE: Columns in "$cBWHT"white"${cRESET}$cBYEL" are eligible for filters; "$cBRED"red text"${cRESET}$cBYEL" indicates a match on the filters requested. (URLs are Xshell5/MobaXterm hyperlinks)"
[ -n "$CMDNOFILTER" ] && FILTER_INUSE=                          # v1.12
echo -e "\n\t"${CMDCOUNT_DESC}${SORTBY_DESC}${EMAIL_DESC}$cBMAG"Filter" $FILTER_DESC "==> '"$FILTER_INUSE"'"
[ -n "$REPORT_CSV" ] && echo -e "\n\t"$cBMAG"Report file (.csv format): '"$REPORT_CSV"'" $cRESET

if [ -z "$CMDNOSCRIPT" ];then

    # Rx and Tx appear to be reversed!!!! so the order of the titles shouldn't match the SQL column
    printf '\n%b%b%-12s%b%-12s%b%-11s%-9s%b%-18s%b%-16s%b%-15s%b%-33s%b%-29s\n\n' "$cBCYA" "$COLORRX" "Tx Bytes" "$COLORTX" "Rx Bytes" "$COLORTIME" "YYYY/MM/DD" "HH:MM:SS" "$COLORMAC" "MAC address" "$cBCYA" "Host Name" "$COLORIP" "IP address" "$COLORCAT" "Category" "$COLORAPP" "Application"
    [ -n "$CMDNODISPLAY" ] && echo -e $cRED"\t\t***No Display of records on screen requested***\n"  # v1.12
    echo -en $cRESET

    # v1.07 unused filters cannot be NULL
    [ -z "$DATE_FILTER" ] && DATE_FILTER="¬"
    [ -z "$TIME_FILTER" ] && TIME_FILTER="¬"
    [ -z "$IP_FILTER"   ] && IP_FILTER="¬"
    [ -z "$CAT_FILTER"  ] && CAT_FILTER="¬"
    [ -z "$APP_FILTER"  ] && APP_FILTER="¬"
    [ -z "$MAC_FILTER"  ] && MAC_FILTER="¬"

    RX_TOTAL=0
    TX_TOTAL=0

    RESULT_PAGECNT=0                                            # v1.08 No. records shown on screen
    RESULT_CNT=0                                                # v1.08 Total number of matching records

    StatusLine $CMDNOANSII"Update" ${cYBLU}$aBOLD"Processing '$SQL_DATABASE' database....please wait!"

    echo -en $cBRED                                             # Just in case SQL error e.g. 'Error: database is locked'

    [ "$CMDREPORT" = "CreateCSV" ] && rm $REPORT_CSV 2>/dev/null    # v1.12 Erase .csv report file

    # Display Summary count of matches  ONLY?
    if [ -n "$CMDCOUNT" ];then
        RESULT_CNT=$(sqlite3 $SQL_DATABASE "SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time,  count(*) FROM $SQL_TABLE $WHERE ORDER BY $SORTBY;"  | cut -d'|' -f2)
        #echo -e $CMDCOUNT_DESC
    else
        # Rather than loop thru' each record to create .csv, simply allow SQL to create the .csv - much faster!
        if [ "$CMDREPORT" = "CreateCSV" ] && [ "$CMDNODISPLAY" = "NoDISPLAY" ];then     # v1.12
            [ $SHOWSQL -eq 1 ] && echo -e "sqlite3 -csv $SQL_DATABASE SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, mac, cat_name, app_name, tx, rx FROM $SQL_TABLE $WHERE ORDER BY $SORTBY;\n"
            sqlite3 -csv $SQL_DATABASE "SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, mac, cat_name, app_name, tx, rx FROM $SQL_TABLE $WHERE ORDER BY $SORTBY;" > $REPORT_CSV
            [ $SHOWSQL -eq 1 ] && echo -e "sqlite3 $SQL_DATABASE SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, mac, cat_name, app_name, tx, rx, count(*) FROM $SQL_TABLE $WHERE ORDER BY $SORTBY;\n"    # v1.13
            RESULT_CNT=$(sqlite3 $SQL_DATABASE "SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, mac, cat_name, app_name, tx, rx, count(*) FROM $SQL_TABLE $WHERE ORDER BY $SORTBY;"   | cut -d'|' -f7)
            nvram set tmp_WH_TOTAL=$RESULT_CNT
        else
            [ $SHOWSQL -eq 1 ] && echo -e "sqlite3 $SQL_DATABASE SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, mac, cat_name, app_name, tx, rx FROM $SQL_TABLE $WHERE ORDER BY $SORTBY;\n"  # v1.13
            sqlite3 $SQL_DATABASE "SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, mac, cat_name, app_name, tx, rx FROM $SQL_TABLE $WHERE ORDER BY $SORTBY;" | while IFS= read -r LINE
                do

                    [ -z "$RECORD_CNT" ] && RECORD_CNT=0

                    DATE=${LINE:0:10}

                    TIME=${LINE:11:8}

                    MAC=${LINE:20:17}

                    DESC=$(MAC_to_IP "$MAC")
                    HOSTNAME=${DESC% *}                                 # First word (' ' delimiter)
                    IP=${DESC##* }                                      # Last word  (' ' delimiter)
                    if [ "${HOSTNAME:0:3}" == "***" ];then
                        HOSTNAME="n/a"
                        IP="n/a"
                    fi

                    CAT=$(echo $LINE | awk ' FS="|" {print $3}')

                    APP=$(echo $LINE | awk ' FS="|" {print $4}')

                    RX=$(echo $LINE | awk ' FS="|" {print $5}')

                    #TX=${LINE##*|}                                     # Last word ('|' delimiter)
                    TX=$(echo $LINE | awk ' FS="|" {print $6}')

                    # DEBUG_LINE=">"$LINE"<"
                    # DEBUG_FILTER_INUSE=">"$FILTER_INUSE"<"
                    # DEBUG_DATE=">"$DATE"<"
                    # DEBUG_FILTER_DATE=">"$DATE_FILTER"<"
                    # DEBUG_TIME=$TIME
                    # DEBUG_FILTER_TIME=">"$TIME_FILTER"<"
                    # DEBUG_MAC=$MAC
                    # DEBUG_FILTER_MAC=">"$MAC_FILTER"<"
                    # DEBUG_DESC=$DESC
                    # DEBUG_HOSTNAME=$HOSTNAME
                    # DEBUG_IP=$IP
                    # DEBUG_FILTER_IP=">"$IP_FILTER"<"
                    # DEBUG_CAT=$CAT
                    # DEBUG_FILTER_CAT=">"$CAT_FILTER"<"
                    # DEBUG_APP=$APP
                    # DEBUG_FILTER_APP=">"$APP_FILTER"<"

                    # Cosmetic highlighting! ;-)
                    if echo "$DATE" | grep -qE "$DATE_FILTER" ;then # Date filter match? # YYYY-MM-DD
                        COLOUR_DATE=$cBRED
                    else
                        COLOUR_DATE=$cRESET
                    fi

                    if echo "$TIME" | grep -qE "$TIME_FILTER" ;then             # Time filter match? # HH:MM:SS
                        COLOUR_TIME=$cBRED
                    else
                        COLOUR_TIME=$cRESET
                    fi

                    if echo "$MAC" | grep -qE "$MAC_FILTER" ;then           # v1.12
                        COLOUR_MAC=$cBRED
                    else
                        COLOUR_MAC=$cRESET
                    fi

                    if echo "$MAC" | grep -qE "$IP_FILTER" ;then            # MAC filter match?
                        COLOUR_IP=$cBRED
                    else
                        COLOUR_IP=$cRESET
                    fi

                    if echo "$CAT" | grep -qE "$CAT_FILTER" ;then   # CATEGORY filter match?
                        COLOUR_CAT=$cBRED
                    else
                        COLOUR_CAT=$cRESET
                    fi

                    if echo "$APP" | grep -qE "$APP_FILTER" ;then   # APPLICATION filter match?
                        COLOUR_APP=$cBRED
                    else
                        COLOUR_APP=$cRESET
                    fi

                    #
                    # SQL format is YYYY-MM-DD so convert to EU ->YYYY/MM/DD
                    DATE=$(echo "$DATE" | tr '-' '/')

                    # Rx and Tx are from the router's perspective so appear to be reversed!!!!
                    #
                    #   WTF!!! echo $((1191071409+2037987240))
                    #               -1065908647
                    #RX_TOTAL=$((RX_TOTAL+RX))              # LAN->WAN
                    #TX_TOTAL=$((TX_TOTAL+TX))              # WAN->LAN

                    # Use old-skool method - but slower :-(
                    RX_TOTAL=`expr "$RX_TOTAL" + "$RX"`         # LAN->WAN
                    TX_TOTAL=`expr "$TX_TOTAL" + "$TX"`         # WAN->LAN

                    RECORD_CNT=$((RECORD_CNT+1))

                    nvram set tmp_TA_TOTAL=$RECORD_CNT                          # Damn subshells VERY UGLY HACK :-(
                    nvram set tmp_RX_TOTAL=$RX_TOTAL                            # Damn subshells VERY UGLY HACK :-(
                    nvram set tmp_TX_TOTAL=$TX_TOTAL                            # Damn subshells VERY UGLY HACK :-(

                    if [ "$CMDNODISPLAY" != "NoDISPLAY" ];then                  # v1.12
                        printf '%b%-12d%-12d%b%-10s%b %-8s%b %-18s%b%-16s%b%-15s%b%-33s%b%-32s\n' "${cBBLU}$xERASE" "$RX" "$TX" "$COLOUR_DATE" "$DATE"  "$COLOUR_TIME" "$TIME" "$COLOUR_MAC" "$MAC" "$cBBLU" "$HOSTNAME" "$COLOUR_IP" "$IP" "$COLOUR_CAT" "$CAT" "$COLOUR_APP" "$APP" # v1.12
                    fi
                    if [ -n "$SEND_EMAIL" ];then
                        printf '%-13d %-14d %-10s %-8s %-18s %-17s %-16s %-32s %-32s\n' "$RX" "$TX" "$DATE"  "$TIME" "$MAC" "$HOSTNAME" "$IP" "$CAT" "$APP"  >>$MAILFILE
                    fi

                    # Slow...compared to 'sqlite3 -csv' invocation
                    if [ "$CMDREPORT" = "CreateCSV" ];then                      # v1.12
                        echo -e "\"$RX\",\"$TX\",\"$DATE $TIME\",\"$MAC\",\"$HOSTNAME\",\"$IP\",\"$CAT\",\"$APP\""  >>$REPORT_CSV
                    fi

                    # Experimental scrollable window Rows 10 to 20
                    #[ $RECORD_CNT -eq 20 ] && echo -en "\e[10;20r"

                    # Experimental non-scroll page output
                    #[ $RESULT_PAGECNT-eq 23 ] && { echo -en $(Goto "10" "1")$xERASEDOWN; RESULT_PAGECNT=0; }
                    echo -en $cRESET

                done
            fi

        # Rx and Tx are from the router's perspective so appear to be reversed!!!!
        RX_TOTAL=$(nvram get tmp_RX_TOTAL); nvram unset tmp_RX_TOTAL        # Damn subshells VERY UGLY HACK :-(
        TX_TOTAL=$(nvram get tmp_TX_TOTAL); nvram unset tmp_TX_TOTAL        # Damn subshells VERY UGLY HACK :-(

        # Print the RX and TX summary (Rx and Tx are from the router's perspective so appear to be reversed!!!!)
        printf '%b%-12s%-12s\n'   "${cBYEL}$xERASE" "-----------" "------------"

        [ -z $CMDNOFORMAT ] && printf '%b%-12s%-12s\n'   "${cBGRE}$xERASE" "$(Size_Human "$RX_TOTAL")" "$(Size_Human "$TX_TOTAL")" || \
                                 printf '%b%-12s%-12s\n'   "${cBGRE}$xERASE" ""$RX_TOTAL"" ""$TX_TOTAL""
        printf '%b%-12s%-12s\n\n' "${cBYEL}$xERASE" "===========" "============"

        if [ -n "$SEND_EMAIL" ];then
            printf '%-11s %-12s\n'  "-------------" "-------------" >>$MAILFILE
            printf '%-11s %-12s\n'  "$(Size_Human "$RX_TOTAL")" "$(Size_Human "$TX_TOTAL")" >>$MAILFILE
            printf '%-11s %-12s\n'  "=============" "=============" >>$MAILFILE
        fi

        if [ -n "$SEND_EMAIL" ];then
            echo -e $cBYEL
            StatusLine $CMDNOANSII"Update" ${cYBLU}$aBOLD"Preparing e-mail....please wait!"
            sleep 1
            SendMail $MAILFILE
            StatusLine $CMDNOANSII"Clear"
            #echo -e $cBGRE"\n\tEmail sent..."$MAILFILE     # SendMail() already issues message..but without filename
        fi

        RESULT_CNT=$(nvram get tmp_TA_TOTAL);nvram unset tmp_TA_TOTAL   # Damn subshells VERY UGLY HACK :-(
        [ -z "$RESULT_CNT" ] && RESULT_CNT=0

    fi

    # Summarise
    [ $RESULT_CNT -eq 0 ] && IND=$cBRED || IND=$cBGRE

    if [ -z "$CMDNOANSII" ];then
        if [ -n "$CMDCOUNT" ] || [ $RESULT_CNT -le 20 ];then                    # v1.09
            StatusLine $CMDNOANSII"NoFLASH" ${IND}$aREVERSE"Summary: Result count = "$RESULT_CNT" "
        else
            echo -e "\n"${cRESET}${cIND}$aREVERSE"Summary: Result count = "${RESULT_CNT}" "$aREVERSEr
        fi
    else
        echo -e "\n"${cRESET}${cIND}$aREVERSE"Summary: Result count = "${RESULT_CNT}" "$aREVERSEr
    fi
else
    echo -e $cBYEL
    if [ -z "$CMDCOUNT" ];then                                                  # v1.10
        if [ "$CMDREPORT" = "CreateCSV" ];then                                  # v1.12
            [ $SHOWSQL -eq 1 ] && echo -e "sqlite3 -header -csv $SQL_DATABASE SELECT * FROM $SQL_TABLE;\n"  # v1.13
            sqlite3 -header -csv $SQL_DATABASE "SELECT * FROM $SQL_TABLE;" > $REPORT_CSV    # Use '*' for raw table
        else
            # NOTE: Display/create the additional human-friendly timestamp!
            [ $SHOWSQL -eq 1 ] && echo -e "sqlite3 $SQL_DATABASE SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, timestamp, mac, cat_name, app_name, tx, rx FROM $SQL_TABLE $WHERE;\n"    # v1.13
            sqlite3 $SQL_DATABASE "SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, timestamp, mac, cat_name, app_name, tx, rx FROM $SQL_TABLE $WHERE;"
        fi
    fi
    [ $SHOWSQL -eq 1 ] && echo -e "sqlite3 $SQL_DATABASE SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, count(*) FROM $SQL_TABLE $WHERE;\n"  # v1.13
    SQL_TOTAL=$(sqlite3 $SQL_DATABASE "SELECT datetime(timestamp, 'unixepoch', 'localtime') AS time, count(*) FROM $SQL_TABLE $WHERE;" | cut -d'|' -f2)
    echo -e $cBGRE"\nTotal Records = "$SQL_TOTAL

fi

#       cat /proc/bw_dpi_conf
# v1.10 Moved to after summary report
if [ $(nvram get TM_EULA) -eq 0 ] || [ $(nvram get bwdpi_db_enable) -eq 0 ];then        # v1.09 Check TREND Micro EULA and Traffic Analyzer
    echo -e $cBRED"\a\n**Warning" $SQL_DB_DESC "NOT currently enabled\n"$cRESET     # v1.09
    #exit 97
fi

echo -e $cRESET


exit 0


