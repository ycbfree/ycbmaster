#!/bin/bash
#
# Copyright (c) 2018 YCB Project
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH YCB TEAM.
#
# The YCB team!

# Read Configuration file
configfile='./config.cfg'
configfile_secured='./secure-config.cfg'

if egrep -q -v '^#|^[^ ]*=[^;]*' "$configfile"; then
	egrep '^#|^[^ ]*=[^;&]*'  "$configfile" > "$configfile_secured"
	configfile="$configfile_secured"
fi
source "$configfile"

function _write_log()
{
	if [ "$debug" ==  "1" ]; then   
		`logger -s "$1" 2>> $logfile`
	else 
		tput setaf 6; echo "$1"; tput sgr0;
	fi
}

# Verificar ID pi
function check_current_user()
{
	_write_log "[] Checking user "

	if [ $UID != "$user_id" ]; then
		_write_log "[x] You need to be pi user ..."
		die
	else
		_write_log "[OK] PI user ..."
	fi	

}

# No finaliza
function die()
{	
	exit 1
}

# Check so
function check_so()
{
	sys_op=`uname -n`
	if [ "$sys_op" = "raspberrypi" ]; then
		_write_log "[OK] Raspberrypi running ..."	
	else
		_write_log "[x] Another Operating system found: $sys_op ..."
		die
	fi
}

# Check Internet
function check_lan()
{

	_write_log "[] Checking Connectivity ..."

	# Verificamos link
	verify_int=`sudo ethtool $int|grep "Link detected: yes"|awk '{print $3}'`

	if [ "$verify_int" == "yes" ]
	then
		_write_log "[OK] link $int ..."

	else
		echo "[ERROR] Ethernet interface is not connected ..."
		`ifconfig $int up` && check_lan
	fi

	# Verificamos ip
	get_ip=`ifconfig $int|grep inet|grep -v inet6|awk '{print $2}'` 	
	if [ "$get_ip" == "" ]
	then
		_write_log "[WARN] NO IP Addr" 
		evade_net
	else
		_write_log "[OK] IP Addr detected: $get_ip"
		ip_addr=$get_ip
		#evade_net #prueba de evade_net
	fi

	# Verificamos Gateway
	get_gateway=`/sbin/ip route | awk '/default/ { print $3 }'`
	if [ _detect_gateway == "" ]; then
		_write_log "[Error] No gateway detected"
		_write_log "[] Searching Gateway"
		evade_net
	else
		_write_log "[OK] Gateway detected: $get_gateway "
	#	_verifydns
	#	_verifyhttp
		#evade_net
	fi
}

function _detect_gateway()
{
	# Verificamos Gateway
	get_gateway=`/sbin/ip route | awk '/default/ { print $3 }'`
	if [ "$get_gateway" == "" ]; then
		return 0
	else
		return 1
	fi

}

function _evade_net()
{
	#`sudo ip addr flush dev $bridge`
	`sudo ip addr flush dev $int`
	`sudo ifconfig $int promisc`

	# captura arp
	_write_log "[] Evade Networking " 
	_write_log "[OK] Packet capturing on $int ..."
	`sudo timeout $timeout_tcpdump tcpdump -nnti eth0 arp -w $arp_pcap and '(src net (10 or 172.16/12 or 192.168/16) and dst net (10 or 172.16/12 or 192.168/16))'`

	# Analizamos el PCAP y extraimos las IP y mac
	regexReply='^.*Reply\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) is-at ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}),\s.*$'
	regexRequest='^.*Request who-has\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) tell ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}),\s.*'
	` > $ycb_works/ip_output.txt`
	tcpdump -n -r "$arp_pcap" | while read line; do  
	    #echo $line
	        if [[ $line =~ $regexReply ]] 
		then
			`echo "${BASH_REMATCH[1]};${BASH_REMATCH[2]}" >> $ycb_works/ip_output.txt`
	        elif [[ $line =~ $regexRequest ]] 
		then
			`echo "${BASH_REMATCH[1]};" >> $ycb_works/ip_output.txt`
			`echo "${BASH_REMATCH[2]};" >> $ycb_works/ip_output.txt`
		fi

	done
	echo `awk '{print $1}' $ycb_works/ip_output.txt |sort|uniq > $ycb_works/ip_detected.txt`
	
	# parsiamos IP
	detect_dns=0
	http_enable=0
	https_enable=0
	for ip in `cat $ycb_works/ip_detected.txt|grep -E '(([0-9]{1,3})\.){3}([0-9]{1,3}){1}' | grep -vE '25[6-9]|2[6-9][0-9]|[3-9][0-9][0-9]'`;do
		get_ip=`echo $ip|cut -d ";" -f "1"` 
		get_mac=`echo $ip|cut -d ";" -f "2"` 
		
		if [ $get_ip != "0.0.0.0" ]
		then
			oc1=`echo $get_ip|cut -d '.' -f 1`
			oc2=`echo $get_ip|cut -d '.' -f 2` 
			oc3=`echo $get_ip|cut -d '.' -f 3`
			oc4=`echo $get_ip|cut -d '.' -f 4`
			#echo "$get_ip"
			octToNmap="$oc1.$oc2.$oc3.0/24"
			if (( $oc4 > 5 )) && (( $oc4 <200 ))
			then
				## asignar ip temporal
				_write_log "Asignar $int $get_ip"
				`sudo ifconfig $int $get_ip`


				_write_log "[] Nmap For $octToNmap ..."
				## realizar nmap
				
				regexIP=".*\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
				arr=()
				IP=
				while read line
				do
					if [[ "$line" =~ ^Nmap ]]; then
						if [[ $line =~ $regexIP ]];  then
							IP=${BASH_REMATCH[1]}
							#echo $IP
							arr=(${arr[@]} $IP)

						fi
					fi		
				done < <(sudo nmap -sP $octToNmap)	
				my_array_length=${#arr[@]}
				#echo "array: "
				#echo $my_array_length
				START=5
				END=254
				`sudo ip addr flush dev $int`

				for i in $(eval echo "{$START..$END}")
				do
					ip_new="$oc1.$oc2.$oc3.$i"
					for(( i=0; i<${#arr[@]}; i++ )); do
						default=${arr[$i]}
						if [[ $ip_new == "$default" ]]; then
							#echo "$var present in the array"
							break 
						else
							# asignamo IP a interfaz $bridge
							#echo "asignar $int $ip_new"
							#echo "asignr gw $default"
							`sudo ifconfig $int up`
							`sudo ifconfig $int $ip_new`
							echo "[OK] IP Assigned: $ip_new"

							# Descubrimiento del default gw
							`sudo route add default gw $default`
							echo "[OK] DEFAULT GW: $default"
							return 1
						fi
					done
				done			
			fi	## end if > 9 && < 200
		fi
	done

	
            
 

		  
	
}

# funcion para detectar dns resolver en la red
function _verifydns()
{
	_write_log "[] Verify DNS ..." 

	get_domain=`host -t a $fqdn_check|grep address`
	get_timedout=`host -t a $fqdn_check|awk '{print $3 "" $4}'`

	if [[ $get_timedout == *"timedout"* ]]; then
		_write_log "[ERROR] Resolving $fqdn_check with dns server $dns_server "
		return 0
	else
		_write_log "[-] Resolving $fqdn_check with dns server $dns_server "
		_write_log "[OK] $get_domain"
		return 1
	fi
}

function _verifydns_detected()
{
	if [ -z "$1" ]; then
		_write_log "[ERROR] Please pass argument"
		die
	fi

	_write_log "[] Verify DNS ..." 

	get_domain=`host -t a $fqdn_check $1|grep address`
	get_timedout=`host -t a $fqdn_check $1|awk '{print $3 "" $4}'`

	if [[ $get_timedout == *"timedout"* ]]; then
		_write_log "[ERROR] Resolving $fqdn_check with dns server $dns_server "
		return 0
	else
		_write_log "[-] Resolving $fqdn_check with dns server $dns_server "
		_write_log "[OK] $get_domain"
		`echo "nameserver $1" | sudo tee /etc/resolv.conf` > /dev/null 2>&1
		return 1
	fi
}

function _verifyhttp()
{
	_write_log "[] Verify HTTP User Navigation "
	_write_log "[-] Probing HTTP $fqdn_check ..."

	status_code=$(curl --connect-timeout 5 --write-out %{http_code} --silent --output /dev/null $fqdn_check)

	if [[ "$status_code" -ne 200 ]] ; then
		_write_log "[ERORR] status code is $status_code"
	else
		_write_log "[OK] status code is $status_code"
		return 1
	fi
}

function _verifyhttps()
{
	_write_log "[] Verify HTTPs User Navigation "
	_write_log "[-] Probing HTTPs $fqdn_check ..."
	status_code=$(curl --connect-timeout 5 --write-out %{http_code} --silent --output /dev/null https://$fqdn_check)

	if [[ "$status_code" -ne 200 ]] ; then
		_write_log "[ERORR] status code is $status_code"
	else
		_write_log "[OK] status code is $status_code"
		return 1
	fi
}

# Funcion para verificar TOR
function _check_tor()
{
	_write_log "[-] Verify Tor is running "
	netstat_tor=`sudo netstat -ntlp|grep 9050|awk '{print $4}'`
	if [[ $netstat_tor == "127.0.0.1:9050"  ]]; then
		_write_log "[OK] Tor is running on port 9050"
	else
		_write_log "[] Starting tor ... "
		`sudo systemctl start tor`
	fi
}

function _test_tor()
{
	_write_log "[-] Enable Curl with tor"
	max_try=2
	get_curl=`curl --socks5-hostname 127.0.0.1:9050 --silent https://api.ipify.org/`
	get_ip_curl=`curl --silent curl https://api.ipify.org`
	if [[ "$get_curl" != "" ]]; then
		_write_log "[OK] Tor Circuit IP: $get_curl"
		_write_log "[OK] My Direct IP: $get_ip_curl"
	else
		_write_log "[OK] Error Tor Circuit IP"
	fi
}


# Funcion DNS Tunnelling
function _dns_tunneling()
{
	_write_log "[-] Enable DnsTunneling"
	get_proc_dns=`ps aux|grep -i iodine|grep -v grep|awk '{print $2}'`
	if [[ $get_proc_dns == "" ]]; then
		_write_log "[Error] Tunnel is Down, Up Now!"
		sleep 2
		`screen -dm bash -c "sudo iodine -f -P $pass_iodine $domain_iodine"`
	else
		_write_log "[OK] DNS Tunneling is UP"
	fi
}

function _test_dns_tunneling()
{
	_write_log "[-] Test DnsTunneling"
	get_proc_dns=`ps aux|grep -i iodine|grep -v grep|awk '{print $2}'`
	if [[ $get_proc_dns != "" ]]; then
		get_ip_tunnel=`ifconfig dns0|grep inet|awk '{print $2}'`
		curl_ip_dns=`ssh 10.0.1.1 "curl --silent ifconfig.me"`
		_write_log "[OK] DNS TUnneling IP Local: $get_ip_tunnel"
		_write_log "[OK] DNS Tunneling IP External: $curl_ip_dns"
	else
		_write_log "[ERROR] DNS Tunnel is Down"
	fi

}

# Funcion Proxy 
function _squid_proxy()
{
	_write_log "[OK] Enable Squid Proxy"
	get_proc_ssh=`sudo netstat -ntlp|grep 3128|awk '{print $4}'`
	curl_ip_squid=`curl -x http://127.0.0.1:3128 --silent ifconfig.me`
	get_int_dns=`ifconfig dns0|grep dns0|awk '{print $1}'`
	if [[ $get_proc_ssh == "127.0.0.1:3128"  ]]; then
		_write_log "[OK] Tunnel Squid is Up"
		_write_log "[OK] IP Tunnel $curl_ip_squid"
	else
		if [[ $get_int_dns == "" ]]; then
			_write_log "[ERROR] Please first starting tunnel with -i option"
			die
		else
			_write_log "[ERROR] Tunnel is Down, starting"
			sleep 2
			`screen -dm bash -c "ssh -f -N -T -L0.0.0.0:3128:127.0.0.1:3128 10.0.1.1 -o ConnectTimeout=10"`
			_write_log "[OK] Tunnel HTTP/s Proxy is Done!"
		fi
	fi
}

# Bajamos todo
function _stop_all()
{
	case "$1" in 
	tor)
		if [[ $netstat_tor == "127.0.0.1:9050"  ]]; then
			_write_log "[OK] Stop Tor"
			`sudo systemctl stop tor`
		else
			_write_log "[Error] Tor is not running"
		fi
		;;
	dnstunnel)
		_write_log "[OK] Stop DNS Tunneling"
		dns_tunnel=`ps aux|grep -i iodine|grep -v grep|awk '{print $2}'|xargs`
		if [ "$dns_tunnel" != "" ]; then
			`ps aux|grep -i iodine|grep -v grep|awk '{print $2}'|xargs sudo kill -9`
		fi
		;;
	squid)
		_write_log "[OK] Stop Squid Proxy"
		proxy_tunnel=`ps aux|grep -i 3128|grep -v grep|awk '{print $2}'|xargs`
		if [ "$proxy_tunnel" != "" ]; then
			`ps aux|grep -i 3128|grep -v grep|awk '{print $2}'|xargs kill -9`
		fi
		;;
	resolv)
		_write_log "[OK] Remove /etc/resolv.conf"
		`echo "" | sudo tee /etc/resolv.conf` > /dev/null 2>&1
		;;
	*) 
		_write_log "add an option to stop a service:"
		_write_log " tor"
		_write_log " squid"
		_write_log " resolv.conf"
		;;
	esac
}


# Verifiamos que las variables esten definidas
if [ -z "$TITLE" ]; then
	_write_log "[ERROR] Please set variable 'TITLE'";
	die
elif
   [ -z "$logfile" ]; then
	_write_log "[ERROR] Please set variable 'logfile'";
	die
elif
   [ -z "$ycb_works" ]; then
	_write_log "[ERROR] Please set variable 'ycb_works'";
	die
elif
   [ -z "$pass_iodine" ]; then
	_write_log "[ERROR] Please set variable 'pass_iodine'";
	die
elif
   [ -z "$domain_iodine" ]; then
	_write_log "[ERROR] Please set variable 'domain_iodine'";
	die
elif
   [ -z "$fqdn_check" ]; then
	_write_log "[ERROR] Please set variable 'fqdn_check'";
	die
elif
   [ -z "$arp_pcap" ]; then
	_write_log "[ERROR] Please set variable 'arp_pcap'";
	die
elif
   [ -z "$int" ]; then
	_write_log "[ERROR] Please set variable 'int'";
	die
elif
   [ -z "$debug" ]; then
	_write_log "[ERROR] Please set variable 'debug'";
	die
fi

# Main
usage() { 
echo $TITLE
echo "Usage: $0 [options]" &&
echo "  -l Verify LAN Connectivity Raspberrry [checklan()]" && 
echo "  -d [enable checkdns() module]" && 
echo "  -w [enable checkhttp() module]" && 
echo "  -q [enable checkhttps() module]" && 
echo "  -e [enable checkevade() module]" && 
echo "  -t [enable checktor() module]" && 
echo "  -u [enable testtor() module]" && 
echo "  -i [enable dnstunneling() module]" && 
echo "  -o [enable testdnstunneling() module]" && 
echo "  -s [verify dns resolver]" && 
echo "  -p [enable tunnel squid]" && 
echo "  -z [stop all tunneling]" && 
echo "  -h [help]"  && grep ".)\ #" $0; exit 0; }


[ $# -eq 0 ] && usage
while getopts ":hs:ldwqetuhiospz" arg; do
	case $arg in
	l)
		check_lan
		;;
	d) 
		_verifydns
		;;
	w)
		_verifyhttp
		;;
	q)
		_verifyhttps
		;;
	e)	
		_evade_net
		;;
	t)
		_check_tor
		;;
	u)
		_test_tor
		;;
	i)
		_dns_tunneling
		;;
	o)
		_test_dns_tunneling
		;;
	s) 
		_verifydns_detected $2
		;;	
	p) 
		_squid_proxy
		;;	
	z) 
		_stop_all $2
		;;	
	h|*)
		usage -l checklan
		exit 0
		;;
	esac
done

