#!/bin/sh
#
# WG-RC
#
# WireGuard client using Netifrc.
#

# exit when any command fails
set -T

echoexit() {
  # Print to stderr and exit
  printf "%s\n" "$@" 1>&2
  exit 1
}

# Checking dependencies:
whereis wg > /dev/null || echoexit "'wg' command not found."
whereis ip > /dev/null || echoexit "'ip' command not found."
whereis nft > /dev/null || echoexit "'nft' command not found."
whereis rc-service > /dev/null || echoexit "'rc-service' not found."

#
# Constants
#

# tmpfs
TMP_DIR="/tmp"

# no request user confirmation
NOINTERACT="0"

# format colors
ENDC="$(tput sgr0)"
GREEN="$(tput setaf 2)"
RED="$(tput setaf 1)"
CYAN="$(tput setaf 6)"
BOLD="$(tput bold)"
BGREEN="${BOLD}${GREEN}"
BRED="${BOLD}${RED}"
BCYAN="${BOLD}${CYAN}"

# config files
INIT_DIR="/etc/init.d"
CONF_DIR="/etc/conf.d"
WG_DIR="/etc/wireguard"
TMP_CONF="$TMP_DIR/wg-rc.conf"
NET_LO="$INIT_DIR/net.lo"
NET_CONF="$CONF_DIR/net"
DEFAULT_IP="10.5.0.2/32"

# verify if user has root privileges
verify_root() {
	if [ "$(id -u)" != "0" ]; then
		echo -e "This command requires administrative privileges."
		echo -e "Try '${BOLD}sudo nordvpn-rc <options>${ENDC}' or login as root."
		exit 1
	fi
}

# set wireguard interface in the config file
set_interface() {
	verify_root
	
	local config interface
	interface=$1

	# check the string provided by user
	if [[ "$interface" == "" ]]; then
		echo -e ""
		echo -e "Attempting to set ${RED}invalid${ENDC} interface."
		echo -e ""
		exit 1
	fi

	create_interface "$interface"
	configure_interface "$interface"
	create_wireguard_config "$interface"

	echo -e ""
	echo -e "${GREEN}Interface${ENDC} '${BGREEN}$interface${ENDC}' ${GREEN}configured.${ENDC}"
	echo -e ""
}

create_interface() {
	verify_root
	
	local interface net_if
	interface=$1
	net_if="$INIT_DIR/net.$interface"

	# check for existing net config file
	if [[ "$NOINTERACT" == "0" ]] && test -f "$net_if"; then
		echo -e ""
		echo -e "Interface init script '${BOLD}$net_if${ENDC}' already exists."
		echo -e ""
		read -p "$(echo -e "${BOLD}Do you want to override it?${ENDC} [${BGREEN}Yes${ENDC}/${BRED}No${ENDC}] ")" -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			echo -e ""
    			echo -e "Not doing anything."
			echo -e ""
			exit 0
		fi
	fi

	echo -e ""
	echo -e "Creating init script at '${BOLD}$net_if${ENDC}' ..."

	rm -rf $net_if 2>/dev/null
	ln -s $NET_LO $net_if

	# check for existing config file
	if ! test -f "$net_if" || [[ "$(realpath $net_if)" != "$NET_LO" ]]; then
		echo -e ""
		echo -e "${RED}Could not create init script at${ENDC} '${BRED}$net_if${ENDC}' ${RED}.${ENDC}"
		echo -e ""
		exit 1
	fi

	echo -e ""
	echo -e "${GREEN}Created init script at${ENDC} '${BGREEN}$net_if${ENDC}' ${GREEN}.${ENDC}"
}

configure_interface() {
	verify_root
	
	local interface wg_if_conf net_wg_pre net_config_pre net_content net_wg_found net_config_found
	interface=$1
	wg_if_conf="$WIREGUARD_DIR/$interface.conf"
	net_wg_pre="wireguard_$interface="
	net_config_pre="config_$interface="
	net_content=$(cat "$NET_CONF" 2>/dev/null)
	net_wg_found=$(printf %b "$net_content" | grep -c "^$net_wg_pre\$" 2>/dev/null)
	net_config_found=$(printf %b "$net_content" | grep -c "^$net_config_pre" 2>/dev/null)

	# check for existing net config file
	if [[ "$NOINTERACT" == "0" ]] && test -f "$NET_CONF" && (( $net_wg_found + $net_config_found > 0 )); then
		echo -e ""
		echo -e "Interface configuration at '${BOLD}$NET_CONF${ENDC}' already exists."
		echo -e ""
		read -p "$(echo -e "${BOLD}Do you want to override it?${ENDC} [${BGREEN}Yes${ENDC}/${BRED}No${ENDC}] ")" -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			echo -e ""
    			echo -e "Not doing anything."
			echo -e ""
			exit 0
		fi
	fi

	echo -e ""
	echo -e "Creating network configuration at '${BOLD}$NET_CONF${ENDC}' ..."
	
	local net_wg_ful net_config_full net_clear
	net_wg_ful="$net_wg_pre\"$wg_if_conf\""
	net_config_ful="$net_config_pre\"$DEFAULT_IP"
	net_clear=$(printf %b "$net_content" | grep -v "^$net_wg_pre\$" 2>/dev/null | grep -v "^$net_config_pre" 2>/dev/null)
	
	printf "$net_clear" > $NET_CONF
	printf "$net_wg_ful" >> $NET_CONF
	printf "$net_config_ful" >> $NET_CONF

	echo -e ""
	echo -e "${GREEN}Interface${ENDC} '${BGREEN}$interface${ENDC}' ${GREEN}configured as${ENDC} '${BGREEN}$DEFAULT_IP${ENDC}'${GREEN}.${ENDC}"
}

create_wireguard_config() {
	verify_root
	
	local interface wg_if_conf
	interface=$1
	wg_if_conf="$WIREGUARD_DIR/$interface.conf"

	# check for existing config file
	if [[ "$NOINTERACT" == "0" ]] && test -f "$wg_if_conf"; then
		echo -e ""
		echo -e "WireGuard config file '${BOLD}$wg_if_conf${ENDC}' already exists."
		echo -e ""
		read -p "$(echo -e "${BOLD}Do you want to override it?${ENDC} [${BGREEN}Yes${ENDC}/${BRED}No${ENDC}] ")" -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			echo -e ""
    			echo -e "Not doing anything."
			echo -e ""
			exit 0
		fi
	fi

	echo -e ""
	echo -e "Creating WireGuard config file at '${BOLD}$wg_if_conf${ENDC}' ..."
	
	rm -rf $wg_if_conf
	ln -s $TMP_CONF	$wg_if_conf

	echo -e ""
	echo -e "${GREEN}Created WireGuard config file for interface${ENDC} '${BGREEN}$interface${ENDC}' ${GREEN}at${ENDC} '${BGREEN}$wg_if_conf${ENDC}'${GREEN}.${ENDC}"
}

# get status of current wireguard connection
get_status() {
	verify_root

	local interface server_id response server if_pub_key if_stts peer_stts routing_stts conn_stts
	interface=$1
	
	if [[ "$interface" == "" ]]; then
		echoexit "error: invalid wireguard interface."
	fi

	# check if interface is connected to given server
	if_pub_key="$(wg show "$interface" public-key 2>/dev/null)"
	if [[ "$if_pub_key" == "" ]]; then
		if_stts="down"
	else
		if_stts="up"
	fi
	
	# check if routing is set
	routing_stts=$(routing_status "$interface") || exit $?
	if [[ "$routing_stts" == "yes:yes" ]]; then
		routing_stts="on"
	else
		routing_stts="off"
	fi

	# check if interface is connected to given server
	if [[ "$if_stts" == "up" ]] && [[ "$routing_stts" == "on" ]]; then
		conn_stts="connected"
	else
		conn_stts="disconnected"
	fi
	
	local stts_color conn_color

	# conditional color
	if [[ "$conn_stts" == "connected" ]]; then
		stts_color="$BCYAN"
		conn_color="$CYAN"
	else
		stts_color="$BRED"
		conn_color="$RED"
	fi

	# print status
	printf "${stts_color}status${ENDC}: ${conn_color}$conn_stts${ENDC}\n"
	printf "  ${BOLD}interface${ENDC}: $if_stts\n"
	printf "  ${BOLD}routing${ENDC}: $routing_stts\n"

	# print info if interface is up
	if [[ "$if_stts" == "up" ]]; then
		# print wireguard info
		echo -e ""
		wg show "$interface"
	fi
}

# check for routing status
routing_status() {
	verify_root

	local interface
	interface=$1

	local r_rule f_rule routing firewall r_status
	r_rule="not from all fwmark 0x51a77 lookup 2468"
	f_rule="oifname != \"$interface\" meta mark != 0x00051a77 fib daddr type != local counter packets 0 bytes 0 reject"

	# get status
	routing=$(ip rule | grep -m 1 "$r_rule")
	firewall=$(nft list chain ip filter output 2>/dev/null | grep -m 1 "$f_rule") 

	# check status
	if [[ "$routing" == "" ]]; then
		r_status="no:"
	else
		r_status="yes:"
	fi
	if [[ "$firewall" == "" ]]; then
		r_status+="no"
	else
		r_status+="yes"
	fi

	# print both statuses
	printf %s "$r_status"
}

#
# wireguard postup script
#
# After the interface is up, we add routing and firewall rules,
# which prevent packets from going through the normal routes, which are
# for "plaintext" packets.
#
# If the connection to the VPN goes down, the firewall rule makes sure
# no other connections can be open, until you explicitly disconnect
# the client by running 'nordvpn-rc disconnect'
#
set_routing() {
	verify_root

	local interface nft_atom nft_atom_file nft_handle
	interface=$1

	echo -e "Adding routing and firewall rules ..."
	
	#
	# create firewall blocking rule.
	#
	# if packet isn't going out the wireguard interface, doesn't have
	# the wireguard firewall mark and isn't broadcast or multicast
	# reject it (don't drop it like there's no connection).
	#
	# firewall rules taken from: man wg-quick
	#
	
	# create atomic operation
	nft_atom="#!/sbin/nft -f"
	nft_atom+="\n"
	nft_atom+="\nadd table ip filter"
	nft_atom+="\nadd chain ip filter output"
	nft_atom+="\n"

	local f_rule
	f_rule="oifname != \"$interface\" meta mark != 0x00051a77 fib daddr type != local counter packets 0 bytes 0 reject"

	# check if old rule exists
	nft_handle=$(nft -a list chain ip filter output 2>/dev/null | grep -m 1 "$f_rule")
	if [[ "$nft_handle" != "" ]]; then
		# get rule handle
		nft_handle=$(echo "$nft_handle" | cut -d "#" -f 2 | grep "handle" | sed -r "s/handle/ /g")
	
		# create atomic operation	
		nft_atom+="\ndelete rule filter output handle $nft_handle"
		nft_atom+="\n"
	fi
	
	# create rule
	nft_atom+="\ninsert rule ip filter output oifname!=\"$interface\" mark!=334455 fib daddr type!=local counter reject"
	nft_atom+="\n"

	# write operation to file
	nft_atom_file="$TMPDIR/nordvpn_nftables.set"
	echo -e "$nft_atom" > "$nft_atom_file"

	# run atomic operation
	nft -f "$nft_atom_file" || return 1

	#
	# create routing rules.
	#
	# add wireguard interface to table 2468 and then
	# route all packets through that table.
	#
	# routing rules taken from: https://www.wireguard.com/netns/
	#
	
	# removing old routing rules, if they exist, to prevent errors.
	ip rule del not fwmark 334455 table 2468 2>/dev/null
	ip route del default dev "$interface" table 2468 2>/dev/null
	
	# set a firewall mark for all packets going through wireguard interface.
	wg set "$interface" fwmark 334455 || return 1

	# add wireguard interface to table 2468
	ip route add default dev "$interface" table 2468 || return 1
	
	# if packet doesn't have the wireguard firewall mark, send it to table 2468.
	ip rule add not fwmark 334455 table 2468 || return 1

	#
	# change DNS servers.
	#
	# Add DNS servers from NordVPN to resolv.conf 
	# to enable name resolution in the VPN connection.
	#
	# DNS taken from: https://support.nordvpn.com/General-info/1047409702/What-are-your-DNS-server-addresses.htm
	#
	
	# prevent dhcpcd from writing to '/etc/resolv.conf'.
	echo "nohook resolv.conf" >> "/etc/dhcpcd.conf"
	echo -e ""

	# restart dhcpcd to reload the config.
	# it should not edit /etc/resolv.conf anymore.
	rc-service dhcpcd restart

	# DNS Servers from NordVPN:
	echo "# File generated by wg-rc script." > /etc/resolv.conf || return 1
	echo "# Do not edit this file manually." >> /etc/resolv.conf || return 1
	echo "nameserver 103.86.96.100" >> /etc/resolv.conf || return 1
	echo "nameserver 103.86.99.100" >> /etc/resolv.conf || return 1
}

#
# wireguard predown script
#
# When disconnecting the client, make sure that all rules
# specific to isolating the wireguard connections are gone, so
# that normal connections can work again.
# Change the DNS values for your setup!
#
unset_routing() {
	verify_root

	local interface routing_stts nft_atom nft_atom_file nft_handle
	interface=$1

	echo -e "Revoking routing and firewall rules ..."	

	# check routing status
	routing_stts=$(routing_status "$interface") || exit $?
	if [[ "$routing" == "no:no" ]]; then
		return 0
	fi
	
	#
	# remove wireguard routing rules.
	#
	# routing rules taken from: https://www.wireguard.com/netns/
	#
	
	# delete routing rule.
	ip rule del not fwmark 334455 table 2468 || return 1
	
	# remove wireguard interface from table 2468.
	ip route del default dev "$interface" table 2468 || return 1

	#
	# bring back your own DNS settings.
	#

	# enable dhcpcd to write to '/etc/resolv.conf' again.
	local dhcpcd_conf
	dhcpcd_conf=$(grep -v "nohook resolv.conf" "/etc/dhcpcd.conf")
	echo -e "$dhcpcd_conf" > "/etc/dhcpcd.conf"
	echo -e "" > "/etc/resolv.conf"
	
	# restart dhcpcd to reset DNS settings
	echo -e ""
	rc-service dhcpcd restart

	#
	# remove firewall blocking rule.
	#
	# firewall rules taken from: man wg-quick
	#

	local f_rule
	f_rule="oifname != \"$interface\" meta mark != 0x00051a77 fib daddr type != local counter packets 0 bytes 0 reject"
	
	# check for rule in nftables
	nft_handle=$(nft -a list chain ip filter output 2>/dev/null | grep -m 1 "$f_rule")
	if [[ "$nft_handle" != "" ]]; then
		# get rule handle
		nft_handle=$(echo "$nft_handle" | cut -d "#" -f 2 | grep "handle" | sed -r "s/handle/ /g")
	
		# delete blocking rule
		nft delete rule ip filter output handle "$nft_handle" || return 1
	fi
}

# connect to given wireguard server
connect() {
	verify_root

	local server hostname station server_id public_key config private_key wg_config wg_config_file interface wg_if_file set_routing_stts routing_stts
	server=$1

	
	
	chmod 600 "$wg_config_file"

	# ask for user confirmation
	if [[ "$NOINTERACT" == "0" ]]; then
		echo -e ""
		echo -e "You will be ${GREEN}connected${ENDC} to server '${BOLD}$hostname${ENDC}'."
		echo -e ""
		show_server "$server"
		echo -e ""
		read -p "$(echo -e "${BOLD}Do you want to continue?${ENDC} [${BGREEN}Yes${ENDC}/${BRED}No${ENDC}] ")" -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			echo -e ""
    			echo -e "Not doing anything."
			echo -e ""
			exit 0
		fi
	fi

	# extract interface
	interface=$(cat "$WGRC_IF")
	if [[ "$interface" == "" ]]; then
		echoexit "error: invalid wireguard interface."
	fi

	# wireguard config file name
	wg_if_file="$WIREGUARD_DIR/$interface.conf"
	
	# change interface symlink
	rm "$wg_if_file"
	ln -s "$wg_config_file" "$wg_if_file"

	# print connecting
	echo -e ""
	echo -e "${GREEN}Connecting to server${ENDC} '${BGREEN}$hostname${ENDC}' ${GREEN}...${ENDC}"
	
	# start wireguard interface
	echo -e ""
	rc-service "net.$interface" stop
	rc-service "net.$interface" start

	# add wireguard firewall rules
	echo -e ""
	set_routing "$interface" || set_routing_stts=$?

	# check routing status
	routing_stts=$(routing_status "$interface") || exit $?
	if [[ "$routing_stts" != "yes:yes" ]] || [[ "$set_routing_stts" != "" ]]; then
		echo -e ""
		echo -e "${RED}Error setting routing rules.${ENDC}"
		echo -e ""
		echo -e "You can verify the status of your routing with '${BOLD}ip rule${ENDC}' and firewall with '${BOLD}nft list ruleset${ENDC}'."
		echo -e ""
		exit 1
	fi
	
	# print connected
	echo -e ""
	echo -e "${GREEN}Connected successfully!${ENDC}"
	echo -e ""
}

# disconnect
wg_disconnect() {
	verify_root

	local config interface if_pub_key hostname server_id response server unset_routing_stts routing_stts

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# extract interface
	interface=$(printf %s "$config" | jq -r '.interface')
	if [[ "$interface" == "" ]] || [[ "$interface" == "null" ]]; then
		echoexit "error: invalid wireguard interface."
	fi

	# check if interface is up
	if_pub_key="$(wg show "$interface" public-key 2>/dev/null)"
	if [[ "$if_pub_key" == "" ]]; then
		echo -e ""
		echo -e "You are already disconnected."
		echo -e ""
		exit 1
	fi
	
	# extract server hostname
	hostname=$(get_server_hostname "$interface") || exit $?

	# ask for user confirmation
	if [[ "$NOINTERACT" == "0" ]]; then
		echo -e ""
		echo -e "You will be ${RED}disconnected${ENDC} from server '${BOLD}$hostname${ENDC}'."
		echo -e ""
		read -p "$(echo -e "${BOLD}Do you want to continue?${ENDC} [${BGREEN}Yes${ENDC}/${BRED}No${ENDC}] ")" -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			echo -e ""
    			echo -e "Not doing anything."
			echo -e ""
			exit 0
		fi
	fi

	# print disconnecting
	echo -e ""
	echo -e "${RED}Disconnecting from server${ENDC} '${BRED}$hostname${ENDC}' ${RED}...${ENDC}"
	
	# remove wireguard firewall rules
	echo -e ""
	unset_routing "$interface" || unset_routing_stts=$?

	# check routing status
	routing_stts=$(routing_status "$interface") || exit $?
	if [[ "$routing_stts" != "no:no" ]] || [[ "$unset_routing_stts" != "" ]]; then
		echo -e ""
		echo -e "${RED}Error revoking routing rules.${ENDC}"
		echo -e ""
		echo -e "You can verify the status of your routing with '${BOLD}ip rule${ENDC}' and firewall with '${BOLD}nft list ruleset${ENDC}'."
		echo -e ""
		exit 1
	fi

	# stop wireguard interface
	echo -e ""
	rc-service "net.$interface" stop

	# print disconnected
	echo -e ""
	echo -e "${RED}Disconnected successfully!${ENDC}"
	echo -e ""
}

# restart
wg_restart() {
	verify_root

	local config interface if_pub_key hostname

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# extract interface
	interface=$(printf %s "$config" | jq -r '.interface')
	if [[ "$interface" == "" ]] || [[ "$interface" == "null" ]]; then
		echoexit "error: invalid wireguard interface."
	fi

	# check if interface is up
	if_pub_key="$(wg show "$interface" public-key 2>/dev/null)"
	if [[ "$if_pub_key" == "" ]]; then
		echo -e ""
		echo -e "There are no connections to be restarted."
		echo -e ""
		exit 1
	fi

	# extract server hostname
	hostname=$(get_server_hostname "$interface") || exit $?

	# ask for user confirmation
	if [[ "$NOINTERACT" == "0" ]]; then
		echo -e ""
		echo -e "Your connection to server '${BOLD}$hostname${ENDC}' will be ${GREEN}restarted${ENDC}."
		echo -e ""
		read -p "$(echo -e "${BOLD}Do you want to continue?${ENDC} [${BGREEN}Yes${ENDC}/${BRED}No${ENDC}] ")" -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			echo -e ""
    			echo -e "Not doing anything."
			echo -e ""
			exit 0
		fi
	fi
	
	# print restarting
	echo -e ""
	echo -e "${GREEN}Restarting connection to server${ENDC} '${BGREEN}$hostname${ENDC}' ${GREEN}...${ENDC}"

	# restart wireguard interface
	echo -e ""
	rc-service "net.$interface" stop
	rc-service "net.$interface" start

	# add wireguard firewall rules
	echo -e ""
	set_routing "$interface"

	# print restarted
	echo -e ""
	echo -e "${GREEN}Restarted successfully!${ENDC}"
	echo -e ""
}

# error wrong number of args
exit_args() {
	local mod
	mod=$(printf %s " $2 " | sed -r 's/[[:blank:]]+/ /g')
	echo -e "Too $1 arguments."
	echo -e "Try 'nordvpn-rc$mod--help' to see available options."
	exit 1
}

#
# main
#

# options loop
in_opt="0"
while [[ "$in_opt" == "0" ]]; do
	[ $# -lt 1 ] && exit_args "few" ""
	m_opt=$1
	shift
	case "$m_opt" in
		"-y")
			NOINTERACT="1"
			;;
		"--nocolor")
			ENDC=""
			GREEN=""
			RED=""
			CYAN=""
			BOLD=""
			BGREEN=""
			BRED=""
			BCYAN=""
			;;
		*)
			in_opt="1"
			;;
	esac
done

# modules
case "$m_opt" in
	"-h" | "--help")
		[ $# -gt 0 ] && exit_args "many" ""
		echo -e ""
		echo -e "NordVPN client using WireGuard and Netifrc."
		echo -e "Usage: nordvpn-rc <action> <options>"
		echo -e ""
		echo -e "actions:"
		echo -e "  -h, --help    display this help message"
		echo -e "  -y            run command in non-interactive mode"
		echo -e "  (g)et         get info from VPN provider"
		echo -e "  (s)et         set config"
		echo -e "  (c)onnect     connect to server"
		echo -e "  (d)isconnect  disconnect from server"
		echo -e "  (r)estart     restart current connection"
		echo -e ""
		echo -e "To see options run '${BOLD}nordvpn-rc <action> --help${ENDC}'"
		echo -e ""
		exit 0
		;;
	"g" | "gs" | "get")
		case "$m_opt" in
			"gs") g_opt="s" ;;
			*)
				[ $# -lt 1 ] && exit_args "few" "get"
				g_opt=$1
				shift
				;;
		esac	
		case "$g_opt" in
			"-h" | "--help")
				[ $# -gt 0 ] && exit_args "many" "get"
				echo -e ""
				echo -e "NordVPN client using WireGuard and Netifrc."
				echo -e "Action: get"
				echo -e "Usage: nordvpn-rc get <options>"
				echo -e ""
				echo -e "options:"
				echo -e "  -h, --help  display this help message"
				echo -e "  countries   get country list from VPN provider"
				echo -e "  cities      get city list from VPN provider"
				echo -e "  (s)tatus      get current VPN status"
				echo -e ""
				exit 0
				;;
			"countries")
				[ $# -gt 0 ] && exit_args "many" "get"
				get_countries | jq -r '.[].name'
				exit 0
				;;
			"cities")
				[ $# -lt 1 ] && exit_args "few" "get"
				country=$1
				shift
				[ $# -gt 0 ] && exit_args "many" "get"
				get_cities "$country" | jq -r '.[].name'
				exit 0
				;;
			"s" | "status")
				[ $# -gt 0 ] && exit_args "many" "get"
				get_status
				exit 0
				;;
			*)
				echo -e "Invalid argument '$g_opt'."
				echo -e "Try 'nordvpn-rc get --help' to see available options."
				exit 1
				;;
		esac
		;;
	"s" | "set")
		[ $# -lt 1 ] && exit_args "few" "set"
		s_opt=$1
		shift
		case "$s_opt" in
			"-h" | "--help")
				[ $# -gt 0 ] && exit_args "many" "set"
				echo -e ""
				echo -e "NordVPN client using WireGuard and Netifrc."
				echo -e "Action: set"
				echo -e "Usage: nordvpn-rc set <options>"
				echo -e ""
				echo -e "options:"
				echo -e "  -h, --help     display this help message"
				echo -e "  token          set the token given by VPN provider"
				echo -e "  if, interface  set the name of the wireguard interface"
				echo -e ""
				exit 0
				;;
			"token")
				[ $# -lt 1 ] && exit_args "few" "set"
				token=$1
				shift
				[ $# -gt 0 ] && exit_args "many" "set"
				set_token "$token"
				exit 0
				;;
			"if" | "interface")
				[ $# -lt 1 ] && exit_args "few" "set"
				interface=$1
				shift
				[ $# -gt 0 ] && exit_args "many" "set"
				set_interface "$interface"
				exit 0
				;;
			*)
				echo -e "Invalid argument '$s_opt'."
				echo -e "Try 'nordvpn-rc set --help' to see available options."
				exit 1
				;;
		esac
		;;
	"c" | "cr" | "co" | "connect")
		case "$m_opt" in
			"cr") c_opt="r" ;;
			"co") c_opt="o" ;;
			*)
				[ $# -lt 1 ] && exit_args "few" "connect"
				c_opt=$1
				shift
				;;
		esac
		case "$c_opt" in
			"-h" | "--help")
				[ $# -gt 0 ] && exit_args "many" "connect"
				echo -e ""
				echo -e "NordVPN client using WireGuard and Netifrc."
				echo -e "Action: connect"
				echo -e "Usage: nordvpn-rc connect <options>"
				echo -e ""
				echo -e "options:"
				echo -e "  -h, --help      display this help message"
				echo -e "  (r)recommended  connect to a server recommended by the VPN provider"
				echo -e "  (o)ther         connect to a different server than the current one"
				echo -e "  <id|hostname>   connect to a server with given <id> or <hostname>"
				echo -e ""
				exit 0
				;;
			"r" | "recommended")
				[ $# -lt 1 ] && country="" || country=$1 && shift 2>/dev/null
				[ $# -lt 1 ] && city="" || city=$1 && shift 2>/dev/null
				[ $# -gt 0 ] && exit_args "many" "connect"
				filters=$(connect_location "$country" "$city") || exit $?
				connect_to_recommended "$filters"
				exit 0
				;;
			"o" | "other")
				[ $# -lt 1 ] && country="" || country=$1 && shift 2>/dev/null
				[ $# -lt 1 ] && city="" || city=$1 && shift 2>/dev/null
				[ $# -gt 0 ] && exit_args "many" "connect"
				filters=$(connect_location "$country" "$city") || exit $?
				connect_to_other "$filters"
				exit 0
				;;
			*)
				[ $# -gt 0 ] && exit_args "many" "connect"
				num_re='^[0-9]+$'
				if [[ $c_opt =~ $num_re ]]; then
					connect_by_id "$c_opt"
				else
					connect_by_hostname "$c_opt"
				fi
				exit 0
				;;
		esac
		;;
	"d" | "disconnect")
		[ $# -gt 0 ] && exit_args "many" ""
		wg_disconnect
		exit 0
		;;
	"r" | "restart")
		[ $# -gt 0 ] && exit_args "many" ""
		wg_restart
		exit 0
		;;
	*)
		echo -e "Invalid argument '$m_opt'."
		echo -e "Try 'nordvpn-rc --help' to see available options."
		exit 1
		;;
esac

