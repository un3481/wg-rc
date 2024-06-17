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
TMP_CONF="$TMP_DIR/wgrc.conf"
NET_LO="$INIT_DIR/net.lo"
NET_WG="$INIT_DIR/net.wgrc"
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
up() {
	verify_root
	
	local config
	config=$1

	# check the string provided by user
	if [[ "$config" == "" ]]; then
		echo -e ""
		echo -e "Attempting to set ${RED}invalid${ENDC} config."
		echo -e ""
		exit 1
	fi

	create_init_script
	add_netifrc_configuration
	create_config_symlink "$config"

	# start wireguard interface
	echo -e ""
	rc-service "net.wgrc" stop
	rc-service "net.wgrc" start

	# add wireguard firewall rules
	echo -e ""
	set_routing || set_routing_stts=$?

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

create_init_script() {
	verify_root
	
	rm -rf $NET_WG 2>/dev/null
	ln -s $NET_LO $NET_WG

	# check for symlink
	if ! test -f "$NET_WG" || [[ "$(realpath $NET_WG)" != "$NET_LO" ]]; then
		echo -e ""
		echo -e "${RED}Could not create init script at${ENDC} '${BRED}$NET_WG${ENDC}' ${RED}.${ENDC}"
		echo -e ""
		exit 1
	fi

	echo -e ""
	echo -e "${GREEN}Created init script at${ENDC} '${BGREEN}$NET_WG${ENDC}' ${GREEN}.${ENDC}"
}

add_netifrc_configuration() {
	verify_root
	
	local net_wg_prefix net_config_prefix net_content
	net_wg_prefix="wireguard_wgrc="
	net_config_prefix="config_wgrc="
	net_content=$(cat "$NET_CONF" 2>/dev/null)

	local net_wg net_config net_clear
	net_wg="$net_wg_prefix\"$TMP_CONF\""
	net_config="$net_config_prefix\"$DEFAULT_IP\""
	net_clear=$(printf %b "$net_content" | grep -v "^$net_wg_prefix\$" 2>/dev/null | grep -v "^$net_config_prefix" 2>/dev/null)
	
	printf "$net_clear" > $NET_CONF
	printf "\n$net_wg\n$net_config" >> $NET_CONF

	echo -e ""
	echo -e "${GREEN}Interface${ENDC} '${BGREEN}wgrc${ENDC}' ${GREEN}configured as${ENDC} '${BGREEN}$DEFAULT_IP${ENDC}'${GREEN}.${ENDC}"
}

create_config_symlink() {
	verify_root
	
	local config
	config=$1

	rm -rf $TMP_CONF
	ln -s $config $TMP_CONF

	# check for symlink
	if ! test -f "$TMP_CONF" || [[ "$(realpath $TMP_CONF)" != "$config" ]]; then
		echo -e ""
		echo -e "${RED}Could not create symlink at${ENDC} '${BRED}$TMP_CONF${ENDC}' ${RED}.${ENDC}"
		echo -e ""
		exit 1
	fi

	echo -e ""
	echo -e "${GREEN}Created WireGuard config symlink at${ENDC} '${BGREEN}$TMP_CONF${ENDC}'${GREEN}.${ENDC}"
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

	local nft_atom nft_atom_file nft_handle

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
	f_rule="oifname != \"wgrc\" meta mark != 0x00051a77 fib daddr type != local counter packets 0 bytes 0 reject"

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
	nft_atom+="\ninsert rule ip filter output oifname!=\"wgrc\" mark!=334455 fib daddr type!=local counter reject"
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
	ip route del default dev "wgrc" table 2468 2>/dev/null
	
	# set a firewall mark for all packets going through wireguard interface.
	wg set "wgrc" fwmark 334455 || return 1

	# add wireguard interface to table 2468
	ip route add default dev "wgrc" table 2468 || return 1
	
	# if packet doesn't have the wireguard firewall mark, send it to table 2468.
	ip rule add not fwmark 334455 table 2468 || return 1

	#
	# change DNS servers.
	#
	
	# restart dhcpcd to reload the config.
	rc-service dhcpcd restart
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
	routing_stts=$(routing_status "wgrc") || exit $?
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
	ip route del default dev "wgrc" table 2468 || return 1
	
	#
	# remove firewall blocking rule.
	#
	# firewall rules taken from: man wg-quick
	#

	local f_rule
	f_rule="oifname != \"wgrc\" meta mark != 0x00051a77 fib daddr type != local counter packets 0 bytes 0 reject"
	
	# check for rule in nftables
	nft_handle=$(nft -a list chain ip filter output 2>/dev/null | grep -m 1 "$f_rule")
	if [[ "$nft_handle" != "" ]]; then
		# get rule handle
		nft_handle=$(echo "$nft_handle" | cut -d "#" -f 2 | grep "handle" | sed -r "s/handle/ /g")
	
		# delete blocking rule
		nft delete rule ip filter output handle "$nft_handle" || return 1
	fi
	
	#
	# bring back your own DNS settings.
	#

	echo -e ""
	rc-service dhcpcd restart
}

# check for routing status
routing_status() {
	verify_root

	local r_rule f_rule routing firewall r_status
	r_rule="not from all fwmark 0x51a77 lookup 2468"
	f_rule="oifname != \"wgrc\" meta mark != 0x00051a77 fib daddr type != local counter packets 0 bytes 0 reject"

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

# disconnect
down() {
	verify_root

	local if_pub_key hostname server_id response server unset_routing_stts routing_stts

	# check if interface is up
	if_pub_key="$(wg show "wgrc" public-key 2>/dev/null)"
	if [[ "$if_pub_key" == "" ]]; then
		echo -e ""
		echo -e "You are already disconnected."
		echo -e ""
		exit 1
	fi
	
	# ask for user confirmation
	if [[ "$NOINTERACT" == "0" ]]; then
		echo -e ""
		echo -e "You will be ${RED}disconnected${ENDC} from wireguard."
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
	echo -e "${RED}Disconnecting from server ...${ENDC}"
	
	# remove wireguard firewall rules
	echo -e ""
	unset_routing || unset_routing_stts=$?

	# check routing status
	routing_stts=$(routing_status) || exit $?
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
	rc-service "net.wgrc" stop

	# print disconnected
	echo -e ""
	echo -e "${RED}Disconnected successfully!${ENDC}"
	echo -e ""
}

# restart
restart() {
	verify_root

	local config interface if_pub_key hostname

	# check if interface is up
	if_pub_key="$(wg show "wgrc" public-key 2>/dev/null)"
	if [[ "$if_pub_key" == "" ]]; then
		echo -e ""
		echo -e "There are no connections to be restarted."
		echo -e ""
		exit 1
	fi

	# ask for user confirmation
	if [[ "$NOINTERACT" == "0" ]]; then
		echo -e ""
		echo -e "Your connection to wireguard will be ${GREEN}restarted${ENDC}."
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
	echo -e "${GREEN}Restarting connection to server ...${ENDC}"

	# restart wireguard interface
	echo -e ""
	rc-service "net.wgrc" stop
	rc-service "net.wgrc" start

	# add wireguard firewall rules
	echo -e ""
	set_routing

	# print restarted
	echo -e ""
	echo -e "${GREEN}Restarted successfully!${ENDC}"
	echo -e ""
}

# get status of current wireguard connection
status() {
	verify_root

	local if_pub_key if_stts peer_stts routing_stts conn_stts
	
	# check if interface is connected to given server
	if_pub_key="$(wg show wgrc public-key 2>/dev/null)"
	if [[ "$if_pub_key" == "" ]]; then
		if_stts="down"
	else
		if_stts="up"
	fi
	
	# check if routing is set
	routing_stts=$(routing_status) || exit $?
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
		wg show wgrc
	fi
}

# error wrong number of args
exit_args() {
	echo -e "Too $1 arguments."
	echo -e "Try 'wg-rc --help' to see available options."
	exit 1
}

#
# main
#

# options loop
in_opt="0"
while [[ "$in_opt" == "0" ]]; do
	[ $# -lt 1 ] && exit_args "few"
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
		[ $# -gt 0 ] && exit_args "many"
		echo -e ""
		echo -e "WireGuard client using Netifrc."
		echo -e "Usage: wg-rc <action> <options>"
		echo -e ""
		echo -e "actions:"
		echo -e "  -h, --help    display this help message"
		echo -e "  -y            run command in non-interactive mode"
		echo -e "  (s)tatus      show wireguard status"
		echo -e "  (u)p          connect using config"
		echo -e "  (d)own        disconnect from server"
		echo -e "  (r)estart     restart current connection"
		echo -e ""
		echo -e "To see options run '${BOLD}wg-rc <action> --help${ENDC}'"
		echo -e ""
		exit 0
		;;
	"u" | "up")
		[ $# -lt 1 ] && exit_args "few"
		wg_config=$1
		shift
		[ $# -gt 0 ] && exit_args "many"
		up "$wg_config"
		exit 0
		;;
	"d" | "down")
		[ $# -gt 0 ] && exit_args "many"
		down
		exit 0
		;;
	"r" | "restart")
		[ $# -gt 0 ] && exit_args "many"
		restart
		exit 0
		;;
	"s" | "status")
		[ $# -gt 0 ] && exit_args "many"
		status
		exit 0
		;;
	*)
		echo -e "Invalid argument '$m_opt'."
		echo -e "Try 'nordvpn-rc --help' to see available options."
		exit 1
		;;
esac

