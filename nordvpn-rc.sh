#!/bin/sh
#
# NORDVPN-RC
#
# NordVPN client using WireGuard and Netifrc.
#

# exit when any command fails
set -T

echoexit() {
  # Print to stderr and exit
  printf "%s\n" "$@" 1>&2
  exit 1
}

# Checking dependencies:
whereis curl > /dev/null || echoexit "'curl' command not found."
whereis jq > /dev/null || echoexit "'jq' command not found."
whereis wg > /dev/null || echoexit "'wg' command not found."
whereis ip > /dev/null || echoexit "'ip' command not found."
whereis nft > /dev/null || echoexit "'nft' command not found."
whereis rc-service > /dev/null || echoexit "'rc-service' not found."

#
# Constants
#

# tmpfs
TMPDIR="/tmp"

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
WIREGUARD_DIR="/etc/wireguard"
NORDVPN_DIR="$WIREGUARD_DIR/nordvpn"
NORDVPN_CONFIG="$NORDVPN_DIR/config.json"

# urls
NORDVPN_API_BASE="https://api.nordvpn.com"
NORDVPN_API_USER="$NORDVPN_API_BASE/v1/users/current"
NORDVPN_API_CREDENTIALS="$NORDVPN_API_BASE/v1/users/services/credentials"
NORDVPN_API_SERVERS="$NORDVPN_API_BASE/v1/servers"
NORDVPN_API_COUNTRIES="$NORDVPN_API_BASE/v1/servers/countries"
NORDVPN_API_RECOMMENDED="$NORDVPN_API_BASE/v1/servers/recommendations"

# id of wireguard servers
NORDVPN_WG_ID="35"

# api servers filters
NORDVPN_API_SERVERS_FILTERS="filters\[servers.status\]=online"
NORDVPN_API_SERVERS_FILTERS+="&filters\[servers_technologies\]\[id\]=$NORDVPN_WG_ID"
NORDVPN_API_SERVERS_FILTERS+="&filters\[servers_technologies\]\[pivot\]\[status\]=online"

# api servers fields
NORDVPN_API_SERVERS_FIELDS="fields\[servers.id\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.name\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.hostname\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.station\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.load\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.created_at\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.groups.id\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.groups.title\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.technologies.id\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.technologies.metadata\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.locations.country.id\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.locations.country.name\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.locations.country.city.id\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.locations.country.city.name\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.locations.country.city.latitude\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.locations.country.city.longitude\]"
NORDVPN_API_SERVERS_FIELDS+="&fields\[servers.locations.country.city.hub_score\]"

# servers query
NORDVPN_API_SERVERS_BASE="$NORDVPN_API_SERVERS?$NORDVPN_API_SERVERS_FIELDS&$NORDVPN_API_SERVERS_FILTERS"

# recommended servers query
NORDVPN_API_RECOMMENDED_BASE="$NORDVPN_API_RECOMMENDED?$NORDVPN_API_SERVERS_FIELDS&$NORDVPN_API_SERVERS_FILTERS"

# verify if user has root privileges
verify_root() {
	if [ "$(id -u)" != "0" ]; then
		echo -e "This command requires administrative privileges."
		echo -e "Try '${BOLD}sudo nordvpn-rc <options>${ENDC}' or login as root."
		exit 1
	fi
}

# verify api response
verify_response() {
	local response errors
	response=$1

	# check for errors in response
	if [[ "$response" == "" ]]; then
		echoexit "api_error: API call returned nothing."
	fi	
	errors=$(printf %s "$response" | jq '.errors' 2>/dev/null)
	if [[ "$errors" != "" ]] && [[ "$errors" != "null" ]]; then
		echoexit "api_error: API replied with errors: '$errors'."
	fi
}

# verify if token is valid on remote
verify_token() {
	local token response errors valid
	token=$1

	# request api for user metadata
	response=$(curl -s "$NORDVPN_API_USER" -u "token:$token")

	# check for errors in response
	valid="valid"
	if [[ "$response" == "" ]]; then
		exit_invalid_token
	fi
	errors=$(printf %s "$response" | jq '.errors' 2>/dev/null)
	if [[ "$errors" != "" ]] && [[ "$errors" != "null" ]]; then
		exit_invalid_token
	fi
}

# print error message for invalid token and exit
exit_invalid_token() {
	echo -e ""
	echo -e "${RED}You have not set a valid${ENDC} ${BRED}Access Token${ENDC}${RED}.${ENDC}"
	echo -e ""
	echo -e "Please follow the instructions to obtain a new token: https://support.nordvpn.com/Connectivity/Linux/1905092252/How-to-log-in-to-NordVPN-on-Linux-with-a-token.htm"
	echo -e ""
	echo -e "Once you have copied your token, you can use it by running '${BOLD}nordvpn-rc set token <value>${ENDC}'."
	echo -e ""
	exit 1
}

# get wireguard private key from nordvpn and put it in the config file
update_private_key() {
	verify_root

	local config token response private_key

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")

	# get nordvpn token from config file
	token=$(printf %s "$config" | jq -r '.token')

	# request api for credentials
	response=$(curl -s "$NORDVPN_API_CREDENTIALS" -u "token:$token")
	verify_response "$response"

	# get private key from response
	private_key=$(printf %s "$response" | jq -r '.nordlynx_private_key')
	if [[ "$private_key" == "" ]]; then
		echoexit "api_error: API did not provide a valid private_key."
	fi

	# create new config
	config=$(printf %s "$config" | jq --arg key "$private_key" '.private_key = $key')

	# write updated config file
	mkdir -p "$NORDVPN_DIR"
	echo "$config" > "$NORDVPN_CONFIG"
	chmod 600 "$NORDVPN_CONFIG"
}

# set nordvpn access token in the config file
set_token() {
	verify_root

	local config token valid
	token=$1

	# check the string provided by user
	if [[ "$token" == "" ]]; then
		echo -e ""
		echo -e "Attempting to set ${RED}invalid${ENDC} ${BOLD}Access Token${ENDC}."
		echo -e ""
		exit 1
	fi

	echo -e ""
	echo -e "Verifying ${BOLD}Access Token${ENDC} ..."
	
	# verify token
	verify_token "$token"

	echo -e ""
	echo -e "${BGREEN}Access Token${ENDC} ${GREEN}is valid!${ENDC}"

	# ask for user confirmation
	if [[ "$NOINTERACT" == "0" ]]; then
		echo -e ""
		echo -e "Your ${BOLD}Access Token${ENDC} will be updated. Any previous credentials will be lost."
		echo -e ""
		read -p "$(echo -e "${BOLD}Do you want to continue?${ENDC} [${BGREEN}Yes${ENDC}/${BRED}No${ENDC}] ")" -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			echo -e ""
    			echo -e "Not doing anything."
			echo -e ""
			exit 0
		fi
	fi

	echo -e ""
	echo -e "Updating ${BOLD}Access Token${ENDC} ..."

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# create new config
	config=$(printf %s "$config" | jq --arg tok "$token" '.token = $tok')
	
	# write updated config file
	mkdir -p "$NORDVPN_DIR"
	echo "$config" > "$NORDVPN_CONFIG"
	chmod 600 "$NORDVPN_CONFIG"

	echo -e ""
	echo -e "${BGREEN}Access Token${ENDC} ${GREEN}updated successfully!${ENDC}"

	echo -e ""
	echo -e "Updating ${BOLD}WireGuard Private Key${ENDC} ..."

	# update credentials
	update_private_key

	echo -e ""
	echo -e "${BGREEN}WireGuard Private Key${ENDC} ${GREEN}updated successfully!${ENDC}"
	echo -e ""
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

	# file paths
	local net_lo_file net_if_file net_conf_file wg_if_file

	net_lo_file="$INIT_DIR/net.lo"
	net_if_file="$INIT_DIR/net.$interface"
	net_conf_file="$CONF_DIR/net"
	wg_if_file="$WIREGUARD_DIR/$interface.conf"

	echo -e ""
	echo -e "Checking init script at '${BOLD}$net_if_file${ENDC}' ..."

	# check for existing config file
	if ! test -f "$net_if_file" || [[ "$(realpath $net_if_file)" != "$net_lo_file" ]]; then
		echo -e ""
		echo -e "${RED}Init script at${ENDC} '${BRED}$net_if_file${ENDC}' ${RED}is not valid.${ENDC}"
		echo -e ""
		exit 1
	fi

	echo -e ""
	echo -e "${GREEN}Init script at${ENDC} '${BGREEN}$net_if_file${ENDC}' ${GREEN}is valid.${ENDC}"

	echo -e ""
	echo -e "Checking network configuration at '${BOLD}$net_conf_file${ENDC}' ..."

	# check for interface config
	local net_conf_wg_if net_conf_config_if net_conf wg_if_line config_if_line config_if

	net_conf_wg_if="wireguard_$interface=\"$wg_if_file\""
	net_conf_config_if="config_$interface=\""

	# read config file
	net_conf=$(cat "$net_conf_file" 2>/dev/null)
	wg_if_line=$(printf %b "$net_conf" | grep "^$net_conf_wg_if\$" 2>/dev/null)
	config_if_line=$(printf %b "$net_conf" | grep "^$net_conf_config_if" 2>/dev/null)
	config_if=$(printf %b "$config_if_line" | sed -r "s/$net_conf_config_if//g" | sed -r "s/\"//g")

	# check for line in file	
	if [[ "$wg_if_line" == "" ]] || [[ "$config_if_line" == "" ]]; then
		echo -e ""
		echo -e "${RED}Network configuration missing at${ENDC} '${BRED}$net_conf_file${ENDC}'${RED}.${ENDC}"
		echo -e ""
		exit 1
	fi

	echo -e ""
	echo -e "${GREEN}Interface${ENDC} '${BGREEN}$interface${ENDC}' ${GREEN}configured as${ENDC} '${BGREEN}$config_if${ENDC}'${GREEN}.${ENDC}"
	
	# check for existing config file
	if [[ "$NOINTERACT" == "0" ]] && test -f "$wg_if_file"; then
		echo -e ""
		echo -e "WireGuard config file '${BOLD}$wg_if_file${ENDC}' already exists."
		echo -e ""
		read -p "$(echo -e "${BOLD}Do you want to override it?${ENDC} [${BGREEN}Yes${ENDC}/${BRED}No${ENDC}] ")" -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
			echo -e ""
    			echo -e "Not doing anything."
			echo -e ""
			exit 0
		fi
	fi

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# create new config
	config=$(printf %s "$config" | jq --arg if "$interface" '.interface = $if')
	
	# write updated config file
	mkdir -p "$NORDVPN_DIR"
	echo "$config" > "$NORDVPN_CONFIG"
	chmod 600 "$NORDVPN_CONFIG"
	
	echo -e ""
	echo -e "${GREEN}Interface${ENDC} '${BGREEN}$interface${ENDC}' ${GREEN}configured.${ENDC}"
	echo -e ""
}

# get countries from nordvpn
get_countries() {
	local response countries

	# request api for countries
	response=$(curl -s "$NORDVPN_API_COUNTRIES")
	verify_response "$response"

	# extract country name and id
	countries=$(printf %s "$response" | jq 'map({ id: .id, conde: .code, name: .name })')

	# return response
	printf %s "$countries"
}

# get cities from nordvpn
get_cities() {
	local country response cities
	country=$1

	# request api for countries
	response=$(curl -s "$NORDVPN_API_COUNTRIES")
	verify_response "$response"

	# extract city name and id
	cities=$(printf %s "$response" | jq --arg cc "$country" '.[] | select((.name|ascii_upcase) == ($cc|ascii_upcase)) | .cities | map({id: .id, name: .name})')

	# return response
	printf %s "$cities"
}

# print server info to terminal
show_server() {
	local server form cyan white normcyan boldcyan bold endcolor
	server=$1

	# check server
	if [[ "$server" == "" ]] || [[ "$server" == "null" ]]; then
		echoexit "error: invalid server json."
	fi

	# print formattated output
	echo -e "${BCYAN}nordvpn${ENDC}: ${CYAN}$(printf %s "$server" | jq -r '.id')${ENDC}"
	echo -e "  ${BOLD}name${ENDC}: $(printf %s "$server" | jq -r '.name')"
	echo -e "  ${BOLD}hostname${ENDC}: $(printf %s "$server" | jq -r '.hostname')"
	echo -e "  ${BOLD}station${ENDC}: $(printf %s "$server" | jq -r '.station')"
	echo -e "  ${BOLD}public key${ENDC}: $(printf %s "$server" | jq -r --argjson wi "$NORDVPN_WG_ID" '.technologies[] | select(.id == $wi) | .metadata[] | select(.name == "public_key") | .value')"	
	echo -e "  ${BOLD}groups${ENDC}: $(printf %s "$server" | jq -r '.groups | map(.title) | join(", ")')"
	echo -e "  ${BOLD}created at${ENDC}: $(printf %s "$server" | jq -r '.created_at')"
	echo -e "  ${BOLD}country${ENDC}: $(printf %s "$server" | jq -r '.locations[].country.name')"
	echo -e "  ${BOLD}city${ENDC}: $(printf %s "$server" | jq -r '.locations[].country.city.name')"
	echo -e "  ${BOLD}latitude${ENDC}: $(printf %s "$server" | jq -r '.locations[].country.city.latitude')"
	echo -e "  ${BOLD}longitude${ENDC}: $(printf %s "$server" | jq -r '.locations[].country.city.longitude')"
	echo -e "  ${BOLD}hub score${ENDC}: $(printf %s "$server" | jq -r '.locations[].country.city.hub_score')"
	echo -e "  ${BOLD}load${ENDC}: $(printf %s "$server" | jq -r '.load')"
}

# get server id from file
get_server_id() {
	verify_root

	local interface wg_if_file wg_if line server_id
	interface=$1

	# wireguard config file name
	wg_if_file="$WIREGUARD_DIR/$interface.conf"
	
	# check if file exists
	if ! test -f "$wg_if_file"; then
		echoexit "No interface config file found."
	fi

	# read config file
	wg_if=$(cat "$wg_if_file" 2>/dev/null)

	# check for line in file
	line=$(printf %b "$wg_if" | grep "^# SERVER_ID = " 2>/dev/null)
	if [[ "$line" == "" ]]; then
		echoexit "error: invalid wireguard config '$wg_if_file'."
	fi

	# extract server id
	server_id=$(printf %s "$line" | cut -d "=" -f 2 | sed -r "s/\ //g")
	
	# return server id
	printf %s "$server_id"
}

# get server hostname from file
get_server_hostname() {
	verify_root

	local interface wg_if_file wg_if line hostname
	interface=$1

	# wireguard config file name
	wg_if_file="$WIREGUARD_DIR/$interface.conf"
	
	# check if file exists
	if ! test -f "$wg_if_file"; then
		echoexit "error: no interface config file found."
	fi

	# read config file
	wg_if="$(cat "$wg_if_file" 2>/dev/null)"

	# check for line in file
	line="$(printf %b "$wg_if" | grep "^# HOSTNAME = " 2>/dev/null)"
	if [[ "$line" == "" ]]; then
		echoexit "error: invalid wireguard config '$wg_if_file'."
	fi

	# extract server hostname
	hostname=$(printf %s "$line" | cut -d "=" -f 2 | sed -r "s/\ //g")
	
	# return server hostname
	printf %s "$hostname"
}

# check if wireguard conifg matches connected interface
peer_online() {
	verify_root

	local interface server server_ip server_key if_endpoint if_ip if_key
	interface=$1
	server=$2

	# get server info
	server_ip="$(printf %s "$server" | jq -r '.station')"
	server_key="$(printf %s "$server" | jq -r --argjson wi "$NORDVPN_WG_ID" '.technologies[] | select(.id == $wi) | .metadata[] | select(.name == "public_key") | .value')"

	# get interface info
	if_endpoint="$(wg show "$interface" endpoints 2>/dev/null)"
	if_ip="$(printf %s "$if_endpoint" | sed -r 's/[[:blank:]]+/ /g' | cut -d " " -f 2 | cut -d ":" -f 1)"
	if_key="$(printf %s "$if_endpoint" | sed -r 's/[[:blank:]]+/ /g' | cut -d " " -f 1)"

	# print result of match
	if [[ "$server_ip" == "$if_ip" ]] && [[ "$server_key" == "$if_key" ]]; then
		printf %s "online"
	else
		printf %s "offline"
	fi
}

# get status of current wireguard connection
get_status() {
	verify_root

	local config interface server_id response server if_pub_key if_stts peer_stts routing_stts conn_stts

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# extract interface
	interface=$(printf %s "$config" | jq -r '.interface')
	if [[ "$interface" == "" ]] || [[ "$interface" == "null" ]]; then
		echoexit "error: invalid wireguard interface."
	fi
	
	# extract server id
	server_id="$(get_server_id "$interface")"

	# request api for server with given id
	response=$(curl -s "$NORDVPN_API_SERVERS_BASE&filters\[servers.id\]=$server_id&limit=1")
	verify_response "$response"

	# extract server
	server="$(printf %s "$response" | jq '.[]')"

	# check if interface is connected to given server
	if_pub_key="$(wg show "$interface" public-key 2>/dev/null)"
	if [[ "$if_pub_key" == "" ]]; then
		if_stts="down"
	else
		if_stts="up"
	fi

	# check if remote matches interface
	peer_stts="none"
	if [[ "$if_stts" == "up" ]]; then
		peer_stts=$(peer_online "$interface" "$server") || exit $?
	fi

	# check if routing is set
	routing_stts=$(routing_status "$interface") || exit $?
	if [[ "$routing_stts" == "yes:yes" ]]; then
		routing_stts="on"
	else
		routing_stts="off"
	fi

	# check if interface is connected to given server
	if [[ "$if_stts" == "up" ]] && [[ "$peer_stts" == "online" ]] && [[ "$routing_stts" == "on" ]]; then
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
	printf "  ${BOLD}peer${ENDC}: $peer_stts\n"
	printf "  ${BOLD}routing${ENDC}: $routing_stts\n"

	# print info if interface is up
	if [[ "$if_stts" == "up" ]]; then
		# print wireguard info
		echo -e ""
		wg show "$interface"
		# print nordvpn server info
		echo -e ""
		show_server "$server"
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
	echo "# File generated by nordvpn-rc script." > /etc/resolv.conf || return 1
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

	# extract hostname
	hostname=$(printf %s "$server" | jq -r '.hostname')
	if [[ "$hostname" == "" ]] || [[ "$hostname" == "null" ]]; then
		echoexit "error: invalid server hostname."
	fi

	# extract hostname
	station=$(printf %s "$server" | jq -r '.station')
	if [[ "$station" == "" ]] || [[ "$station" == "null" ]]; then
		echoexit "error: invalid server station."
	fi

	# extract server id
	server_id=$(printf %s "$server" | jq -r '.id')
	if [[ "$server_id" == "" ]] || [[ "$server_id" == "null" ]]; then
		echoexit "error: invalid server id."
	fi

	# extract public key
	public_key=$(printf %s "$server" | jq -r --argjson wi "$NORDVPN_WG_ID" '.technologies[] | select(.id == $wi) | .metadata[] | select(.name == "public_key") | .value')
	if [[ "$public_key" == "" ]] || [[ "$public_key" == "null" ]]; then
		echoexit "error: invalid server public key."
	fi

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# extract private key
	private_key=$(printf %s "$config" | jq -r '.private_key')
	if [[ "$private_key" == "" ]] || [[ "$private_key" == "null" ]]; then
		echoexit "error: invalid client private key."
	fi
	
	# create wireguard config
	wg_config="# File created by nordvpn-rc script."
	wg_config+="\n# Do not edit this file manually."
	wg_config+="\n# SERVER_ID = $server_id"
	wg_config+="\n# HOSTNAME = $hostname"
	wg_config+="\n"
	wg_config+="\n[Interface]"
	wg_config+="\nPrivateKey = $private_key"
	wg_config+="\nListenPort = 51820"
	wg_config+="\n"
	wg_config+="\n[Peer]"
	wg_config+="\nPublicKey = $public_key"
	wg_config+="\nAllowedIPs = 0.0.0.0/0"
	wg_config+="\nEndpoint = $station:51820"
	wg_config+="\n"

	# wireguard config file name
	wg_config_file="$NORDVPN_DIR/$(printf %s "$hostname" | cut -d "." -f 1).conf"

	# write wireguard config
	mkdir -p "$NORDVPN_DIR"
	printf %b "$wg_config" > "$wg_config_file"
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
	interface=$(printf %s "$config" | jq -r '.interface')
	if [[ "$interface" == "" ]] || [[ "$interface" == "null" ]]; then
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

# connect to server by id
connect_by_id() {
	verify_root

	local server_id response server
	server_id=$1
	
	# request api for server with given id
	response=$(curl -s "$NORDVPN_API_SERVERS_BASE&filters\[servers.id\]=$server_id&limit=1")
	verify_response "$response"

	# extract server
	server="$(printf %s "$response" | jq '.[]')"

	# connect to server
	connect "$server"
}

# connect to recommended server
connect_to_recommended() {
	verify_root

	local filters response server
	filters=$1

	# request api for recommended server
	response=$(curl -s "$NORDVPN_API_RECOMMENDED_BASE&$filters&limit=1")
	verify_response "$response"

	# extract server
	server="$(printf %s "$response" | jq '.[]')"

	# connect to server
	connect "$server"
}

# connect to other server
connect_to_other() {
	verify_root

	local filters config interface old_server_id response server server_id
	filters=$1
	
	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# extract interface
	interface=$(printf %s "$config" | jq -r '.interface')
	if [[ "$interface" == "" ]] || [[ "$interface" == "null" ]]; then
		echoexit "error: invalid wireguard interface."
	fi

	# extract server id
	old_server_id=$(get_server_id "$interface") || exit $?

	# request api for recommended server
	response=$(curl -s "$NORDVPN_API_RECOMMENDED_BASE&$filters&limit=2")
	verify_response "$response"

	# extract server
	server=$(printf %s "$response" | jq '.[0]')

	# check id
	server_id=$(printf %s "$server" | jq -r '.id')
	if [[ "$old_server_id" == "$server_id" ]]; then
		server=$(printf %s "$response" | jq '.[1]')
	fi

	# connect to server
	connect "$server"
}

# connect to recommended server in given country
connect_location() {
	verify_root

	local country city filters
	country=$1
	city=$2

	# set filters
	if [[ "$city" == "" ]]; then
		if [[ "$country" == "" ]]; then
			filters=""
		else
			local countries country_id
			# extract country id
			countries=$(get_countries) || exit $?
			country_id=$(printf %s "$countries" | jq -r --arg cc "$country" '.[] | select((.name|ascii_upcase) == ($cc|ascii_upcase)) | .id')
			if [[ "$country_id" == "" ]]; then
				echoexit "error: invalid country."
			fi
			# set country filters
			filters="filters\[country_id\]=$country_id"
		fi
	else
		local cities city_id
		# extract city id
		cities=$(get_cities "$country") || exit $?
		city_id=$(printf %s "$cities" | jq -r --arg ct "$city" '.[] | select((.name|ascii_upcase) == ($ct|ascii_upcase)) | .id')
		if [[ "$city_id" == "" ]]; then
			echoexit "error: invalid country or city."
		fi
		# set country filters
		filters="filters\[country_city_id\]=$city_id"
	fi
	
	# return filters
	printf %s "$filters"
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

