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
whereis curl > /dev/null || echoexit "'curl' not found."
whereis jq > /dev/null || echoexit "'jq' not found."
whereis wg > /dev/null || echoexit "'wg' not found."
whereis rc-service > /dev/null || echoexit "'rc-service' not found."

# constants

TMPDIR="/tmp"
DB_FILE="$TMPDIR/nordvpn-rc-db"

# config files
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

# api servers query
NORDVPN_API_SERVERS_QUERY="filters\[servers.status\]=online"
NORDVPN_API_SERVERS_QUERY+="&filters\[servers_technologies\]\[id\]=$NORDVPN_WG_ID"
NORDVPN_API_SERVERS_QUERY+="&filters\[servers_technologies\]\[pivot\]\[status\]=online"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.id\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.name\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.hostname\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.station\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.load\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.groups.id\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.technologies.id\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.technologies.metadata\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.locations.country.id\]"
NORDVPN_API_SERVERS_QUERY+="&fields\[servers.locations.country.city.id\]"

# servers query
NORDVPN_API_SERVERS_FULL="$NORDVPN_API_SERVERS?limit=1&$NORDVPN_API_SERVERS_QUERY"

# recommended servers query
NORDVPN_API_RECOMMENDED_FULL="$NORDVPN_API_RECOMMENDED?limit=1&$NORDVPN_API_SERVERS_QUERY"

# verify if user has root privileges
verify_root() {
	if [ "$(id -u)" != "0" ]; then
   		exit_non_root
	fi
}

# print error message for insufficient privileges and exit
exit_non_root() {
	echo -e "This command requires administrative privileges."
	echo -e "Try 'sudo nordvpn-rc <your-args-go-here>' or login as root."
	exit 1
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
	echo -e "You have not set a valid nordvpn access token."
	echo -e "Please follow the instructions to obtain a new token: https://support.nordvpn.com/Connectivity/Linux/1905092252/How-to-log-in-to-NordVPN-on-Linux-with-a-token.htm"
	echo -e "Once you have copied your token, you can use it by running 'nordvpn-rc set token <your-token-goes-here>'."
	exit 1
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

# get wireguard private key from nordvpn and put it in the config file
update_private_key() {
	verify_root

	local config token response private_key
	
	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")

	# get nordvpn token from config file
	token=$(printf %s "$config" | jq -r '.token')

	# verify token
	verify_token "$token"

	# request api for credentials
	response=$(curl -s "$NORDVPN_API_CREDENTIALS" -u "token:$token")
	verify_response "$response"

	# get private key from response
	private_key=$(printf %s "$response" | jq -r '.nordlynx_private_key')
	if [[ "$private_key" == "" ]]; then
		echoexit "api_error: API did not provide a valid private_key."
	fi

	# create new config
	config=$(printf %s "$config" | jq --arg key "$private_key" '. | .private_key = $key')

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
		echoexit "error: Attempting to set invalid access token."
	fi
	
	# verify token
	verify_token "$token"

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# create new config
	config=$(printf %s "$config" | jq --arg tok "$token" '. | .token = $tok')
	
	# write updated config file
	mkdir -p "$NORDVPN_DIR"
	echo "$config" > "$NORDVPN_CONFIG"
	chmod 600 "$NORDVPN_CONFIG"

	# update credentials
	update_private_key
}

# set wireguard interface in the config file
set_interface() {
	verify_root
	
	local config interface wg_if_file
	interface=$1

	# check the string provided by user
	if [[ "$interface" == "" ]]; then
		echoexit "error: Attempting to set invalid interface."
	fi

	# check for existing config file
	wg_if_file="$WIREGUARD_DIR/$interface.conf"
	if test -f "$wg_if_file"; then
		echo -e "File '$wg_if_file' already exists."
		read -p "Do you want to override it? [Yes/No] " -r
		if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    			echo -e "Not doing anything."
			exit 0
		fi
	fi

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# create new config
	config=$(printf %s "$config" | jq --arg if "$interface" '. | .interface = $if')
	
	# write updated config file
	mkdir -p "$NORDVPN_DIR"
	echo "$config" > "$NORDVPN_CONFIG"
	chmod 600 "$NORDVPN_CONFIG"

	echo -e "Interface '$interface' configured."
}

# get countries from nordvpn
get_countries() {
	local response countries

	# request api for countries
	response=$(curl -s "$NORDVPN_API_COUNTRIES")
	verify_response "$response"

	# extract country name and id
	countries=$(printf %s "$response" | jq 'map({ id: .id, name: .name })')

	# return response
	printf %s "$countries"
}

get_cities() {
	local country response cities
	country=$1

	# request api for countries
	response=$(curl -s "$NORDVPN_API_COUNTRIES")
	verify_response "$response"

	# extract city name and id
	cities=$(printf %s "$response" | jq --arg cc "$country" '.[] | select(.name == $cc) | .cities | map({id: .id, name: .name})')

	# return response
	printf %s "$cities"
}

# connect to given wireguard server
connect() {
	verify_root

	local server hostname public_key config private_key wg_config wg_config_file interface wg_if_file
	server=$1

	# extract hostname
	hostname=$(printf %s "$server" | jq -r '.hostname')
	if [[ "$hostname" == "" ]] || [[ "$hostname" == "null" ]]; then
		echoexit "error: invalid server hostname."
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
	wg_config="\n[Interface]"
	wg_config+="\nPrivateKey = $private_key"
	wg_config+="\nListenPort = 51820"
	wg_config+="\n"
	wg_config+="\n[Peer]"
	wg_config+="\nPublicKey = $public_key"
	wg_config+="\nAllowedIPs = 0.0.0.0/0"
	wg_config+="\nEndpoint = $hostname:51820"
	wg_config+="\n"

	# wireguard config file name
	wg_config_file="$NORDVPN_DIR/$(printf %s "$hostname" | cut -d "." -f 1).conf"

	# write wireguard config
	mkdir -p "$NORDVPN_DIR"
	printf %b "$wg_config" > "$wg_config_file"
	chmod 600 "$wg_config_file"

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

	# log connection
	printf %b "Connecting to server '$hostname'.\n"
	
	# start wireguard interface
	rc-service "net.$interface" stop
	rc-service "net.$interface" start
}

# connect to server by id
connect_by_id() {
	verify_root

	local server_id
	server_id=$1
	
	# request api for server with given id
	response=$(curl -s "$NORDVPN_API_SERVERS_FULL&filters\[servers.id\]=$server_id")
	verify_response "$response"

	# connect to server
	connect "$(printf %s "$response" | jq '.[]')"
}

# connect to recommended server
connect_to_recommended() {
	verify_root

	local response

	# request api for recommended server
	response=$(curl -s "$NORDVPN_API_RECOMMENDED_FULL")
	verify_response "$response"

	# connect to server
	connect "$(printf %s "$response" | jq '.[]')"
}

# connect to recommended server in given country
connect_to_recommended_country() {
	verify_root

	local country country_id response
	country=$1

	# extract country id
	country_id=$(get_countries | jq -r --arg cc "$country" '.[] | select(.name == $cc) | .id')

	# request api for recommended server in given country
	response=$(curl -s "$NORDVPN_API_RECOMMENDED_FULL&filters\[country_id\]=$country_id")	
	verify_response "$response"

	# connect to server
	connect "$(printf %s "$response" | jq '.[]')"
}

# connect to recommended server in given city
connect_to_recommended_city() {
	verify_root

	local country city city_id response
	country=$1
	city=$2

	# extract city id
	city_id=$(get_cities "$country" | jq -r --arg ct "$city" '.[] | select(.name == $ct) | .id')
	
	# request api for recommended server in given city
	response=$(curl -s "$NORDVPN_API_RECOMMENDED_FULL&filters\[country_city_id\]=$city_id")
	verify_response "$response"

	# connect to server
	connect "$(printf %s "$response" | jq '.[]')"
}

# disconnect
disconnect() {
	verify_root

	local config interface

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# extract interface
	interface=$(printf %s "$config" | jq -r '.interface')
	if [[ "$interface" == "" ]] || [[ "$interface" == "null" ]]; then
		echoexit "error: invalid wireguard interface."
	fi

	# stop wireguard interface
	rc-service "net.$interface" stop
}

# main
case $1 in
	"--help")
		echo -e ""
		exit 0
		;;
	"get")
		case $2 in
			"--help")
				echo -e ""
				exit 0
				;;
			"countries")
				get_countries | jq -r '.[] | .name'
				exit 0
				;;
			"cities")
				get_cities "$3" | jq -r '.[] | .name'
				exit 0
				;;
			"")
				echo -e "Too few arguments."
				echo -e "Try 'nordvpn-rc get --help' to see available options."
				exit 1
				;;
			*)
				echo -e "Invalid argument '$2'."
				echo -e "Try 'nordvpn-rc get --help' to see available options."
				exit 1
				;;
		esac
		;;
	"set")
		case $2 in
			"--help")
				echo -e ""
				exit 0
				;;
			"token")
				set_token "$3"
				exit 0
				;;
			"interface")
				set_interface "$3"
				exit 0
				;;
			"")
				echo -e "Too few arguments."
				echo -e "Try 'nordvpn-rc set --help' to see available options."
				exit 1
				;;
			*)
				echo -e "Invalid argument '$2'."
				echo -e "Try 'nordvpn-rc set --help' to see available options."
				exit 1
				;;
		esac
		;;
	"connect")
		case $2 in
			"--help")
				echo -e ""
				exit 0
				;;
			"recommended")
				connect_to_recommended
				exit 0
				;;
			"id")
				connect_by_id "$3"
				exit 0
				;;
			"")
				echo -e "Too few arguments."
				echo -e "Try 'nordvpn-rc connect --help' to see available options."
				exit 1
				;;

			*)
				case $3 in
					"recommended")
						connect_to_recommended_country "$2"
						exit 0
						;;
					"")
						echo -e "Too few arguments."
						echo -e "Try 'nordvpn-rc connect --help' to see available options."
						exit 1
						;;
					*)
						case $4 in
							"recommended")
								connect_to_recommended_city "$2" "$3"
								exit 0
								;;
							"")
								echo -e "Too few arguments."
								echo -e "Try 'nordvpn-rc connect --help' to see available options."
								exit 1
								;;
							*)
								echo -e "Invalid argument '$4'."
								echo -e "Try 'nordvpn-rc connect --help' to see available options."
								exit 1
								;;
						esac
						;;
				esac
				;;
		esac
		;;
	"disconnect")
		disconnect
		exit 0
		;;
	"")
		echo -e "Too few arguments."
		echo -e "Try 'nordvpn-rc --help' to see available options."
		exit 1
		;;
	*)
		echo -e "Invalid argument '$1'."
		echo -e "Try 'nordvpn-rc --help' to see available options."
		exit 1
		;;
esac

