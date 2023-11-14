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

WIREGUARD_DIR="/etc/wireguard"
NORDVPN_DIR="$WIREGUARD_DIR/nordvpn"
NORDVPN_CONFIG="$NORDVPN_DIR/config.json"

NORDVPN_API_BASE="https://api.nordvpn.com"
NORDVPN_API_CURRENT_USER="$NORDVPN_API_BASE/v1/users/current"
NORDVPN_API_CREDENTIALS="$NORDVPN_API_BASE/v1/users/services/credentials"

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
	response=$(curl -s "$NORDVPN_API_CURRENT_USER" -u "token:$token")

	# check for errors in response
	valid="valid"
	if [[ "$response" == "" ]]; then
		exit_invalid_token
	fi
	errors=$(printf %s "$response" | jq --raw-output '.errors')
	if [[ "$errors" != "" ]] && [[ "$errors" != "null" ]]; then
		exit_invalid_token
	fi
}

# print error message for invalid token and exit
exit_invalid_token() {
	echo -e "You have not set a valid nordvpn access token."
	echo -e "Please follow the instructions provided in their website to obtain a new token: https://support.nordvpn.com/Connectivity/Linux/1905092252/How-to-log-in-to-NordVPN-on-Linux-with-a-token.htm"
	echo -e "Once you have copied your token, you can set it in nordvpn-rc by running 'nordvpn-rc set --token <your-token-goes-here>'."
	exit 1
}

# get wireguard private key from nordvpn and put it in the config file
# requires superuser privileges
update_private_key() {
	verify_root

	local config token response errors private_key
	
	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")

	# get nordvpn token from config file
	token=$(printf %s "$config" | jq --raw-output '.token')

	# verify token
	verify_token "$token"

	# request api for credentials
	response=$(curl -s "$NORDVPN_API_CREDENTIALS" -u "token:$token")

	# check for errors in response
	if [[ "$response" == "" ]]; then
		echoexit "api_error: API call returned nothing."
	fi	
	errors=$(printf %s "$response" | jq --raw-output '.errors')
	if [[ "$errors" != "" ]] && [[ "$errors" != "null" ]]; then
		echoexit "api_error: API replied with errors: '$errors'."
	fi

	# get private key from response
	private_key=$(printf %s "$response" | jq --raw-output '.nordlynx_private_key')
	if [[ "$private_key" == "" ]]; then
		echoexit "api_error: API did not provide a valid private_key."
	fi

	# create new config
	config=$(printf %s "$config" | jq --arg key "$private_key" --raw-output '. | .private_key = $key')

	# write updated config file
	mkdir -p "$NORDVPN_DIR"
	echo "$config" > "$NORDVPN_CONFIG"
	chmod 600 "$NORDVPN_CONFIG"
	
}

# set nordvpn access token in the config file
# requires superuser privileges
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
	config=$(printf %s "$config" | jq --arg tok "$token" --raw-output '. | .token = $tok')
	
	# write updated config file
	mkdir -p "$NORDVPN_DIR"
	echo "$config" > "$NORDVPN_CONFIG"
	chmod 600 "$NORDVPN_CONFIG"

	# update credentials
	update_private_key
}

# set wireguard interface in the config file
# requires superuser privileges
set_interface() {
	verify_root
	
	local config interface
	interface=$1

	# check the string provided by user
	if [[ "$interface" == "" ]]; then
		echoexit "error: Attempting to set invalid interface."
	fi

	# read config file
	config=$(cat "$NORDVPN_CONFIG" 2>/dev/null || echo "{}")
	
	# create new config
	config=$(printf %s "$config" | jq --arg if "$interface" --raw-output '. | .interface = $if')
	
	# write updated config file
	mkdir -p "$NORDVPN_DIR"
	echo "$config" > "$NORDVPN_CONFIG"
	chmod 600 "$NORDVPN_CONFIG"
}

# main


