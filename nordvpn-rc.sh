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

CONFIG_FILE="/etc/wireguard/nordvpn.json"
NORDVPN_API_CREDENTIALS="https://api.nordvpn.com/v1/users/services/credentials"

# Print error message for invalid token and exit
exit_invalid_token() {
	echo -e "You have not set a valid nordvpn access token."
	echo -e "Please follow the instructions provided in their website to obtain a new token: https://support.nordvpn.com/Connectivity/Linux/1905092252/How-to-log-in-to-NordVPN-on-Linux-with-a-token.htm"
	echo -e "Once you have copied your token, you can set it in nordvpn-rc by running 'nordvpn-rc set --token <your-token-goes-here>'."
	exit 1
}

# set nordvpn access token in the config file
set_token() {
	exit 1	
}

# get wireguard private key from nordvpn and put it in the config file
update_private_key() {
	local config token response errors private_key
	
	# read config file
	config=$(cat "$CONFIG_FILE")

	# get nordvpn token from config file
	token=$(printf %s "$config" | jq --raw-output '.token')

	# request api for credentials
	response=$(curl -s "$NORDVPN_API_CREDENTIALS" -u "token:$token")

	# check for errors in response
	errors=$(printf %s "$response" | jq --raw-output '.errors')
	if [[ "$errors" == "" ]]; then
		echoexit "api_error: $errors"
	fi
	
	# get private key from response
	private_key=$(printf %s "$response" | jq --raw-output '.nordlynx_private_key')
	if [[ "$private_key" == "" ]]; then
		echoexit "api_error: private key not found"
	fi

	# write updated config file
	echo "$config" > "$CONFIG_FILE"
}

# main


