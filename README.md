# wg-rc

## name

wg-rc - set up a WireGuard interface simply

## synopsis

wg-quick [ up | down | save | strip ] [ CONFIG_FILE | INTERFACE ]
DESCRIPTION

This is an extremely simple script for easily bringing up a WireGuard interface, suitable for a few common use cases.

Use up to add and set up an interface, and use down to tear down and remove an interface. Running up adds a WireGuard interface, brings up the interface with the supplied IP addresses, sets up mtu and routes, and optionally runs pre/post up scripts. Running down optionally saves the current configuration, removes the WireGuard interface, and optionally runs pre/post down scripts. Running save saves the configuration of an existing interface without bringing the interface down. Use strip to output a configuration file with all wg-quick(8)-specific options removed, suitable for use with wg(8).

CONFIG_FILE is a configuration file, whose filename is the interface name followed by ‘.conf’. Otherwise, INTERFACE is an interface name, with configuration found at ‘/etc/wireguard/INTERFACE.conf’, searched first, followed by distro-specific search paths.

Generally speaking, this utility is just a simple script that wraps invocations to wg(8) and ip(8) in order to set up a WireGuard interface. It is designed for users with simple needs, and users with more advanced needs are highly encouraged to use a more specific tool, a more complete network manager, or otherwise just use wg(8) and ip(8), as usual.

# disclaimer

This project aims to keep API as close as possible to wg-quick.

This project is made entirely with shell script and it's designed to be simple, small, easily maintainable and auditable.

### Behaviour

The script creates a WireGuard interface and connects to WireGuard servers.

Therefore, this requires valid WireGuard configurations for each server.

Once the WireGuard connection is established, the script will route all network traffic through the interface.

In order to do this, firewall rules will be set in nftables as well as changes to "/etc/dispatch.conf" file.

Once the firewall rules are set, all the network traffic is routed through WireGuard.

The user can restart the connection or connect to different servers without loosing protection at any given point.

The firewall rules will only be revoked once the user explicitly disconnects from the client.

## Install

### Dependencies

You need to have the following packages installed in your system for this client to work:

```
openrc netifrc dhcpcd nftables iproute2 wireguard-tools
```

You can install these with portage by running the following command:

```
emerge -av sys-apps/openrc net-misc/netifrc net-misc/dhcpcd net-firewall/nftables sys-apps/iproute2 net-vpn/wireguard-tools
```

You also need to make sure your kernel has the WireGuard feature enabled, as well as the firewall feature for nftables.

### Client

You can copy the script into any directory that's in your PATH variable, like the following:

```
cp wg-rc.sh /usr/bin/wg-rc
```

Make sure the file is executable by running:

```
chmod +x /usr/bin/wg-rc
```

Then run the commands normally, like:

```
wg-rc --help
```

## Creating Interface

### Init Script

You need to create a WireGuard interface before connecting to any server with this client.

In Netifrc, this requires creating an init script for the interface in folder "/etc/init.d".

For example, for interface "wg0", run the following command:

```
ln -s /etc/init.d/net.lo /etc/init.d/net.wg0
```

### Configuration

You also need to configure the newly created interface to use WireGuard.

In order to do that, you need to add some entries to "/etc/conf.d/net".

The first entry is "wireguard_\<interface\>". This is the path to the WireGuard config file.

For this client to work, the path to the config file should be "/etc/wireguard/\<interface\>.conf"

OBS.: You do not need to create the actual config file, the client will do that programmatically later on.

The second entry is "config_\<interface\>". This is the local ip address of your interface.

You can choose any ip address that doesn't conflict with your local network.

For example, for interface "wg0", the entries should look like:

```
wireguard_wg0="/etc/wireguard/wg0.conf"
config_wg0="10.5.0.2/32"
```

After the above is completed successfully, you should be able to use your interface.

OBS.: Do not add any extra configuration besides these two unless you really know what you are doing. Adding extra configuration can make this client uneffective or unusable.

### Using the Interface

Now you just need to add your configured interface to the client.

For example, for interface "wg0", run the following command:

```
nordvpn-rc set interface wg0
```

The choosen interface will now be used to establish WireGuard connections to NordVPN's servers.

## Authentication

This client requires the use of a valid NordVPN Access Token to connect to the servers.

To obtain your token, you can follow the [official instructions](https://support.nordvpn.com/Connectivity/Linux/1905092252/How-to-log-in-to-NordVPN-on-Linux-with-a-token.htm) available on their blog.

Once you have your token, you can use it with this client by running:

```
nordvpn-rc set token "your-token-goes-here"
```

The above command will verify the validity of your token before setting it.

It will also fetch and store a WireGuard private-key, which is used to connect to the servers.

## Connecting

With this client, one can easily connect to the server recommended by NordVPN in any given country or city.

For example, for the recommended server in france, run the following command:

```
nordvpn-rc cr france
```

For the recommended server in warsaw:

```
nordvpn-rc cr poland warsaw
```

To see other connection options, run:

```
nordvpn-rc connect --help
```

