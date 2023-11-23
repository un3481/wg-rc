# nordvpn-rc

NordVPN client using WireGuard and Netifrc.

This project is made entirely with shell script and it's designed to be simple, small, easily maintainable and auditable. 

### Behaviour

The client uses a WireGuard interface to connect to NordVPN's NordLynx (WireGuard) servers.

Therefore, the client requires a valid WireGuard private-key provided by NordVPN.

For the client to obtain a private-key, the user must provide valid NordVPN credentials (Access Token).

Once the WireGuard connection is established, the client will route all network traffic through the interface.

In order to do this, the client will change firewall rules in nftables as well as edit "/etc/dispatch.conf" file.

Once the firewall rules are set, all the network traffic is routed through WireGuard.

The user can restart the connection or connect to different servers without loosing protection at any given point.

The firewall rules will only be revoked once the user explicitly disconnects from the client.

## Install

### Dependencies

You need to have the following packages installed in your system for this client to work:

```
openrc netifrc dhcpcd nftables iproute2 wireguard-tools curl jq
```

You can install these with portage by running the following command:

```
emerge -av sys-apps/openrc net-misc/netifrc net-misc/dhcpcd net-firewall/nftables sys-apps/iproute2 net-vpn/wireguard-tools net-misc/curl app-misc/jq
```

You also need to make sure your kernel has the WireGuard feature enabled, as well as the firewall feature for nftables.

### Client

You can copy the script into any directory that's in your PATH variable, like the following:

```
cp nordvpn-rc.sh /usr/bin/nordvpn-rc
```

Make sure the file is executable by running:

```
chmod +x /usr/bin/nordvpn-rc
```

Then run the commands normally, like:

```
nordvpn-rc --help
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

