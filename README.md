# nordvpn-rc

NordVPN client using WireGuard and Netifrc

## Install

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

You need to create a WireGuard interface before connecting to any server with this client.

In Netifrc, this requires creating an init script for the interface in folder "/etc/init.d".

For example, for interface "wg0", run the following command:

```
ln -s /etc/init.d/net.wg0 /etc/init.d/net.lo
```

You also need to configure the newly created interface to use WireGuard.

In order to do that, you need to add some entries to "/etc/conf.d/net".

The first entry is "wireguard_\<interface\>". This is the path to the WireGuard config file.

For this client to work, the path to the config file should be "/etc/wireguard/\<interface\>.conf"

The second entry is "config_\<interface\>". This is the local ip address of your interface.

You can choose any ip address that doesn't conflict with your local network.

For example, for interface "wg0", the entries should look like:

```
wireguard_wg0="/etc/wireguard/wg0.conf"
config_wg0="10.5.0.2/32"
```

After the above is completed successfully, you should be able to use your interface.

You just need to add your interface to the client.

For example, for interface "wg0", run the following command:

```
nordvpn-rc set interface wg0
```

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

With this client, one can easily connect to the server recommended by NordVPN in a given country or city.

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

