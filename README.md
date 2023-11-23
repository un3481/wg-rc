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

In Netifrc, this requires crating an init script for the interface in folder "/etc/init.d".

For example, for interface "wg0", run the following command:
```
ln -s /etc/init.d/net.wg0 /etc/init.d/net.lo
```

You also need to configure the newly created interface to use wireguard.
In order to do that, you need to add some entries to "/etc/conf.d/net".

The first entry is "wireguard_\<interface\>". This is the path to the wireguard config file.
For this client to work, the path to the config file should be "/etc/wireguard/<interface>.conf"

The second entry is "config_\<interface\>". This is the local ip address of your interface.
You can choose any ip address that doesn't conflict with your local network.

For example, for interface "wg0", the entries should look like:
```
wireguard_wg0="/etc/wireguard/wg0.conf"
config_wg0="10.5.0.2/32"
```

After all the above is completed successfully, you should be able to use your interface.
You just need to add your interface to the client.

For example, for interface "wg0", run the following command:
```
nordvpn-rc set interface wg0
```

