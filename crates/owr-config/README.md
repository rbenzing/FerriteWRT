# owr-config

Typed, versioned config (`/etc/ferritewrt/config.toml`, mode 0600). Unknown keys are rejected
and every problem is reported with a field path (`network.vlans[1].ports[0]`).
`Config::defaults_for(&board)` builds the first-boot config (no users, no APs).

Rules: `schema` and each radio's `width_mhz` are required (the sensible width depends on the
band, so there is no serde default; `Config::defaults_for` picks 20 MHz on 2.4 GHz and 80 MHz on
5/6 GHz); each port is used once across lan/wan/vlans; LAN, VLAN and static-WAN subnets must not
overlap; DHCP pools (enabled or not) fit the subnet and exclude the router; forward/lease IPs lie
inside the LAN or a VLAN; once any user exists one enabled `admin` is required; passphrases are
8..=63 printable ASCII; `password_hash` is an argon2id PHC string with bounded cost (m 8 MiB..1 GiB,
t 1..=10, p 1..=16, salt >= 8 bytes, hash >= 16 bytes); the redacted placeholder `***` is never a
valid secret; PPPoE username/service use `[A-Za-z0-9._@+:/-]` and the password printable ASCII without
`"` or `\`; lists are bounded (32 users, 256 rules, 256 port forwards, 1024 static leases, 32 SSH
keys of at most 4096 characters). Against a board (`validate_against`): WAN is a `wan` port, LAN/VLAN
ports are `lan` ports, APs sit on enabled radios, and fixed channels fit the width (5 GHz 80/160 MHz
blocks) and country (no 2.4 GHz channels 12-13 in `US`).

Parse errors name the field path but never echo the offending value. `Store::save`/`load` check
the config only against itself; use `save_for`/`load_for`/`load_or_default` to also check it against
the board. The file is created 0600 in a 0700 directory, capped at 1 MiB on load, and an older
schema is migrated and rewritten on load.

Annotated Flint 2 example (parsed and validated by the unit tests):

```toml
schema = 1
[system]
hostname = "flint2"
timezone = "Europe/Berlin"           # IANA name; default "UTC"
[[users]]
name = "admin"
role = "admin"                       # admin | viewer
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFy"
[network.lan]
ports = ["lan1", "lan2", "lan3", "lan4"]
ipv4 = "192.168.8.1/24"              # router address + prefix; also ipv6 = disabled | ula
dhcp = { enabled = true, start = 100, limit = 150, lease = "12h" }
[network.wan]
port = "wan"
proto = { type = "dhcp" }            # or "static" (ipv4, gateway, dns) / "pppoe"; also ipv6, mtu
[[network.vlans]]
name = "iot"                         # ^[a-z][a-z0-9_]{0,11}$
id = 20                              # 1..=4094
ports = ["lan5"]
ipv4 = "10.20.0.1/24"
dhcp = { enabled = true, start = 50, limit = 100, lease = "1h" }
isolated = true                      # no forwarding to the LAN
[[wireless.radios]]
id = "radio0"                        # board radio id; 2.4 GHz allows 20/40 MHz
width_mhz = 20                       # required: 20 | 40 | 80 | 160
channel = "auto"                     # "auto" or a channel number
country = "DE"
[[wireless.radios]]
id = "radio1"                        # 5 GHz, up to 160 MHz
width_mhz = 80
country = "DE"
[[wireless.aps]]
radio = "radio1"
ssid = "flint2"
security = { type = "wpa3_sae", passphrase = "correct horse battery" }  # open | wpa2_psk | wpa3_sae | wpa2_wpa3_mixed
network = "lan"                      # "lan" or a VLAN name
[firewall]
hw_offload = true                    # WED/flowtable; also default_wan_input = drop | reject
[[firewall.port_forwards]]
name = "web"
proto = "tcp"                        # tcp | udp | tcp_udp
wan_port = "8080-8081"               # "80" or "a-b"
dest_ip = "192.168.8.50"
dest_port = 80
[services.api]
bind = "lan"                         # lan | lan_and_vlans; also port, session_ttl = "30m"
```
