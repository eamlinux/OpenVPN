### 首先安装依赖
```
sudo apt install automake autoconf libtool m4 liblz4-tool liblz4-dev liblzo2-dev libssl-dev libpam0g-dev libcmocka-dev make
```
### 下载```OpenVPN```源码
```bash
wget https://swupdate.openvpn.org/community/releases/openvpn-2.5.4.tar.gz
tar xf openvpn-2.5.4.tar.gz
cd openvpn-2.5.4
./configure
make
mv src/openvpn/openvpn /usr/local/bin/
chown root:root /usr/local/bin/openvpn
chmod 0755 /usr/local/bin/openvpn
setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/openvpn
```
以上在```root```用户下进行，普通用户编译安装时加上```sudo```

### 安装iptables防火墙
```shell
apt update
apt upgrade
apt-get install -y iptables openssl wget ca-certificates curl
```
### 创建证书
```shell
wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz
mkdir -p /opt/easy-rsa /etc/openvpn
tar zxf ./EasyRSA-3.0.8.tgz --strip-components=1 --directory /opt/easy-rsa
cd /opt/easy-rsa
echo "set_var EASYRSA_ALGO ec" >vars
echo "set_var EASYRSA_CURVE secp521r1" >>vars
echo "set_var EASYRSA_REQ_CN cn_server" >>vars
./easyrsa init-pki
./easyrsa --batch build-ca nopass
./easyrsa build-server-full server nopass
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
openvpn --genkey --secret /etc/openvpn/tls-crypt.key
cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
chmod 644 /etc/openvpn/crl.pem
```
### 创建```server.conf```
```bash
port 1194
proto udp
dev tun0
dev-type tun
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.10.10.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "redirect-gateway def1 bypass-dhcp"
dh none
ecdh-curve secp521r1
tls-crypt tls-crypt.key
crl-verify crl.pem
ca ca.crt
cert server.crt
key server.key
auth SHA512
cipher AES-256-GCM
data-ciphers AES-256-GCM
tls-server
tls-version-min 1.3
tls-ciphersuites TLS_AES_256_GCM_SHA384
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3
duplicate-cn
explicit-exit-notify 1
```
### 创建配置中的文件路径
```
# mkdir -p /etc/openvpn/ccd /var/log/openvpn
```
### 创建开机启动```nano /etc/systemd/system/openvpn@.service```
```bash
[Unit]
Description=OpenVPN connection to %i
# Before=systemd-user-sessions.service
After=network-online.target
Wants=network-online.target
Documentation=man:openvpn(8)

[Service]
Type=notify
PrivateTmp=true
WorkingDirectory=/etc/openvpn
ExecStart=/usr/local/bin/openvpn --daemon ovpn-%i --status /etc/openvpn/%i.status 10 --cd /etc/openvpn --config /etc/openvpn/%i.conf --writepid /etc/openvpn/%i.pid
PIDFile=/etc/openvpn/%i.pid
KillMode=process
CapabilityBoundingSet=CAP_IPC_LOCK CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETUID CAP_SYS_CHROOT CAP_DAC_OVERRIDE CAP_AUDIT_WRITE
#LimitNPROC=100
DeviceAllow=/dev/null rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=true
ProtectHome=true
RestartSec=5s
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
### 创建防火墙转发配置```iptables-openvpn.service```
```bash
[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/openvpn/add-openvpn-rules.sh
ExecStop=/etc/openvpn/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```
### 添加防火墙转发规则```/etc/openvpn/add-openvpn-rules.sh```
```bash
#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.10.10.0/24 -o ens3 -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i ens3 -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o ens3 -j ACCEPT
iptables -I INPUT 1 -i ens3 -p udp --dport 1194 -j ACCEPT
# ens3是当前系统外网网卡名称，如不是自行修改
```
### 清除防火墙转发规则```/etc/openvpn/rm-openvpn-rules.sh```
```bash
#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o ens3 -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i ens3 -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o ens3 -j ACCEPT
iptables -D INPUT -i ens3 -p udp --dport 1194 -j ACCEPT
# ens3是当前系统外网网卡名称，如不是自行修改
```
### 添加运行权限
```
# chmod +x /etc/openvpn/add-openvpn-rules.sh
# chmod +x /etc/openvpn/rm-openvpn-rules.sh
```
### 开启ip转发
```bash
# echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
# echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf #如果需要ipv6
```
### 创建客户端证书
```bash
# cd /opt/easy-rsa
# ./easyrsa build-client-full client nopass
```
### 创建客户端ovpn配置
```json
client
proto tcp-client
remote $server_ip $port
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server name
auth SHA512
auth-nocache
cipher AES-256-GCM
tls-client
tls-version-min 1.3
tls-ciphersuites TLS_AES_256_GCM_SHA384
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3
<ca>
# 粘贴CA证书内容
</ca>
<cert>
# 粘贴/opt/easy-rsa/pki/issued/client.crt内容
</cert>
<key>
# 粘贴/opt/easy-rsa/pki/private/client.key内容
</key>
<tls-crypt>
# 粘贴tls-crypt.key内容
</tls-crypt>
```
将证书导入客户端即可！
### 启动服务器
```shell
# systemctl daemon-reload
# systemctl --now enable openvpn@server
# systemctl --now enable iptables-openvpn
```
