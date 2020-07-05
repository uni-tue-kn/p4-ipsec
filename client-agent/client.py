#!/usr/bin/env python3

import grpc
import argparse
import sys
import threading
import time
import queue
import atexit

# import generated proto classes
import client_pb2
import client_pb2_grpc

import tunnel_handler
import netlink_monitor
import tunnel_exceptions

# define certificate paths
ca_path = '../tools/certstrap/out/P4_VPN_Test_CA.crt'
cert_path = '../tools/certstrap/out/client.test.crt'
key_path = '../tools/certstrap/out/client.test.key'

# process command line options
parser = argparse.ArgumentParser()
parser.add_argument('-i', default='eth0', help='interface, default is "eth0"')
parser.add_argument('-v', default=False, action='store_const', const=True, help='verbose')
parser.add_argument('--simulate', default=False, action='store_const', const=True,
                    help='do not set up VPN, print commands instead')
parser.add_argument('--controller', default='localhost:50051',
                    help='ip and port of controller, default is "localhost:50051"')
args = parser.parse_args()
interface = vars(args)['i']
verbose = vars(args)['v']
simulate = vars(args)['simulate']
controller = vars(args)['controller']
print('[*] using interface ' + interface)
print('[*] simulate: ' + str(simulate))
print('[*] controller: ' + str(controller))

# prepare tls creds
try:
    with open(ca_path, 'rb') as ca_file:
        ca = ca_file.read()
except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
    print(e)
    sys.exit("[E] Error opening CA file")

try:
    with open(cert_path, 'rb') as cert_file:
        cert = cert_file.read()
except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
    print(e)
    sys.exit("[E] Error opening cert file")

try:
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
except (FileNotFoundError, PermissionError, IsADirectoryError) as e:
    print(e)
    sys.exit("[E] Error opening key file")

# create grpc channel and stub
client_creds = grpc.ssl_channel_credentials(ca, key, cert)
channel = grpc.secure_channel(controller, client_creds)
stub = client_pb2_grpc.TunnelServiceStub(channel)

# queues for netlink_monitor
renew_q = queue.Queue()

nl_monitor = netlink_monitor.NetlinkMonitor(renew_q, verbose)
nl_monitor_t = threading.Thread(target=nl_monitor.monitor_msg_expire)
nl_monitor_t.daemon = True
nl_monitor_t.start()

# dictionary containing all active tunnels
# key = domain name
# value = tunnel parameters as a tuple consisting of local ip, gateway ip, subnet, spi out and spi in
active_tunnels = {}

# delete SAD, SPD and routes when the client is stopped
th = tunnel_handler.TunnelHandler(verbose, interface, simulate)
atexit.register(th.delete_rules, active_tunnels, stub)

try:
    while True:
        while not request_q.empty():
            domain = request_q.get()
            if domain not in active_tunnels:
                try:
                    tunnel = th.request_tunnel(domain, stub)
                except tunnel_exceptions.RequestDenied:
                    print('[*] tunnel with target ' + domain + ' denied')
                except tunnel_exceptions.TargetUnknown:
                    print('[*] target ' + domain + ' not known to controller')
                else:
                    active_tunnels[domain] = tunnel
            elif verbose:
                print('[v] tunnel already active, not requesting: ' + domain)

        while not renew_q.empty():
            saddr, daddr, spi = renew_q.get()

            for domain in active_tunnels:
                # tunnel can either be inbound or outbound
                if (active_tunnels[domain][0] == saddr and active_tunnels[domain][1] == daddr and
                    active_tunnels[domain][3] == spi) or (
                        active_tunnels[domain][0] == daddr and active_tunnels[domain][1] == saddr and
                        active_tunnels[domain][4] == spi):
                    try:
                        tunnel = th.renew_tunnel(active_tunnels[domain], domain, stub)
                    except tunnel_exceptions.RequestDenied:
                        print('[*] tunnel with target ' + domain + ' denied')
                        del(active_tunnels[domain])
                    except tunnel_exceptions.TargetUnknown:
                        print('[*] target ' + domain + ' not known to controller')
                        del(active_tunnels[domain])
                    except tunnel_exceptions.TunnelUnknown:
                        print('[*] tunnel not known to controller')
                        del(active_tunnels[domain])
                    else:
                        active_tunnels[domain] = tunnel
                elif verbose:
                    print('[v] tunnel does not exist, not deleting')

        time.sleep(1)
except KeyboardInterrupt:
    print('[*] shutting down')
    sys.exit(0)
