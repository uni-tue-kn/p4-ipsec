import os
import netifaces
import sys

import client_pb2
import tunnel_exceptions

class TunnelHandler:
    # define command templates
    state_template = 'ip xfrm state add src {0} dst {1} proto esp spi 0x{2} reqid 0x{2} mode tunnel auth "{3}" 0x{4} enc "{5}" 0x{6} limit packet-soft {7} limit time-soft {8}'
    state_template_null = 'ip xfrm state add src {0} dst {1} proto esp spi 0x{2} reqid 0x{2} mode tunnel auth "{3}" 0x{4} enc "{5}" "" limit packet-soft {7} limit time-soft {8}'
    state_template_aead = 'ip xfrm state add src {0} dst {1} proto esp spi 0x{2} reqid 0x{2} mode tunnel aead "{5}" 0x{6} 128 limit packet-soft {7} limit time-soft {8}'
    state_del_template = 'ip xfrm state del src {0} dst {1} proto esp spi 0x{2}'
    policy_template = 'ip xfrm policy add src {0} dst {1} dir {2} tmpl src {3} dst {4} proto esp reqid 0x{5} mode tunnel'
    policy_del_template = 'ip xfrm policy delete src {0} dst {1} dir {2}'
    state_flush = 'ip xfrm state flush'
    policy_flush = 'ip xfrm policy flush'
    route_template = 'ip route add {0} dev {1} src {2}'
    route_del_template = 'ip route delete {0} src {1}'

    def __init__(self, verbose, interface, simulate):
        self.verbose = verbose
        self.interface = interface
        self.simulate = simulate

    def algo_to_xfrm(self, x):
        """takes algorithm from controller response and returns equivalent representation for ip xfrm

        :param x: algorithm in IPsec-Tools format
        :return: algorithm in xfrm format
        """
        return {
            'aes-ctr': 'rfc3686(ctr(aes))',
            'AES-GCM': 'rfc4106(gcm(aes))',
            'hmac-md5': 'hmac(md5)',
            'hmac-sha256': 'hmac(sha256)',
            'null': 'ecb(cipher_null)',
            'null-auth': 'digest_null'
        }[x]

    def delete_rules(self, tunnels, stub):
        """flushes SPD and SAD, deletes routes

        :param tunnels: dictionary containing all active tunnels
        """
        try:
            local_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            print(e)
            sys.exit('[E] can\'t get ip of interface ' + self.interface)

        for domain in tunnels:
            self.send_tunnel_delete(domain, local_ip, stub)
            command = self.route_del_template.format(tunnels[domain][2], tunnels[domain][0])

            if self.verbose:
                print('[v] delete route for ' + domain)
                print('[v] ' + command)

            if self.simulate and not self.verbose:
                print('[s] ' + command)

            if not self.simulate:
                os.system(command)

        if self.simulate:
            print('[s] ' + self.state_flush)
            print('[s] ' + self.policy_flush)
            return

        if self.verbose:
            print('[v] ' + self.state_flush)
            print('[v] ' + self.policy_flush)

        os.system(self.state_flush)
        os.system(self.policy_flush)


    def run_command(self, c):
        """executes command

        Executes a given command.
        If the '--simulate' command-line option is used, the command is only printed and not executed.
        If the '-v' command-line option is used, the command is printed before it is executed.
        If the execution fails, the SPD and SAD are flushed and the program will be stopped.
        :param c: command
        """
        if self.simulate:
            print('[s] ' + c)
            return

        if self.verbose:
            print('[v] ' + c)

        if os.system(c) != 0:
            print('Error running command: ' + c)
            sys.exit()

    def add_tunnel(self, response):
        """adds a new tunnel

        :param response: gRPC response send by the controller
        :return: tunnel parameters as a tuple consisting of local ip, gateway ip, subnet, spi out and spi in
        """

        if self.verbose:
            print('[v] tunnel details:')
            print('tunnelID: ' + str(response.tunnelID))
            print('gateway IP: ' + response.left)
            print('left subnet: ' + response.leftSubnet)
            print('inbound SPI: 0x' + response.spiIn.hex())
            print('inbound encryption algorithm: ' + response.encryptionAlgoIn)
            print('inbound encryption key: 0x' + response.encryptionKeyIn.hex())
            print('inbound authentication algorithm: ' + response.authenticationAlgoIn)
            print('inbound authentication key: 0x' + response.authenticationKeyIn.hex())
            print('inbound soft packet limit: ' + str(response.softPacketLimitIn))
            print('inbound soft time limit: ' + str(response.softTimeLimitIn))
            print('outbound SPI: 0x' + response.spiOut.hex())
            print('outbound encryption algorithm: ' + response.encryptionAlgoOut)
            print('outbound encryption key: 0x' + response.encryptionKeyOut.hex())
            print('outbound authentication algorithm: ' + response.authenticationAlgoOut)
            print('outbound authentication key: 0x' + response.authenticationKeyOut.hex())
            print('outbound soft packet limit: ' + str(response.softPacketLimitOut))
            print('outbound soft time limit: ' + str(response.softTimeLimitOut))

        # turn algorithms into ip xfrm format
        algo_enc_in = self.algo_to_xfrm(response.encryptionAlgoIn)
        algo_enc_out = self.algo_to_xfrm(response.encryptionAlgoOut)
        algo_auth_in = self.algo_to_xfrm(response.authenticationAlgoIn)
        algo_auth_out = self.algo_to_xfrm(response.authenticationAlgoOut)

        if (algo_enc_in == 'rfc4106(gcm(aes))'):
            state_template_in = self.state_template_aead
        elif (algo_enc_in == 'ecb(cipher_null)'):
            state_template_in = self.state_template_null
        else:
            state_template_in = self.state_template

        if (algo_enc_out == 'rfc4106(gcm(aes))'):
            state_template_out = self.state_template_aead
        elif (algo_enc_out == 'ecb(cipher_null)'):
            state_template_out = self.state_template_null
        else:
            state_template_out = self.state_template


        try:
            local_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            print(e)
            sys.exit('[E] can\'t get ip of interface ' + self.interface)

        # assemble iproute2 commands
        # SA
        state_out = state_template_out.format(local_ip, response.left, response.spiOut.hex(), algo_auth_out,
                                               response.authenticationKeyOut.hex(), algo_enc_out,
                                               response.encryptionKeyOut.hex(), response.softPacketLimitOut,
                                               response.softTimeLimitOut)
        state_in = state_template_in.format(response.left, local_ip, response.spiIn.hex(), algo_auth_in,
                                              response.authenticationKeyIn.hex(), algo_enc_in,
                                              response.encryptionKeyIn.hex(), response.softPacketLimitIn,
                                              response.softTimeLimitIn)

        # SP
        policy_out = self.policy_template.format(local_ip, response.leftSubnet, 'out', local_ip, response.left,
                                                 response.spiOut.hex())
        policy_in = self.policy_template.format(response.leftSubnet, local_ip, 'in', response.left, local_ip,
                                                response.spiIn.hex())

        # route
        route = self.route_template.format(response.leftSubnet, self.interface, local_ip)

        self.run_command(state_out)
        self.run_command(state_in)
        self.run_command(policy_out)
        self.run_command(policy_in)
        self.run_command(route)

        return local_ip, response.left, response.leftSubnet, response.spiOut.hex(), response.spiIn.hex()

    def delete_tunnel(self, local_ip, remote_ip, remote_sub, spiOut, spiIn):
        """deletes tunnel

        :param local_ip: local IP address
        :param remote_ip: gateway IP address
        :param remote_sub: tunnel subnet
        :param spiOut: outbound SPI
        :param spiIn: inbound SPI
        """

        if self.verbose:
            print('[v] deleting tunnel')

        delete_state_out = self.state_del_template.format(local_ip, remote_ip, spiOut)
        delete_state_in = self.state_del_template.format(remote_ip, local_ip, spiIn)
        delete_policy_out = self.policy_del_template.format(local_ip, remote_sub, 'out')
        delete_policy_in = self.policy_del_template.format(remote_sub, local_ip, 'in')
        delete_route = self.route_del_template.format(remote_sub, local_ip)

        self.run_command(delete_state_out)
        self.run_command(delete_state_in)
        self.run_command(delete_policy_out)
        self.run_command(delete_policy_in)
        self.run_command(delete_route)

    @staticmethod
    def send_request(target, local_ip, stub, renew):
        """sends tunnel request to controller

        :param stub: gRPC stub
        :param local_ip: the client's IP address
        :param renew: True if tunnel is to be renewed, False if new tunnel is to be requested
        :return: gRPC response send by the controller
        """

        # create request
        tunnel_request = client_pb2.request(target=target, clientIP=local_ip)

        # get response
        if renew:
            print('[*] sending renew request for ' + target)
            response = stub.renewTunnelByIP(tunnel_request)
        else:
            print('[*] sending request for ' + target)
            response = stub.requestTunnelByIP(tunnel_request)

        print('[*] response received')
        return response

    @staticmethod
    def send_tunnel_delete(target, local_ip, stub):
        """sends tunnel delete request to controller

        :param stub: gRPC stub
        :param local_ip: the client's IP address"""

        tunnel_delete = client_pb2.request(target=target, clientIP=local_ip)
        print('[*] asking conroller to delete tunnel to ' + target)
        stub.deleteTunnelByIP(tunnel_delete)

    def request_tunnel(self, target, stub):
        """request and add a new tunnel

        :param target: string containing the tunnel's target (e.g. IP address)
        :param stub: gRPC stub
        :return: new tunnel parameters as a tuple consisting of local ip, gateway ip, subnet, spi out and spi in
        """

        try:
            local_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            print(e)
            sys.exit('[E] can\'t get ip of interface ' + self.interface)

        new_tunnel = self.send_request(target, local_ip, stub, False)
        if not new_tunnel.status.success:
            if new_tunnel.status.error == 'target unknown':
                raise tunnel_exceptions.TargetUnknown()
            if new_tunnel.status.error == 'request denied':
                raise tunnel_exceptions.RequestDenied()

        return self.add_tunnel(new_tunnel)

    def renew_tunnel(self, tunnel, target, stub):
        """renews a tunnel

        Sends a request for the new tunnel, deletes the old tunnel and adds the new tunnel
        :param tunnel: tunnel parameters as a tuple consisting of local ip, gateway ip, subnet, spi out and spi in
        :param target: string containing the tunnel's target (e.g. IP address)
        :param stub: gRPC stub
        :return: new tunnel parameters as a tuple consisting of local ip, gateway ip, subnet, spi out and spi in
        """

        try:
            local_ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            print(e)
            sys.exit('[E] can\'t get ip of interface ' + self.interface)

        print('[*] renewing tunnel for ' + target)
        new_tunnel = self.send_request(target, local_ip, stub, True)
        self.delete_tunnel(tunnel[0], tunnel[1], tunnel[2], tunnel[3], tunnel[4])
        if not new_tunnel.status.success:
            if new_tunnel.status.error == 'target unknown':
                raise tunnel_exceptions.TargetUnknown()
            if new_tunnel.status.error == 'request denied':
                raise tunnel_exceptions.RequestDenied()
            if new_tunnel.status.error == 'tunnel unknown':
                raise tunnel_exceptions.TunnelUnknown()

        return self.add_tunnel(new_tunnel)
