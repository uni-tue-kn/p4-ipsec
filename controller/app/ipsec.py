from datetime import datetime
from os import urandom

import simplejson as json
from scapy.layers.inet import IP
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import Ether


class IPsecS2SApplication(object):

    def __init__(self, base_controller):
        self.base_controller = base_controller

        self.allowed_traffic_codes = {"ICMP": 1}
        self.spd_codes = {"bypass": 1, "protect": 2, "discard": 3}
        self.sa = {}

        # Register application at switch controller with response code
        self.base_controller.register_application(self, [1, 2])

    def packet_in(self, reason, packet):
        # Soft timeout
        if reason == 1:
            spi = ESP(IP(Ether(packet[18:]).payload).payload).spi
            print("[+] SA (spi=" + str(spi) + "): soft timeout triggered.")

            # Renew tunnel
            self.renew_sa(spi)

        # Hard timeout
        elif reason == 2:
            spi = ESP(IP(Ether(packet[18:]).payload).payload).spi
            print("[+] SA (spi=" + str(spi) + "): hard timeout triggered; packets are dropped now.")

    def create_sa(self, local_switch, remote_switch, cipher_suite, local_endpoint_address, remote_endpoint_address,
                  target_resource, soft_packet_limit=10, hard_packet_limit=20):

        spi = urandom(4)
        spi_number = int(spi.encode('hex'), 16)

        if cipher_suite == "aes_ctr_hmac_md5":
            self.sa[spi_number] = {
                "local_switch": local_switch,
                "remote_switch": remote_switch,
                "local_endpoint_address": local_endpoint_address,
                "remote_endpoint_address": remote_endpoint_address,
                "target_resource": target_resource,
                "type": "aes_ctr_hmac_md5",
                "aes_ctr_key": urandom(20),
                "hmac_md5_key": urandom(16),
                "soft_packet_limit": soft_packet_limit,
                "hard_packet_limit": hard_packet_limit,
                "last_renewed": datetime.now(),
                "register_index_encrypt": self.base_controller.switches[local_switch]["usable_register_index"].pop(),
                "register_index_decrypt": self.base_controller.switches[remote_switch]["usable_register_index"].pop()
            }

            return spi, self.sa[spi_number]

        elif cipher_suite == "null":
            self.sa[spi_number] = {
                "local_switch": local_switch,
                "remote_switch": remote_switch,
                "local_endpoint_address": local_endpoint_address,
                "remote_endpoint_address": remote_endpoint_address,
                "target_resource": target_resource,
                "type": "null",
                "soft_packet_limit": soft_packet_limit,
                "hard_packet_limit": hard_packet_limit,
                "last_renewed": datetime.now(),
                "register_index_encrypt": self.base_controller.switches[local_switch]["usable_register_index"].pop(),
                "register_index_decrypt": self.base_controller.switches[remote_switch]["usable_register_index"].pop()
            }
            return spi, self.sa[spi_number]

    def renew_sa(self, old_spi):
        # Get required information about SA via SPI
        sa_data = self.sa[old_spi]

        # Create new keying material
        spi, sa_information = self.create_sa(sa_data["local_switch"], sa_data["remote_switch"], sa_data["type"],
                                             sa_data["local_endpoint_address"], sa_data["remote_endpoint_address"],
                                             sa_data["target_resource"])

        # Install new SA on remote switch for decryption
        table_entry = self.base_controller.p4info_helper.buildTableEntry(
            table_name="MyIngress.sad_decrypt",
            match_fields={
                "hdr.ipv4.srcAddr": sa_information["local_endpoint_address"],
                "hdr.ipv4.dstAddr": sa_information["remote_endpoint_address"],
                "hdr.esp.spi": spi
            },
            action_name="MyIngress.esp_decrypt_null",
            action_params={
                #"key": sa_information["aes_ctr_key"],
                #"key_hmac": sa_information["hmac_md5_key"],
                "register_index": sa_information["register_index_decrypt"]
            })
        self.base_controller.switches[sa_information["remote_switch"]]["connection"].WriteTableEntry(table_entry)

        # Update SA on local switch for encryption
        table_entry = self.base_controller.p4info_helper.buildTableEntry(
            table_name="MyIngress.sad_encrypt",
            match_fields={
                "hdr.ipv4.dstAddr": [sa_information["target_resource"], 32]
            },
            action_name="MyIngress.esp_encrypt_null",
            action_params={
                "spi": spi,
                "src": sa_information["local_endpoint_address"],
                "dst": sa_information["remote_endpoint_address"],
                #"key": sa_information["aes_ctr_key"],
                #"key_hmac": sa_information["hmac_md5_key"],
                "register_index": sa_information["register_index_encrypt"],
                "soft_packet_limit": sa_information["soft_packet_limit"],
                "hard_packet_limit": sa_information["hard_packet_limit"]
            })

        self.base_controller.switches[sa_information["local_switch"]]["connection"].UpdateTableEntry(table_entry)
        print("[+] SA (spi=" + str(old_spi) + ") successfully renewed; substituted by SA (spi=" +
              str(int(spi.encode('hex'), 16)) + ")")

        # TODO Unsuccessful delete of table entry
        """
        # Delete old decryption SA from remote switch
        print("Delete old encrypt SA from local switch")
        table_entry = self.base_controller.p4info_helper.buildTableEntry(
            table_name="MyIngress.sad_decrypt",
            match_fields={
                "hdr.ipv4.srcAddr": sa_information["local_endpoint_address"],
                "hdr.ipv4.dstAddr": sa_information["remote_endpoint_address"],
                "hdr.esp.spi": bytearray(old_spi)
            })
        print(table_entry)
        try:
            self.base_controller.switches[sa_information["local_switch"]]["connection"].DeleteTableEntry(table_entry)
        except Exception as e:
            print("Error in table delete", e)
        """

    def setup_sa(self, source_switch, target_switch, cipher_suite, source_switch_address, target_switch_address,
                 target_resource, soft_packet_limit, hard_packet_limit):

        # Setup ESP (S1->S2)
        spi, sa_information = self.create_sa(source_switch, target_switch, cipher_suite,
                                             source_switch_address, target_switch_address,
                                             target_resource, soft_packet_limit, hard_packet_limit)

        # (1/2) Setup SA for encryption (source switch)
        self.base_controller.build_and_install_table_entry(source_switch, {
            "table_name": "MyIngress.sad_encrypt",
            "match_fields": {
                "hdr.ipv4.dstAddr": [target_resource, 32]
            },
            "action_name": "MyIngress.esp_encrypt_null",
            "action_params": {
                #"key": sa_information["aes_ctr_key"],
                #"key_hmac": sa_information["hmac_md5_key"],
                "spi": spi,
                "src": sa_information["local_endpoint_address"],
                "dst": sa_information["remote_endpoint_address"],
                "register_index": sa_information["register_index_encrypt"],
                "soft_packet_limit": sa_information["soft_packet_limit"],
                "hard_packet_limit": sa_information["hard_packet_limit"]
            }
        })

        # (2/2) Setup SA for decryption (sink switch)
        try:
            self.base_controller.build_and_install_table_entry(target_switch, {
                "table_name": "MyIngress.sad_decrypt",
                "match_fields": {
                    "hdr.ipv4.srcAddr": source_switch_address,
                    "hdr.ipv4.dstAddr": target_switch_address,
                    "hdr.esp.spi": spi
                },
                "action_name": "MyIngress.esp_decrypt_null",
                "action_params": {
                    #"key": sa_information["aes_ctr_key"],
                    #"key_hmac": sa_information["hmac_md5_key"],
                    "register_index": sa_information["register_index_decrypt"]
                }
            })
        except Exception as e:
            print("exception in 2")
            print(e)

    def setup_tunnel(self, configuration_file_path):
        with open(configuration_file_path, 'r') as f:
            tunnel_config = json.load(f)

        # (SPD, left): BYPASS for left subnet
        self.base_controller.build_and_install_table_entry(tunnel_config["left"]["switch"], {
            "table_name": "MyIngress.spd",
            "match_fields": {
                "hdr.ipv4.dstAddr": [tunnel_config["left"]["network-resource"], 32],
                "hdr.ipv4.protocol": self.allowed_traffic_codes[tunnel_config["allowed-traffic"]]
            },
            "action_name": "MyIngress.add_spd_mark",
            "action_params": {
                "spd_mark": self.spd_codes["bypass"]
            }
        })

        # (SPD, left): PROTECT for right subnet
        self.base_controller.build_and_install_table_entry(tunnel_config["left"]["switch"], {
            "table_name": "MyIngress.spd",
            "match_fields": {
                "hdr.ipv4.dstAddr": [tunnel_config["right"]["network-resource"], 32],
                "hdr.ipv4.protocol": self.allowed_traffic_codes[tunnel_config["allowed-traffic"]]
            },
            "action_name": "MyIngress.add_spd_mark",
            "action_params": {
                "spd_mark": self.spd_codes["protect"]
            }
        })

        self.setup_sa(tunnel_config["left"]["switch"], tunnel_config["right"]["switch"],
                      tunnel_config["cipher-suite"], tunnel_config["left"]["endpoint-ipv4"],
                      tunnel_config["right"]["endpoint-ipv4"], tunnel_config["right"]["network-resource"],
                      tunnel_config["soft-packet-limit"], tunnel_config["hard-packet-limit"])

        # (SPD, right): BYPASS for right subnet
        self.base_controller.build_and_install_table_entry(tunnel_config["right"]["switch"], {
            "table_name": "MyIngress.spd",
            "match_fields": {
                "hdr.ipv4.dstAddr": [tunnel_config["right"]["network-resource"], 32],
                "hdr.ipv4.protocol": self.allowed_traffic_codes[tunnel_config["allowed-traffic"]]
            },
            "action_name": "MyIngress.add_spd_mark",
            "action_params": {
                "spd_mark": self.spd_codes["bypass"]
            }
        })

        # (SPD, right): PROTECT for peer's subnet
        self.base_controller.build_and_install_table_entry(tunnel_config["right"]["switch"], {
            "table_name": "MyIngress.spd",
            "match_fields": {
                "hdr.ipv4.dstAddr": [tunnel_config["left"]["network-resource"], 32],
                "hdr.ipv4.protocol": self.allowed_traffic_codes[tunnel_config["allowed-traffic"]]
            },
            "action_name": "MyIngress.add_spd_mark",
            "action_params": {
                "spd_mark": self.spd_codes["protect"]
            }
        })

        self.setup_sa(tunnel_config["right"]["switch"], tunnel_config["left"]["switch"],
                      tunnel_config["cipher-suite"], tunnel_config["right"]["endpoint-ipv4"],
                      tunnel_config["left"]["endpoint-ipv4"], tunnel_config["left"]["network-resource"],
                      tunnel_config["soft-packet-limit"], tunnel_config["hard-packet-limit"])

        print("[+] Successfully set up IPsec tunnel (left=" + tunnel_config["left"]["endpoint-ipv4"] + ", right="
              + tunnel_config["right"]["endpoint-ipv4"] + ")")