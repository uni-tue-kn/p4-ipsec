import binascii
import threading

import simplejson as json
import struct

import p4runtime_lib.bmv2
import p4runtime_lib.helper


class BaseController:
    def __init__(self, p4info_file_path, bmv2_file_path):
        self.switches = {}
        self.port_queues = {}
        self.port_threads = {}
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
        self.p4info_file_path = p4info_file_path
        self.bmv2_file_path = bmv2_file_path
        self.packet_in_threads = []
        self.application_mapping = {}

    def add_switch_connection(self, name, address, device_id, type='bmv2',
                              crypto_address=None, debug=False, notification_socket=None,
                              num_ports=15):

        sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(name=name, address=address, device_id=device_id, debug=debug)
        self.switches[sw.name] = {"connection": sw, "usable_register_index": set(range(1024))}

    def startup(self):
        for switch_name, switch_data in self.switches.items():
            switch_data["connection"].SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                                                  bmv2_json_file_path=self.bmv2_file_path)
            t = threading.Thread(target=switch_data["connection"].send_init_and_wait, args=(self.response_callback,))
            t.start()
            self.packet_in_threads.append(t)

    def teardown(self):
        for switch_name, switch_data in self.switches.items():
            switch_data["connection"].stop_waiting()
        for t in self.packet_in_threads:
            t.join()

    def register_application(self, application, packet_in_codes):
        for code in packet_in_codes:
            self.application_mapping[code] = application

    def install_table_entries_from_json(self, configuration_file_path):

        with open(configuration_file_path, 'r') as f:
            table_entries = json.load(f)

        for switch_name, table_entries in table_entries.items():
            for entry in table_entries:
                table_entry = self.p4info_helper.buildTableEntry(
                    table_name=entry['table'],
                    match_fields=entry['match'],
                    action_name=entry['action_name'],
                    action_params=entry['action_params'])
                self.switches[switch_name]["connection"].WriteTableEntry(table_entry)

            print("[+] Successfully installed table entries from " + configuration_file_path + " on " + switch_name)

    def build_and_install_table_entry(self, switch_name, entry):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name=entry['table_name'],
            match_fields=entry['match_fields'],
            action_name=entry['action_name'],
            action_params=entry['action_params']
        )
        self.switches[switch_name]["connection"].WriteTableEntry(table_entry)

    def response_callback(self, switch, response):
        if response.packet.payload:
            # Parse CPU packet
            reason = struct.unpack(">H", response.packet.payload[8:10])[0]
            ingress_port = struct.unpack(">H", response.packet.payload[10:12])[0]
            timestamp = int(str(binascii.hexlify(response.packet.payload[12:18])), 16)

            # Delegate to registered handler
            if reason in self.application_mapping:
                self.application_mapping[reason].packet_in(reason, response.packet.payload)
            else:
                print("[!] No registered handler for this CPU packet reason.")