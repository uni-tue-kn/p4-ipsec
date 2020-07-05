#!/usr/bin/env python2

import json
import sys
import threading
import time

from app.ipsec import IPsecS2SApplication
from cli import start_cli
import switch_controller

# Load configuration
with open('config/topology.json', 'r') as f:
    config = json.load(f)

# Setup base controller and switch connections
base_controller = switch_controller.BaseController(config['controller_config']['p4info'],
                                                     config['controller_config']['bmv2_json'])
for switch in config["switches"]:
    base_controller.add_switch_connection(switch['name'], address=switch['address'], device_id=switch['device_id'])

base_controller.startup()

# Insert table entries for forwarding
base_controller.install_table_entries_from_json("config/forwarding.json")

ipsec_app = IPsecS2SApplication(base_controller)
ipsec_app.setup_tunnel("config/tunnel_s1_s2_null.json")

# Setup CLI
cli_t = threading.Thread(target=start_cli, args=(base_controller,))
cli_t.daemon = True
cli_t.start()

# Exit CLI when CTRL-C ist pressed or when the CLI is stopped by entering 'exit'
try:
    while cli_t.is_alive():
        time.sleep(1)
except KeyboardInterrupt:
    print('shutting down')
    sys.exit(0)
