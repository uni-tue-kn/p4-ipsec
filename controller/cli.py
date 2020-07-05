import cmd


def start_cli(ctrl):
    cmd = CLI()
    cmd.set_controller(ctrl)
    cmd.cmdloop()
    ctrl.teardown()


class CLI(cmd.Cmd):
    def set_controller(self, controller):
        self.controller = controller

    def do_EOF(self, line):
        return True

    def do_connections(self, line):
        "connections - Lists the currently recognized connections"

        for index, conn in enumerate(self.controller.connection_info):
            print(
                "connection {4}: Port {1} of switch {0} is connected to port {3} of switch {2} [macsec_enabled: {5}]".format(
                    conn['sw_name_1'], conn['sw_port_1'],
                    conn['sw_name_2'], conn['sw_port_2'],
                    index, conn['macsec_enabled']))
        if len(self.controller.connection_info) == 0:
            print("no connections recognized yet")

    def do_list_switches(self, line):
        "list_switches - Lists the currently connected switches"
        for sw in self.controller.switches:
            print(sw)

    def do_read_table_rules(self, line):
        try:
            sw = self.controller.name2switch[line]
        except KeyError:
            print('illegal arguments: "' + line + '"')
            return
        print("reading table rules of {0}".format(sw))

        self.controller.read_table_rules(sw)

    def complete_read_table_rules(self, text, line, begidx, endidx):
        if not text:
            return [sw.name for sw in self.controller.switches]
        else:
            return [sw.name for sw in self.controller.switches if sw.name.startswith(text)]

    def do_exit(self, line):
        return True
