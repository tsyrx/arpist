
import os
import sys
import time 

from rich.text import Text 
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.widgets import DataTable, RichLog, Label, Static, TabbedContent, TabPane, OptionList
from textual.widgets.option_list import Option
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.binding import Binding
from textual import work

from network import ARPSniffer, ARPScanner, ReverseDNS, Pinger, ARPSpoofer, SpooferManager, get_default_gateway, get_default_interface, get_local_addresses, get_subnet

class TaskSelectionScreen(ModalScreen):
    """
    A Class used to display the currently running engines/tasks which
    the user can select from and stop.

    Attributes
    ----------
    active_tasks : list of (str, engine_obj)
        a list of all the currently running tasks in the form
        of (name_of_task, engine_obj). 
    """

    CSS = """
    TaskSelectionScreen {
        align: center middle;
        background: #000000 80%;
    }
    #selection {
        width: 45;
        height: auto;
        border: round #E06C75;
        background: #000000;
        padding: 1 2;
    }
    #selection_title {
        text-align: center;
        color: #E06C75;
        text-style: bold;
        margin-bottom: 1;
    }
    OptionList {
        background: #000000;
        border: none;
        height: auto; 
    }
    OptionList > .option-list--option-highlighted {
        background: #333333;
        color: #ffffff;
        text-style: bold;
    }
    OptionList > .option-list--option-disabled {
        color: #56B6C2;
        text-style: bold;
    }
    """

    BINDINGS = [
        ("escape", "dismiss_screen", "Cancel")
    ]

    def __init__(self, active_tasks):
        super().__init__()

        # to list so we can iterate over them
        self.active_tasks = list(active_tasks.items()) 

    def compose(self):
        with Vertical(id="selection"):
            yield Label("TASKS", id="selection_title")

            # group the tasks by the engine being used
            groups = {} 
            for task_key, _ in self.active_tasks: 
                parts = task_key.split("_", 1) 
                engine_name = parts[0]

                # for tasks on more than one target
                target = parts[1] if len(parts) > 1 else "Main Process"

                if engine_name not in groups:
                    groups[engine_name] = []
                groups[engine_name].append((target, task_key))

            options= []
            for engine_name, tasks in groups.items(): 
                options.append(Option(engine_name.upper(), id=f"group:{engine_name}"))

                for target, task_key in tasks:
                    options.append(Option(f" -> {target}", id=f"task:{task_key}"))

            yield OptionList(*options, id="task_option_list")

    def on_option_list_option_selected(self, event):
        selected_task_id = event.option_id

        if selected_task_id: 
            self.dismiss(selected_task_id)

    def action_dismiss_screen(self) -> None: 
        self.dismiss(None)


class FocusableRichLog(RichLog):
    """
    Used just to make the Logs work with vim :p 
    """
    can_focus = True


class HelpScreen(ModalScreen):
    """
    Class used to display all the different keybinds and tasks that
    the application has available.
    """

    CSS = """
    HelpScreen {
        align: center middle;
        background: #000000 80%; 
    }
    #help_dialog {
        width: 45;
        height: auto;
        border: round #56B6C2;
        background: #000000;
        padding: 1 2;
    }
    .help_title { text-align: center; color: #56B6C2; text-style: bold; margin-bottom: 1; }
    .help_entry { margin-bottom: 0; color: #888888; }
    .help_key { color: #56B6C2; text-style: bold; }
    """

    BINDINGS = [
        ("h", "dismiss", "Close"),
        ("escape", "dismiss", "Close")
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help_dialog"):
            yield Label("HELP", classes="help_title")
            yield Label("[#56B6C2 bold]s[/]           Start Sniffer", classes="help_entry")
            yield Label("[#56B6C2 bold]a[/]           Start Scanner", classes="help_entry")
            yield Label("[#56B6C2 bold]d[/]           Start DoS (Cursor)", classes="help_entry")
            yield Label("[#56B6C2 bold]Shift+d[/]     Start DoS (Selected)", classes="help_entry")
            yield Label("[#56B6C2 bold]p[/]           Start Pinger (Cursor)", classes="help_entry")
            yield Label("[#56B6C2 bold]Shift+p[/]     Start Pinger (Selected)", classes="help_entry")
            yield Label("[#56B6C2 bold]r[/]           Resolve Hostname (Cursor)", classes="help_entry")
            yield Label("[#56B6C2 bold]Shift+r[/]     Resolve Hostnames (Selected)", classes="help_entry")
            yield Label("[#56B6C2 bold]Shift+x[/]     Stop All Backends", classes="help_entry")
            yield Label("[#56B6C2 bold]Ctrl+space[/]  Select All Row", classes="help_entry")
            yield Label("[#56B6C2 bold]space[/]       Select Row", classes="help_entry")
            yield Label("[#56B6C2 bold]Shift+u[/]     Deselect All", classes="help_entry")
            yield Label("[#56B6C2 bold]c[/]           Clear Logs", classes="help_entry")
            yield Label("[#56B6C2 bold]L[/]           Switch_logs", classes="help_entry")
            yield Label("") # spacing 
            yield Label("[#56B6C2 bold]h[/]           Exit Help", classes="help_entry")
            yield Label("[#56B6C2 bold]q[/]           Quit Application", classes="help_entry")

    def action_dismiss(self) -> None:
        self.app.pop_screen()


class ModularSnifferApp(App):
    """
    Class for the TUI. 

    It handles all IO interaction with the user, as well as starting and stopping
    all network tasks and things like that. 

    Attributes
    ----------
    devices : dict of dicts
        used to keep track of all devices that have been found in the LAN. 
        Each entry in the dictionary is identified by its ip and it stores the
        device's mac, last seen time, status (color of row), and if it is currently
        being spoofed.

        {"127.0.0.1":
            { "mac": "<mac>",
              "last_seen": "<time>",
              "style": "<status>",
              "spoof_status": "<status>", 
            },
            ...
        }

    selected_rows : dict of pairs (str, str)
        used to keep track of all the entries that were selected by the user to use
        in tasks with a list of targets. 
        The tuples store the entries in a pair (ip, mac). 

    active_tasks : dict of (str, engine_obj)
        a dictionary of all the currently running tasks in the form
        of (name_of_task, engine_obj). 

    manager : SpooferManager
        handles all the background layer 3 sniffing to ensure that the DoS or MitM are
        working properly.
        As long as an instance of ARPSpoofer is running, the manager is sniffing
        for layer 3 packets. 

    gateway_ip : str
        IP of the LAN's gateway.

    gateway_mac : str
        MAC of the LAN's gateway.
    """

    CSS = """
    Screen { background: #000000; }
    DataTable { height: 1fr; background: #000000; color: #FFFFFF; border: blank; margin: 0 1; scrollbar-size: 0 0; }
    DataTable > .datatable--cursor { background: #333333; color: #FFFFFF; text-style: none; }
    .log_window { 
        height: 12; 
        background: #000000; 
        color: #888888; 
        border: round #333333; 
        margin: 0 1 0 1; 
        padding: 0 0 0 1;
        scrollbar-size: 0 0; 
    }
    #status_pane { width: 32; height: 1fr; padding: 0 1; }
    .status-header {
        border: #005050;
        color: #cccccc;
        text-align: center;
        height: 3;
        width: 100%;
    }
    .backend-card {
        border-bottom: #333333;
        height: 2;
    }
    .backend-title {
        color: #555555;
        margin-right: 1;
    }
    Tabs {
        margin-left: 2; 
        border-bottom: solid #E06C75;
    }
    Tabs > .tabs--indicator {
        display: none; 
    }
    Tab {
        background: #000000;
        color: #555555;
        padding: 0 2;
    }
    Tab.-active {
        color: #FFFFFF;
        text-style: bold;
        background: #000000;
    }
    TabPane {
        padding: 0;
        margin: 0;
    }
    #local_ip_label{
        padding: 0 1;
        color: #555555;
        text-align: center;
        margin-bottom: 0;
    }
    .status-header {
        color: #cccccc;
        text-align: center;
        text-style: bold;
        margin-top: 1;
    }
    #backends_header {
        margin-top: 0;
    }
    #spoofed_container {
        height: 1fr;
        border: round #333333;
        background: #000000;
        padding: 0 1;
        scrollbar-size: 0 0;
        margin-top: 1;
    }
    .spoofed_target_item {
        color: #E06C75;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("s", "start_sniffing", "Sniff"),
        Binding("a", "start_scanning", "Scan"),
        Binding("r", "resolve_hostname", "Resolve"),
        Binding("p", "start_pinging", "Ping"),
        Binding("d", "start_dos", "DoS"),
        Binding("m", "start_mitm", "MitM"),
        Binding("space", "toggle_selection", "Select"),
        Binding("x", "stop_task", "Stop"),
        Binding("c", "clear_logs", "Clear"),
        Binding("h", "toggle_help", "Help"),
        Binding("ctrl+space", "toggle_all_rows", "Select", show=False),
        Binding("X", "stop_all_tasks", "Stop", show=False),
        Binding("q", "quit", "Quit", show=False),
        Binding("L", "switch_logs", "Switch Log Tab", show=False),
        Binding("R", "resolve_hostname('list')", "Resolve", show=False),
        Binding("P", "start_pinging('list')", "Ping", show=False),
        Binding("D", "start_dos('list')", "DoS", show=False),
        Binding("M", "start_mitm('list')", "MitM", show=False),
        Binding("j", "vim_down", "Down", show=False),
        Binding("k", "vim_up", "Up", show=False),
        Binding("g", "vim_top", "Top", show=False),
        Binding("G", "vim_bottom", "Bottom", show=False),
        Binding("U", "emacs_deselect", "Deselect", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical():
            with Horizontal():
                with Vertical(id="left_pane"):
                    yield DataTable(id="network_table")
                    yield DataTable(id="connections_table")

                with Vertical(id="status_pane"):
                    yield Static("")
                    yield Static(f"Host: {self.local_ip}", id="local_ip_label")

                    yield Label("Active Backends", id="backends_header", classes="status-header")
                    yield Static("")

                    with Vertical(classes="backend-card"):
                        with Horizontal():
                            yield Label("[#E06C75]●[/]", id="status_arpsniffer", classes="backend-title")
                            yield Label("ARPSniffer", id="title_arpsniffer", classes="backend-title")

                    with Vertical(classes="backend-card"):
                        with Horizontal():
                            yield Label("[#E06C75]●[/]", id="status_arpscanner", classes="backend-title")
                            yield Label("ARPScanner", id="title_arpscanner", classes="backend-title")

                    with Vertical(classes="backend-card"):
                        with Horizontal():
                            yield Label("[#E06C75]●[/]", id="status_revdns", classes="backend-title")
                            yield Label("RevDNS", id="title_revdns", classes="backend-title")

                    with Vertical(classes="backend-card"):
                        with Horizontal():
                            yield Label("[#E06C75]●[/]", id="status_pinger", classes="backend-title")
                            yield Label("Pinger", id="title_pinger", classes="backend-title")

                    with Vertical(classes="backend-card"):
                        with Horizontal():
                            yield Label("[#E06C75]●[/]", id="status_arpspoofer", classes="backend-title")
                            yield Label("ARPSpoofer", id="title_arpspoofer", classes="backend-title")

                    yield Label("Spoofing", id="dos_header", classes="status-header")
                    with VerticalScroll(id="spoofed_container"):
                        yield Label("[#555555]None[/]", id="no_spoofed_label")
        
            with TabbedContent(id="log_tabs"): 
                with TabPane("Actions", id="actions"):
                    yield FocusableRichLog(id="log_window", highlight=True, markup=True, max_lines=1000, classes="log_window") 
                with TabPane("Sniffer Logs", id="sniffer"):
                    yield FocusableRichLog(id="sniffer_window", highlight=True, markup=True, max_lines=1000, classes="log_window") 

        yield Label(id="custom_footer")

    def set_footer(self):
        footer_label = self.query_one("#custom_footer", Label)

        text = " "
        for b in self.BINDINGS:
            if b.show:
                text += f"[#56B6C2 bold]{b.key}[/] [#555555]{b.description}[/]  " 

        footer_label.update(text)

    # Turn off palette 
    def action_command_palette(self): 
        return

    def __init__(self):
        super().__init__()
        
        self.devices = {}
        self.hostnames = {}
        self.active_tasks = {}
        self.selected_rows = set()

        self.iface = None 
        self.local_ip = None
        self.local_mac = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.subnet = None 

        self.manager = None
        self.active_connections = {}

    def on_mount(self) -> None:
        self.iface = get_default_interface()
        self.local_ip, self.local_mac = get_local_addresses(self.iface)
        self.subnet = get_subnet(self.local_ip, self.iface)
        gateway_info = get_default_gateway()

        if (
            not self.subnet
            or not gateway_info
            or self.local_ip == "0.0.0.0"
            or self.local_mac == "00:00:00:00:00:00"
        ):
            import sys
            print("    ERROR: Network initialization failed.", file=sys.stderr)
            print(f"    Active Interface: {self.iface}", file=sys.stderr)
            print(f"    Assigned Local IP: {self.local_ip}", file=sys.stderr)
            print(f"    Target Subnet:    {self.subnet if self.subnet else 'Unknown'}", file=sys.stderr)
            print(f"    Default Gateway:  {'Found' if gateway_info else 'Not Found'}\n", file=sys.stderr)
            
            self.exit()
            return

        self.gateway_ip, self.gateway_mac = gateway_info

        def manager_callback(event_type, payload):
            self.call_from_thread(self.manager_event, event_type, payload)

        self.manager = SpooferManager(manager_callback, self.gateway_ip, self.gateway_mac, self.local_ip)

        self.set_footer()
        self.query_one("#local_ip_label", Static).update(f"Host: {self.local_ip}")
        self.table = self.query_one("#network_table", DataTable)
        self.conns = self.query_one("#connections_table", DataTable)
        self.logs = self.query_one("#log_window", RichLog)
        self.sniffer_logs = self.query_one("#sniffer_window", RichLog)
        self.tabs = self.query_one("#log_tabs", TabbedContent)

        self.table.add_column("", key="select col", width=4)
        self.table.add_column("IP Address", key="ip col", width=15)
        self.table.add_column("MAC Address", key="mac col", width=20)
        self.table.add_column("Hostname", key="host col", width=40)
        self.table.cursor_type = "row"
        self.table.focus()

        self.conns.add_column("Victim IP", key="vic col", width=15)
        self.conns.add_column("Remote Host", key="rem col", width=18)
        self.conns.add_column("Port", key="port col", width=6)
        self.conns.add_column("Proto", key="proto col", width=8)
        self.conns.add_column("Data Volume", key="size col", width=12)
        self.conns.add_column("Time", key="time col", width=10)
        self.conns.cursor_type = "row"

        # add the gateway right away
        color = "yellow"
        self.table.add_row(
            "[ ]",
            Text(self.gateway_ip, style=color),
            Text(self.gateway_mac, style=color),
            Text("(Gateway)", style=color),
            key=self.gateway_ip
        )
        self.devices[self.gateway_ip] = {
            "mac": self.gateway_mac,
            "last_seen": time.time(),
            "style": color
            }
        self.hostnames[self.gateway_ip] = "(Gateway)"

        self.set_interval(30.0, self.update_device_statuses)

    def update_device_statuses(self): 
        """Method that runs every 30 seconds to update device staleness."""
        for ip in list(self.devices.keys()):
            style = self.get_device_style(ip)
            device = self.devices[ip]
            current_status = device.get("style")

            if current_status != style:
                device["style"] = style
                mac = device.get("mac", "?")
                hostname = self.get_display_name(ip)
                #try:
                self.table.update_cell(row_key=ip, column_key="ip col", value=Text(ip, style=style))
                self.table.update_cell(row_key=ip, column_key="mac col", value=Text(mac, style=style))
                self.table.update_cell(row_key=ip, column_key="host col", value=Text(hostname, style=style))
                # except Exception as e:
                    # return 
                    # self.logs.write(f"[red]UI Staleness Update Error:[/] {e}")

    def force_update_row(self, ip):
        """Method for instantly updating the Table entries' statuses."""
        style = self.get_device_style(ip)
        device = self.devices.setdefault(ip, {})
        device["style"] = style
        mac = device.get("mac", "?")
        hostname = self.get_display_name(ip)

        try:
            self.table.update_cell(row_key=ip, column_key="ip col", value=Text(ip, style=style))
            self.table.update_cell(row_key=ip, column_key="mac col", value=Text(mac, style=style))
            self.table.update_cell(row_key=ip, column_key="host col", value=Text(hostname, style=style))
        except Exception as e:
            self.logs.write(f"[red]UI Force Update Error:[/] {e}")

    def get_device_style(self, ip) -> str:
        """Method that checks the state of the device and updates its table color."""
        is_gateway = ip == self.gateway_ip

        device = self.devices.get(ip, {})
        spoof = device.get("spoof_status", {})

        if spoof and spoof != "cleared": 
            return "red on #330000"
            
        now = time.time()
        last = device.get("last_seen", 0)
        age = now - last
        if age > 600: # if more than 10 minutes stale 
            return "#5C6370" 
        elif age > 300: # if more than 5 minutes might be stale
            return "#E5C07B" if not is_gateway else "#803900"
        return "green" if not is_gateway else "yellow"

    def update_engine_status(self):
        """Method for updating the side pannel with the status of the backends."""
        engines = ["ARPSniffer", "ARPScanner", "RevDNS", "Pinger", "ARPSpoofer"]
        
        for name in engines:
            title_label = self.query_one(f"#title_{name.lower()}", Label)
            status_label = self.query_one(f"#status_{name.lower()}", Label)

            is_running = any(task_key.startswith(name) for task_key in list(self.active_tasks.keys()))
            
            if is_running:
                title_label.update(f"[#ffffff]{name}[/]")
                status_label.update("[#56B6C2]●[/]")
            else:
                title_label.update(f"[#555555]{name}[/]")
                status_label.update("[#E06C75]●[/]")




    #################################
    # UI Actions 
    #################################

    def action_clear_logs(self) -> None:
        self.logs.clear()
        self.table.clear()
        self.devices.clear()

    def action_start_sniffing(self) -> None:
        if "ARPSniffer" in self.active_tasks:
            self.logs.write("ARPSniffer is [yellow]already running[/].")
            return
 
        self.logs.write("Starting ARPSniffer...")

        def packet_callback(event_type, payload):
            self.call_from_thread(self.packet_event, event_type, payload, "sniffer")
        
        sniffer = ARPSniffer(packet_callback, self.iface, self.local_ip, self.local_mac)
        self.run_generic_task("ARPSniffer", sniffer)
        
    def action_start_scanning(self) -> None:
        if "ARPScanner" in self.active_tasks:
            self.logs.write("ARPScanner is [yellow]already running[/].")
            return
            
        self.logs.write("Starting ARPScanner...")

        def packet_callback(event_type, payload):
            self.call_from_thread(self.packet_event, event_type, payload, "scanner")

        scanner = ARPScanner(packet_callback, self.iface, self.local_ip, self.local_mac, self.subnet)
        self.run_generic_task("ARPScanner", scanner)
        
    def action_start_pinging(self, mode="manual") -> None:
        targets = self.get_targets(mode, include_mac=False)
        if not targets:
            return 

        host = self.get_display_name(targets[0])
        msg = f"Starting Pinger: Pinging {host}" + (f" and {len(targets) - 1} more..." if len(targets) > 1 else "...")
        self.logs.write(msg)

        def ping_callback(event_type, payload):
            self.call_from_thread(self.ping_event, event_type, payload)
            
        for ip in targets: 
            pinger_id = f"Pinger_{ip}"
            host = self.get_display_name(ip)
            if pinger_id in self.active_tasks:
                self.logs.write(f"Pinger is [yellow]already running[/] on {host}.")
                continue

            pinger = Pinger(ping_callback)
            self.run_generic_task(pinger_id, pinger, start_args=[ip])

    def action_resolve_hostname(self, mode="manual") -> None:
        targets = self.get_targets(mode, include_mac=False)
        if not targets:
            return 

        msg = f"Starting RevDNS: Resolving for {targets[0]}" + (f" and {len(targets) - 1} more..."  if len(targets) > 1 else "...")
        self.logs.write(msg)

        def hostname_callback(event_type, payload):
            self.call_from_thread(self.hostname_event, event_type, payload)
            
        for ip in targets: 
            resolver_id = f"RevDNS_{ip}"
            if resolver_id in self.active_tasks: 
                self.logs.write(f"RevDNS is [yellow]already running[/] for {ip}.")
                continue
            
            revDNS = ReverseDNS(hostname_callback)
            self.run_generic_task(resolver_id, revDNS, start_args=[ip])

    def action_start_dos(self, mode="manual") -> None:
        targets = self.get_targets(mode, include_mac=True)
        if not targets:
            return 

        host = self.get_display_name(targets[0][0])
        msg = f"Starting ARPSpoofer: DoS on {host}" + (f" and {len(targets) - 1} more..."  if len(targets) > 1 else "...")
        self.logs.write(msg)

        def dos_callback(event_type, payload): 
            self.call_from_thread(self.dos_event, event_type, payload)

        for target in targets: 
            self.run_dos(target, dos_callback)

    def action_start_mitm(self, mode="manual") -> None:
        targets = self.get_targets(mode, include_mac=True) 
        if not targets:
            return 

        host = self.get_display_name(targets[0][0])
        msg = f"Starting MitM on {host}" + (f" and {len(targets) - 1} more..."  if len(targets) > 1 else "...")
        self.logs.write(msg)

        def mitm_callback(event_type, payload): 
            self.call_from_thread(self.mitm_event, event_type, payload)

        for target in targets: 
            self.run_mitm(target, mitm_callback)

    def action_stop_all_tasks(self) -> None: 
        if not self.active_tasks:
            self.logs.write("Nothing to stop.") 
            return 

        self.logs.write("Sending stop signal to all engines...")

        for name, engine in list(self.active_tasks.items()):
            engine.stop()
            self.logs.write(f"- Send stop signal to {name}.")

    def action_toggle_selection(self) -> None:
        if self.table.cursor_row is None or self.table.row_count == 0:
            return

        row_index = self.table.cursor_row
        row_key = list(self.table.rows.keys())[row_index]
        
        clean_ip = row_key.value
        device = self.devices.get(clean_ip, {})
        clean_mac = device.get("mac", "?")
        
        clean_tuple = (clean_ip, clean_mac)
        
        if clean_tuple in self.selected_rows:
            self.selected_rows.remove(clean_tuple)
            self.table.update_cell(row_key, column_key="select col", value="[ ]")
        else:
            self.selected_rows.add(clean_tuple)
            self.table.update_cell(row_key, column_key="select col", value="[X]")

    def action_toggle_all_rows(self) -> None:
        for row_key in self.table.rows.keys(): 
            clean_ip = row_key.value
            device = self.devices.get(clean_ip, {})
            clean_mac = device.get("mac", "?")
            self.selected_rows.add((clean_ip, clean_mac))
            self.table.update_cell(row_key, column_key="select col", value="[X]")

    def action_switch_logs(self) -> None:
        self.tabs.active = "sniffer" if self.tabs.active == "actions" else "actions"

    def action_toggle_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_stop_task(self) -> None:
        if not self.active_tasks:
            self.logs.write("Nothing to stop.") 
            return

        def on_task_selected(selected_id: str | None) -> None:
            if selected_id is None: 
                return

            if selected_id.startswith("task:"):
                task_key = selected_id.replace("task:", "")
                task = self.active_tasks.get(task_key)
                if task and hasattr(task, "stop"):
                    task.stop()
                    self.logs.write(f"Sending stop signal to {task_key}...")
            elif selected_id.startswith("group:"):
                prefix = selected_id.replace("group:", "")
                for key, task in list(self.active_tasks.items()):
                    if key.startswith(prefix):
                        if hasattr(task, "stop"):
                            task.stop()
                        
                self.logs.write(f"Stopping all tasks for {prefix}...")

        self.push_screen(TaskSelectionScreen(self.active_tasks), on_task_selected)
        
    def action_quit(self) -> None:
        for engine in list(self.active_tasks.values()):
            if hasattr(engine, "stop"):
                engine.stop()
        self.exit()



    #################################
    # Threads
    #################################

    # Generic #######################
    @work(thread=True)
    def run_generic_task(self, task_id: str, engine_obj, start_args=None):
        """Generic function for running the backends."""

        self.active_tasks[task_id] = engine_obj
        self.call_from_thread(self.update_engine_status)

        if start_args:
            engine_obj.start(*start_args)
        else:
            engine_obj.start()
            
        self.active_tasks.pop(task_id, None)
        self.call_from_thread(self.update_engine_status)

    # MitM ##########################
    @work(thread=True)
    def run_mitm(self, target, mitm_callback): 
        ip, mac = target

        task_id = f"MITM_{ip}"

        device = self.devices.setdefault(ip, {})
        device["spoof_status"] = "mitming"
        self.call_from_thread(self.force_update_row, ip)
        self.call_from_thread(self.update_spoofed_list)

        mitm = ARPSpoofer(self.iface, self.local_ip, self.local_mac,
                          mitm_callback,
                          self.manager,
                          ip, mac,
                          self.gateway_ip, 
                          self.gateway_mac, 
                          mode="mitm")

        self.active_tasks[task_id] = mitm
        self.call_from_thread(self.update_engine_status)

        mitm.start()

        device = self.devices.get(ip, {})
        device["spoof_status"] = "cleared"
        self.call_from_thread(self.force_update_row, ip)
        self.call_from_thread(self.update_spoofed_list)

        self.active_tasks.pop(task_id, None)
        self.call_from_thread(self.update_engine_status)

    # ARPSpoofer ####################
    @work(thread=True)
    def run_dos(self, target, dos_callback): 
        ip, mac = target

        task_id = f"ARPSpoofer_{ip}"

        device = self.devices.setdefault(ip, {})
        device["spoof_status"] = "spoofing"
        self.call_from_thread(self.force_update_row, ip)
        self.call_from_thread(self.update_spoofed_list)

        spoofer = ARPSpoofer(self.iface, self.local_ip, self.local_mac,
                            dos_callback,
                            self.manager,
                            ip, mac,
                            self.gateway_ip,
                            self.gateway_mac,
                            mode="dos")

        self.active_tasks[task_id] = spoofer 
        self.call_from_thread(self.update_engine_status)

        spoofer.start()

        device = self.devices.get(ip, {})
        device["spoof_status"] = "cleared"
        self.call_from_thread(self.force_update_row, ip)
        self.call_from_thread(self.update_spoofed_list)

        self.active_tasks.pop(task_id, None)
        self.call_from_thread(self.update_engine_status)

    def update_spoofed_list(self):
        container = self.query_one("#spoofed_container")
        spoofed_data = [(ip, d.get("spoof_status")) for ip, d in self.devices.items() if d.get("spoof_status") in ["spoofing", "mitming", "spoofed", "mitm"]]

        active_spoofed_ips = {ip for ip, _ in spoofed_data}

        if spoofed_data:
            try:
                container.query_one("#no_spoofed_label").remove()
            except Exception:
                pass 

        for child in list(container.children): 
            if child.id == "no_spoofed_label":
                continue 

            widget_ip = child.id.replace("spoofed_", "").replace("-", ".")
            if widget_ip not in active_spoofed_ips: 
                child.remove()
                
        if not spoofed_data:
            if not container.query("#no_spoofed_label"):
                container.mount(Label("[#555555]None[/]", id="no_spoofed_label"))
            return 
        
        for ip, status in sorted(spoofed_data):
            safe_id = f"spoofed_{ip.replace('.', '-')}"

            device = self.devices.get(ip, {})
            mac = device.get("mac", "?")
            style = "#E06C75" if status in ["mitm", "spoofed"] else "#D16500"
            host = self.get_display_name(ip)

            label_text = f"[{style}]●"
            label_text += " (M)" if status == "mitm" else "" 
            label_text += f" {host}[/]\n   [#555555]{mac}[/]"

            try: 
                existing_widget = container.query_one(f"#{safe_id}", Label)
                existing_widget.update(label_text)
            except Exception:
                container.mount(Label(label_text, id=safe_id, classes="spoofed_target_item"))



    #################################
    # Events
    #################################

    # Pinger Event ##################
    def ping_event(self, event_type: str, payload: dict):
        if event_type == "LOG": 
            self.logs.write(payload["message"])
            return

        ip = payload["ip"]
        device = self.devices.setdefault(ip, {})
        host = self.get_display_name(ip)
        
        old_state = device.get("ping_state", "UNKNOWN")

        device["ping_state"] = event_type
        device["last_seen"] = time.time()

        if event_type != old_state:
            timestamp = payload["timestamp"]
            if event_type == "UP":
                self.logs.write(f"[{timestamp}] {host} is [green]UP[/].")
            if event_type == "DOWN":
                self.logs.write(f"[{timestamp}] {host} is [red]DOWN[/].")

        self.force_update_row(ip)

    # Packet Event ##############
    def packet_event(self, event_type: str, payload: dict, src: str):
        if event_type == "LOG":
            self.logs.write(payload["message"])

        elif event_type in "PACKET":
            target_log = self.sniffer_logs if src == "sniffer" else self.logs
            ip, mac, timestamp, op_type = payload["ip"], payload["mac"], payload["timestamp"], payload["type"]

            host = self.get_display_name(ip)
            if op_type == "TARGET": 
                target_log.write(f"- [{timestamp}] ARP to   {host} @ {mac} (TARGET)")
            else: 
                target_log.write(f"- [{timestamp}] ARP from {host} @ {mac} ({op_type})")
            
            device = self.devices.setdefault(ip, {})
            device["mac"] = mac
            device["last_seen"] = time.time()
            
            color = self.get_device_style(ip)
            
            if ip not in self.table.rows:
                device["style"] = color
                device["spoof_status"] = "cleared"
                self.hostnames[ip] = "Unknown"
                
                self.table.add_row(
                    "[ ]",
                    Text(ip, style=color),
                    Text(mac, style=color),
                    Text("Unknown", style=color),
                    key=ip
                )

            elif device.get("style") != color:
                device["style"] = color 
                hostname = self.get_display_name(ip)
                self.table.update_cell(row_key=ip, column_key="ip col", value=Text(ip, style=color))
                self.table.update_cell(row_key=ip, column_key="mac col", value=Text(mac, style=color))
                self.table.update_cell(row_key=ip, column_key="host col", value=Text(hostname, style=color))

    # Hostname Event ################
    def hostname_event(self, event_type: str, payload: dict):
        if event_type == "LOG":
            self.logs.write(payload["message"])
            return 

        ip = payload["ip"]

        if event_type == "UNKNOWN": 
            self.logs.write(f"- [Failed] Unknown hostname @ {ip}.")
            display_hostname = "Unknown"
        elif event_type == "HOSTNAME":
            hostname = payload["hostname"]
            self.logs.write(f"- [Resolved] {hostname} @ {ip}.")
            display_hostname = f"(Gateway) {hostname}" if ip == self.gateway_ip else hostname
        else:
            return 

        self.hostnames[ip] = display_hostname

        try:
            style = self.get_device_style(ip)
            self.table.update_cell(row_key=ip, column_key="host col", value=Text(display_hostname, style=style))
        except Exception as e:
            self.logs.write(f"Error updating the UI: {e}")

    # Manager Event #####################
    def manager_event(self, event_type, payload):
        if event_type == "ERROR": 
            self.logs.write(f"[[red]ERROR[/]] {payload["message"]}")
            return 

        if event_type == "CONFIRMED":
            ip = payload["victim_ip"]
            time = payload["timestamp"]
            host = self.get_display_name(ip)

            device = self.devices.get(ip)
            if not device:
                return
            
            if device["spoof_status"] == "spoofing":
                self.logs.write(f"[{time}] Spoof CONFIRMED @ {host}")
                device["spoof_status"] = "spoofed" 
                self.update_spoofed_list()
            elif device["spoof_status"] == "mitming": 
                self.logs.write(f"[{time}] MitM CONFIRMED @ {host}")
                device["spoof_status"] = "mitm" 
                self.update_spoofed_list()

        elif event_type == "MITM_DATA":
            victim = self.get_display_name(payload["victim_ip"])
            target = self.get_display_name(payload["target_ip"])
            proto = payload["proto"]
            size = payload["size"]
            port = payload.get("port", 0)
            time = payload["timestamp"]

            conn_key = f"{victim}_{target}_{port}"

            if port in ["80", "21", "20", "23"]:
                proto_style = "red"
            else:
                proto_style = "cyan"

            if conn_key not in self.active_connections:
                self.active_connections[conn_key] = size
                
                vol = f"{size} B" if size < 1024 else f"{size/1024:.1f} KB"

                self.conns.add_row(
                    Text(victim),
                    Text(target),
                    Text(str(port)),
                    Text(proto, style=proto_style),
                    Text(vol),
                    Text(time),
                    key=conn_key
                )
            else:
                self.active_connections[conn_key] += size
                total_size = self.active_connections[conn_key]
                vol = f"{total_size} B" if total_size < 1024 else f"{total_size/1024:.1f} KB"

                try:
                    self.conns.update_cell(row_key=conn_key, column_key="size col", value=Text(vol))
                    self.conns.update_cell(row_key=conn_key, column_key="time col", value=Text(time))
                except Exception:
                    pass

    # TODO: Add search controls in table and add OEM

    # DoS Event #########################
    def dos_event(self, event_type, payload):
        if event_type == "LOG":
            self.logs.write(payload["message"])
        elif event_type == "ERROR": 
            self.logs.write(f"[[red]ERROR[/]] {payload["message"]}")

    # MitM Event ####################
    def mitm_event(self, event_type, payload):
        if event_type == "LOG":
            self.logs.write(payload["message"])
        elif event_type == "ERROR": 
            self.logs.write(f"[[red]ERROR[/]] {payload["message"]}")

    #################################
    # Key Binds
    #################################

    def action_vim_down(self) -> None:
        focused = self.focused
        if not focused:
            return
        if focused.id in ["network_table", "connections_table"]:
            focused.action_cursor_down()
        elif isinstance(focused, FocusableRichLog):
            focused.action_scroll_down()

    def action_vim_up(self) -> None:
        focused = self.focused
        if not focused:
            return
        if focused.id in ["network_table", "connections_table"]:
            focused.action_cursor_up()
        elif isinstance(focused, FocusableRichLog):
            focused.action_scroll_up()

    def action_vim_bottom(self) -> None:
        focused = self.focused
        if not focused:
            return
        if focused.id in ["network_table", "connections_table"]:
            if focused.row_count > 0: 
                focused.move_cursor(row=focused.row_count - 1)
        elif isinstance(focused, FocusableRichLog):
            focused.action_scroll_end()

    def action_vim_top(self) -> None:
        focused = self.focused
        if not focused:
            return
        if focused.id in ["network_table", "connections_table"]:
            focused.move_cursor(row=0)
        elif isinstance(focused, FocusableRichLog):
            focused.action_scroll_home()
        
    def action_emacs_deselect(self) -> None:
        focused_id = getattr(self.focused, "id", None)
        if focused_id in ["network_table", "connections_table"]:
            if not self.selected_rows:
                return
            
            for clean_ip, _ in self.selected_rows: 
                self.table.update_cell(row_key=clean_ip, column_key="select col", value="[ ]")

            self.selected_rows.clear()
            

    #################################
    # Aux Funcs
    #################################

    def get_targets(self, mode: str, include_mac: bool = False) -> list:
        if mode == "list":
            if not self.selected_rows:
                self.logs.write("[yellow]No rows selected.[/]")
                return []

            if include_mac:
                return list(self.selected_rows)
            return [row[0] for row in self.selected_rows]

        if self.table.row_count == 0 or self.table.cursor_row is None:
            return []

        ip_cell = self.table.get_row_at(self.table.cursor_row)[1]
        clean_ip = ip_cell.plain if hasattr(ip_cell, "plain") else str(ip_cell)

        if include_mac:
            mac_cell = self.table.get_row_at(self.table.cursor_row)[2]
            clean_mac = mac_cell.plain if hasattr(mac_cell, "plain") else str(mac_cell)
            return [(clean_ip, clean_mac)]

        return [clean_ip]

    def get_display_name(self, ip):
        return self.hostnames.get(ip, ip)

if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("    ERROR: Root privileges (sudo) are required to capture raw network packets.", file=sys.stderr)
        print("    Please run this application with: sudo python3 main_tui.py", file=sys.stderr)
        sys.exit(1)

    app = ModularSnifferApp()
    app.run()
