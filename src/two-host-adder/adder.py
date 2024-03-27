from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import VSplit, HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.widgets import TextArea, Frame
from prompt_toolkit.application import get_app

import threading

from scapy.all import (
    IntField,
    Packet,
    StrFixedLenField,
    XByteField,
    Ether,
    IP,
    UDP,
    send,
    sendp,
    sniff,
    bind_layers
)

import sys
import io
from contextlib import contextmanager

class Adder(Packet):
    name = "adder"
    fields_desc = [ StrFixedLenField("A", "A", length=1),
                    StrFixedLenField("D", "D", length=1),
                    XByteField("ver_maj", 0x00),
                    XByteField("ver_min", 0x01),
                    XByteField("seq_num", 0x00),
                    XByteField("is_result", 0x00),
                    IntField("num", 0x00) ]

bind_layers(UDP, Adder, dport=1234)

class AdderSender:
    def __init__(self, tui, dest_ip, dest_port = 1234, src_port = 1234, dest_mac = '08:00:00:00:01:03'):
        self.src_port = src_port
        self.dest_mac = dest_mac
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.seq_num = 0
        self.tui = tui
    def listen_for_ack(self):
        def handle_pkt(pkt):
            if pkt.haslayer(Adder) and pkt[Adder].is_result == 0x01:
                self.tui.print(
                    "[ACK] seq_num: " + 
                    str(pkt[Adder].seq_num) + 
                    " num: " + str(pkt[Adder].num)
                )
        sniff(filter='port 1234', prn=handle_pkt, iface="eth0")

    def send(self, num, seq_num = -1):
        if seq_num == -1:
            seq_num = self.seq_num
            self.seq_num += 1

        pkt = (
            Ether(dst=self.dest_mac, type = 0x0800) /
            IP(dst=self.dest_ip) / 
            UDP(sport = self.src_port, dport=self.dest_port) / 
            Adder(
                A='A', D='D', ver_maj=0x00, ver_min=0x01, 
                seq_num=seq_num, is_result=0x00, num=num
            )
        )
        sendp(pkt, iface="eth0", verbose=False)
        self.tui.print("[SEND] seq_num: " + str(seq_num) + " num: " + str(num))

    def run_thread(self):
        t = threading.Thread(target=self.listen_for_ack)
        t.start()

class AdderReceiver:
    def __init__(self, tui):
        self.filter = 'port 1234'
        self.port = 1234
        self.tui = tui
        

    def handle_pkt(self, pkt):
        if pkt.haslayer(Adder) and pkt[Adder].is_result == 0x01:
            return
        if pkt.haslayer(Adder):
            tui.print(
                "[RECV] seq_num: " + 
                str(pkt[Adder].seq_num) + 
                " num: " + str(pkt[Adder].num)
            )

            # send ack
            ack_pkt = (
                Ether(dst = pkt[Ether].src, type = 0x0800) /
                IP(dst = pkt[IP].src) /
                UDP(sport = self.port, dport = pkt[UDP].sport) /
                Adder(
                    A='A', D='D', ver_maj=0x00, ver_min=0x01,
                    seq_num = pkt[Adder].seq_num, is_result=0x01, num = pkt[Adder].num
                )
            )
            sendp(ack_pkt, iface="eth0", verbose=False)
        else:
            tui.print("[RECV] Unknown packet")
    def receive(self):
        sniff(filter=self.filter, prn=self.handle_pkt, iface="eth0")
    def run_thread(self):
        t = threading.Thread(target=self.receive)
        t.start()

class Tui:
    def __init__(self):
        self.prompt = "[SEND/RECV?] (s/r)> "

        self.kb = KeyBindings()
        # Exit application with Ctrl-C or Ctrl-Q
        @self.kb.add('c-c')
        @self.kb.add('c-q')
        def _(event):
            event.app.exit()
                
        # Move focus with ctrl shift m and ctrl shift i
        @self.kb.add('c-up')
        def _(event):
            self.focus_message()
        @self.kb.add('c-down')
        def _(event):
            self.focus_input()

        # Text areas for input in each "window"
        self.input_text_area = TextArea(
            text=self.prompt,
            multiline=False,
            wrap_lines=True,
            accept_handler=self.accept_input_handler
        )
        self.message_text_area = TextArea(
            text="",
            multiline=True,
            wrap_lines=True
        )

        # Creating two "windows" side by side using VSplit
        self.root_container = HSplit([
            Frame(self.message_text_area, title="Message"),
            Frame(self.input_text_area, title="Input"),
        ])

        # Creating the layout from our root container
        self.layout = Layout(self.root_container)

        # Initialize the application
        self.app = Application(layout=self.layout, key_bindings=self.kb, full_screen=True)

        # Move the focus to the input_text_area
        self.app.layout.focus(self.input_text_area)

        # Move the cursor to the end of the prompt
        self.input_text_area.buffer.cursor_position = len(self.prompt)

        self.agent = None

    def accept_input_handler(self, buffer):
        command = buffer.text.split('> ')[-1]
        if self.prompt == "[SEND/RECV?] (s/r)> ":
            if command == "s":
                self.prompt = "[SEND] (num)> "
                self.agent = AdderSender(self, '10.0.1.3')
                self.agent.run_thread()
            elif command == "r":
                self.prompt = "[RECV]> "
                self.agent = AdderReceiver(self)
                self.agent.run_thread()
            else:
                self.print("Invalid command")
        elif self.prompt == "[SEND] (num)> ":
            num = parse_num(command)
            for n in num:
                self.agent.send(n)
        elif self.prompt == "[RECV]> ":
            # Add receiver command here if needed
            parsed_cmd = command.split(' ')
            if parsed_cmd[0] == "echo":
                self.print(parsed_cmd[1])
        self.sync_prompt(buffer=buffer)

    def sync_prompt(self, buffer):
        def print_prompt():
            buffer.text = self.prompt
            buffer.cursor_position = len(buffer.text)

        get_app().loop.call_soon(print_prompt)

    def focus_input(self):
        self.app.layout.focus(self.input_text_area)

    def focus_message(self):
        self.app.layout.focus(self.message_text_area)

    def print(self, text, end="\n"):
        def print_text():
            self.message_text_area.text += text + end
            self.message_text_area.buffer.cursor_position = len(self.message_text_area.buffer.text)
        # Schedule the print_text
        get_app().loop.call_soon(print_text)


    def run(self):
        self.app.run()

def parse_num(num):
    if num[0] == '[' and num[-1] == ']':
        num = num[1:-1]
        if ',' in num:
            return [int(x) for x in num.split(',')]
        elif ' ' in num:
            return [int(x) for x in num.split(' ')]
        elif ':' in num:
            arr = num.split(':')
            if len(arr) == 2:
                return list(range(int(arr[0]), int(arr[1])))
            elif len(arr) == 3:
                return list(range(int(arr[0]), int(arr[1]), int(arr[2])))
        else:
            return [int(num)]
    else:
        return [int(num)]


if __name__ == "__main__":
    tui = Tui()
    tui.run()