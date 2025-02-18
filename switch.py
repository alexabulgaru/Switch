#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# Constants representing the STP states
BLOCKING = 'BLOCKING'
LISTENING = 'LISTENING'

# 01:80:C2:00:00:00, switches listen to this MAC address to receive BPDUs
BPDU_DEST_MAC = b'\x01\x80\xc2\x00\x00\x00'
# Length field for LLC
BPDU_ETH_TYPE = 0x0000
# LLC header: DSAP = 0x42, SSAP = 0x42, Control = 0x03
BPDU_LLC_HEADER = b'\x42\x42\x03'

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# Inserts a VLAN tag into the Ethernet frame
def add_vlan_tag(data, vlan_id):
    # Splits the original frame into the first 12 bytes and the rest
    ether_type_and_payload = data[12:]
    vlan_tag = create_vlan_tag(vlan_id)
    # Concatenates the first 12 bytes, the VLAN tag and the rest of the frame
    tagged_data = data[0:12] + vlan_tag + ether_type_and_payload
    return tagged_data

# Removes a VLAN tag from the Ethernet frame
def remove_vlan_tag(data):
    # First 12 bytes are kept, then it skips the VLAN tag and keeps the rest
    untagged_data = data[0:12] + data[16:]
    return untagged_data

# Checks if a MAC address is the broadcast address
def is_broadcast_mac(mac):
    # Broadcast MAC address used to send frames to all devices on the local network
    return mac == b'\xff\xff\xff\xff\xff\xff'

# Checks if a MAC address is a multicast address - least significant bit of the first byte is 1
def is_multicast_mac(mac):
    return (mac[0] & 0x01) == 1

# Adjusts the Ethernet frame for sending based on the VLAN configuration
def prepare_frame_for_sending(data, vlan_id, out_interface, interface_configs):
    port_config = interface_configs[out_interface]
    ether_type = int.from_bytes(data[12:14], byteorder='big')
    has_vlan_tag = (ether_type == 0x8200)

    # Checks if the outgoing interface is a trunk port or an access port
    if port_config['trunk']:
        # If it's sending to a trunk port and the frame is untagged, it adds a VLAN tag
        if not has_vlan_tag:
            data = add_vlan_tag(data, vlan_id)
    else:
        # If it's sending to an access port and the frame has a VLAN tag, it removes it
        if has_vlan_tag:
            data = remove_vlan_tag(data)
    return data, len(data)

# Reads the switch configuration from a file
def read_config(switch_id):
    config = {}
    config['interfaces'] = {}
    # Opens the configuration file for the switch in configs/switch<id>.cfg
    filename = f'configs/switch{switch_id}.cfg'
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            # If the file is empty, it exits the program
            if not lines:
                sys.exit(1)
            # Checks if the first line is a number in order to get the priority
            if lines[0].strip().isdigit():
                # Converts the priority to an integer and stores it in the priority key in config
                config['priority'] = int(lines[0].strip())
                # The rest of the lines are assigned to interface_lines
                interface_lines = lines[1:]
            else:
                # If the first line is not a number, the priority is set to 32768 which is the standard default in STP
                config['priority'] = 32768
                interface_lines = lines
            # Then it iterates over each line that represents the interface configuration
            for line in interface_lines:
                # Splits the line by spaces and removes any leading or trailing whitespace
                parts = line.strip().split()
                # If the parts list is empty, it skips it
                if not parts:
                    continue
                interface_name = parts[0]
                # Cheks if there is a second element in parts for potential additional configuration of the interface
                if len(parts) > 1:
                    vlan_or_t = parts[1]
                    # T indicates the interface is a trunk port
                    if vlan_or_t == 'T':
                        # If it is, it sets the trunk key to True
                        config['interfaces'][interface_name] = {'trunk': True}
                    else:
                        # Otherwise, it is assumed to be a VLAN ID
                        vlan_id = int(vlan_or_t)
                        config['interfaces'][interface_name] = {'trunk': False, 'vlan': vlan_id}
                # If there is only one part, it defaults the interface to an access port with VLAN ID 1
                else:
                    config['interfaces'][interface_name] = {'trunk': False, 'vlan': 1}
    except FileNotFoundError:
        sys.exit(1)
    return config

# Represents the state and role of a switch in STP
class PortInfo:
    def __init__(self):
        self.state = BLOCKING
        self.designated = False

# Constructs and sends a BPDU frame out of a specified interface
def send_bpdu(switch_mac, root_bridge_id, sender_bridge_id, root_path_cost, interface):
    dest_mac = BPDU_DEST_MAC
    src_mac = switch_mac

    llc_header = BPDU_LLC_HEADER
    flags = 0
    # Constructs the BPDU data payload
    bpdu_data = struct.pack('!B', flags)
    bpdu_data += struct.pack('!Q', root_bridge_id)
    bpdu_data += struct.pack('!I', root_path_cost)
    bpdu_data += struct.pack('!Q', sender_bridge_id)
    bpdu_data += struct.pack('!H', interface)

    # Total length of the LLC header and the BPDU data
    llc_length = len(llc_header) + len(bpdu_data)
    # Converts the length to a 2-byte unsigned short in network byte order
    llc_length_bytes = struct.pack('!H', llc_length)

    # Constructs the full frame
    frame = dest_mac + src_mac + llc_length_bytes + llc_header + bpdu_data

    send_to_link(interface, len(frame), frame)

# Parses the BPDU data payload
def parse_bpdu(data):
    # Calculates the starting index of the BPDU data payload in the frame
    # 6 bytes for the destination MAC, 6 bytes for the source MAC, 2 bytes for the LLC length field, 3 bytes for the LLC header
    offset = 6 + 6 + 2 + 3
    # Gets the byte of the current offset position - BPDU flags
    flags = data[offset]
    # Moves past the flags byte
    offset += 1
    # Extracts 8 bytes starting from the current offset - Root Bridge ID
    root_bridge_id = int.from_bytes(data[offset:offset+8], byteorder='big')
    offset += 8
    # Extracts 4 bytes starting from the current offset - Root Path Cost
    root_path_cost = int.from_bytes(data[offset:offset+4], byteorder='big')
    offset += 4
    # Extracts 8 bytes starting from the current offset - Sender Bridge ID
    sender_bridge_id = int.from_bytes(data[offset:offset+8], byteorder='big')
    offset += 8
    # Extracts 2 bytes starting from the current offset - Port ID
    port_id = int.from_bytes(data[offset:offset+2], byteorder='big')
    return {
        'flags': flags,
        'root_bridge_id': root_bridge_id,
        'root_path_cost': root_path_cost,
        'sender_bridge_id': sender_bridge_id,
        'port_id': port_id
    }

def send_bdpu_every_sec():
    global stp_state, interfaces, interface_configs, switch_mac
    while True:
        # TODO Send BDPU every second if necessary
        # Checks if the switch is the root bridge by comparing the switch's own bridge ID with the current root bridge ID
        if stp_state['own_bridge_id'] == stp_state['root_bridge_id']:
            # Iterates over each port on the switch to check if a BPDU should be sent out of it
            for i in interfaces:
                port_config = interface_configs[i]
                # If the port is a trunk port and not in thr BLOCKING state, a BPDU is sent
                if port_config['trunk'] and stp_state['ports'][i].state != BLOCKING:
                    send_bpdu(
                        switch_mac=switch_mac,
                        root_bridge_id=stp_state['root_bridge_id'],
                        sender_bridge_id=stp_state['own_bridge_id'],
                        root_path_cost=stp_state['root_path_cost'],
                        interface=i
                    )
        time.sleep(1)

def main():
    global stp_state, interfaces, interface_configs, switch_mac

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    switch_mac = get_switch_mac()
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in switch_mac))

    config = read_config(switch_id)

    interface_names = {}
    interface_configs = {}
    # Initializes the interface's names and configurations
    for i in interfaces:
        interface_name = get_interface_name(i)
        interface_names[i] = interface_name
        if interface_name in config['interfaces']:
            interface_configs[i] = config['interfaces'][interface_name]
        else:
            interface_configs[i] = {'trunk': False, 'vlan': 1}

    # Initializes MAC address table
    mac_table = {}

    # Initializes STP state
    stp_state = {
        'own_bridge_id': config.get('priority', 32768),
        'root_bridge_id': config.get('priority', 32768),
        'root_path_cost': 0,
        'root_port': None,
        'ports': {}
    }

    for i in interfaces:
        # Creates a new PortInfo instance for the current interface
        port_info = PortInfo()
        # Gets the configuration for the current interface
        port_config = interface_configs[i]
        # If the interface is a trunk port, it is set to BLOCKING, otherwise it is set to LISTENING
        if not port_config['trunk']:
            port_info.state = LISTENING
        stp_state['ports'][i] = port_info

    # Checks is the switch is the root bridge
    if stp_state['own_bridge_id'] == stp_state['root_bridge_id']:
        for i in interfaces:
            # Sets the state of each port to LISTENING which allows them to participte in STP operations
            stp_state['ports'][i].state = LISTENING
            # Sets the designated flag to True for each port
            stp_state['ports'][i].designated = True

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        if interface == -1:
            continue

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Checks if the received frame is a BPDU
        if dest_mac == BPDU_DEST_MAC:
            bpdu = parse_bpdu(data)
            port_info = stp_state['ports'][interface]

            # Stores the current root bridge ID before any updates
            prev_root_bridge_id = stp_state['root_bridge_id']

            # Checks if the BPDU's root bridge ID is lower than the current root bridge ID
            if bpdu['root_bridge_id'] < stp_state['root_bridge_id']:
                # Updates the root bridge ID, root path cost and root port to the new values from the BPDU
                stp_state['root_bridge_id'] = bpdu['root_bridge_id']
                stp_state['root_path_cost'] = bpdu['root_path_cost']
                stp_state['root_port'] = interface
                # Checks if the switch was previously the root bridge
                if stp_state['own_bridge_id'] == prev_root_bridge_id:
                    for i in interfaces:
                        port_config = interface_configs[i]
                        # Identifies trunk ports that are not the new root port
                        if port_config['trunk'] and i != stp_state['root_port']:
                            # Sets those ports to BLOCKING to prevent loops because they are no longer designated as primary paths
                            stp_state['ports'][i].state = BLOCKING
                            stp_state['ports'][i].designated = False
                if port_info.state == BLOCKING:
                    port_info.state = LISTENING
                for i in interfaces:
                    # Skips the interface that received the BPDU
                    if i != interface:
                        port_config = interface_configs[i]
                        if port_config['trunk'] and stp_state['ports'][i].state != BLOCKING:
                            send_bpdu(
                                switch_mac=switch_mac,
                                root_bridge_id=stp_state['root_bridge_id'],
                                sender_bridge_id=stp_state['own_bridge_id'],
                                root_path_cost=stp_state['root_path_cost'],
                                interface=i
                            )
            # Checks if the BPDU's root bridge ID is the same as the current root bridge ID
            elif bpdu['root_bridge_id'] == stp_state['root_bridge_id']:
                total_cost = bpdu['root_path_cost']
                # Checks if the BPDU was received on the current root port and then searches for a better path with a lower cost
                if interface == stp_state['root_port']:
                    if total_cost < stp_state['root_path_cost']:
                        stp_state['root_path_cost'] = total_cost
                else:
                    if bpdu['root_path_cost'] > stp_state['root_path_cost']:
                        if not port_info.designated:
                            port_info.state = LISTENING
                            port_info.designated = True
                    else:
                        if interface_configs[interface]['trunk']:
                            port_info.state = BLOCKING
                            port_info.designated = False
            # Checks if the BPDU was sent by the switch itself - potential looped BPDU
            elif bpdu['sender_bridge_id'] == stp_state['own_bridge_id']:
                # If the interface is a trunk port, it is set to BLOCKING to prevent forwarding frames that originated from itself
                if interface_configs[interface]['trunk']:
                    port_info.state = BLOCKING
            # After processing the BPDU, it checks again if the switch is the root bridge
            if stp_state['own_bridge_id'] == stp_state['root_bridge_id']:
                for i in interfaces:
                    stp_state['ports'][i].state = LISTENING
                    # All ports are actively forwarding frames since the switch is the root bridge
                    stp_state['ports'][i].designated = True
            continue

        # Checks if the frame is untagged - no VLAN ID
        if vlan_id == -1:
            if interface_configs[interface]['trunk']:
                # Trunk ports expect VLAN tagged frames, so it skips untagged frames
                continue
            else:
                # Assigns the default VLAN ID for the access port so that untagged frames are associated with the correct VLAN
                vlan_id = interface_configs[interface]['vlan']
        else:
            # Checks if the frame is tagged but received on an access port and drops the frame
            if not interface_configs[interface]['trunk']:
                continue

        port_info = stp_state['ports'][interface]
        # If the port is in the BLOCKING state, it skips the frame to prevent loops
        if port_info.state == BLOCKING:
            continue

        mac_table[(vlan_id, src_mac)] = interface

        # Print the MAC src and MAC dst in human readable format
        dest_mac_str = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac_str}')
        print(f'Source MAC: {src_mac_str}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)

        is_broadcast = is_broadcast_mac(dest_mac)
        is_multicast = is_multicast_mac(dest_mac)

        if is_broadcast or is_multicast:
            for i in interfaces:
                # Skips the interface on which the frame was received to prevent looping back
                if i != interface:
                    port_config = interface_configs[i]
                    # Retrieves the port information for the current interface
                    port_info_i = stp_state['ports'][i]
                    if port_info_i.state == BLOCKING:
                        continue
                    # Checks if the port is a trunk port or an access port assigned to the same VLAN as the frame
                    if port_config['trunk'] or port_config.get('vlan') == vlan_id:
                        prepared_data, prepared_length = prepare_frame_for_sending(
                            data, vlan_id, i, interface_configs)
                        send_to_link(i, prepared_length, prepared_data)
        # If the frames are not broadcast or multicast, they are unicast frames
        else:
            # Checks if the destination MAC address is already in the MAC address table
            if (vlan_id, dest_mac) in mac_table:
                # Gets the interface associated with the destination MAC address
                out_interface = mac_table[(vlan_id, dest_mac)]
                # Makes sure the frame is not sent back on the same interface it was received on
                if out_interface != interface:
                    port_config = interface_configs[out_interface]
                    port_info_i = stp_state['ports'][out_interface]
                    if port_info_i.state == BLOCKING:
                        continue
                    if port_config['trunk'] or port_config.get('vlan') == vlan_id:
                        prepared_data, prepared_length = prepare_frame_for_sending(
                            data, vlan_id, out_interface, interface_configs)
                        send_to_link(out_interface, prepared_length, prepared_data)
            # If the destination MAC address in not in the MAC table
            else:
                # Iterates over all interfaces to flood the frame
                for i in interfaces:
                    # Skips the interface on which the frame was received
                    if i != interface:
                        port_config = interface_configs[i]
                        port_info_i = stp_state['ports'][i]
                        if port_info_i.state == BLOCKING:
                            continue
                        if port_config['trunk'] or port_config.get('vlan') == vlan_id:
                            prepared_data, prepared_length = prepare_frame_for_sending(
                                data, vlan_id, i, interface_configs)
                            send_to_link(i, prepared_length, prepared_data)

if __name__ == "__main__":
    main()
