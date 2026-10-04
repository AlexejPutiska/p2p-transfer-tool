if not bit then
    error("Modul 'bit' nie je dostupny v tomto prostredi Lua.")
end

local my_proto = Proto("AAA", "My protocol")

local f_message_type = ProtoField.uint8("myproto.message_type", "Message Type", base.HEX)
local f_sequence_number = ProtoField.uint32("myproto.sequence_number", "Sequence Number")
local f_data_size = ProtoField.uint16("myproto.data_size", "Data Size")
local f_crc = ProtoField.uint16("myproto.crc", "CRC")
local f_data = ProtoField.bytes("myproto.data", "Data")
local f_is_data = ProtoField.bool("myproto.is_data", "Is Data Message")
local f_packet_type = ProtoField.string("myproto.packet_type", "Packet Type")

local f_flag_text = ProtoField.bool("myproto.flag_text", "TEXT", 8, nil, 0x01)
local f_flag_file = ProtoField.bool("myproto.flag_file", "FILE", 8, nil, 0x02)
local f_flag_ack = ProtoField.bool("myproto.flag_ack", "ACK", 8, nil, 0x04)
local f_flag_syn = ProtoField.bool("myproto.flag_syn", "SYN", 8, nil, 0x08)
local f_flag_heartbeat = ProtoField.bool("myproto.flag_heartbeat", "HEARTBEAT", 8, nil, 0x10)
local f_flag_nack = ProtoField.bool("myproto.flag_nack", "NACK", 8, nil, 0x20)
local f_flag_fin = ProtoField.bool("myproto.flag_fin", "FIN", 8, nil, 0x40)
local f_flag_last_fragment = ProtoField.bool("myproto.flag_last_fragment", "LAST_FRAGMENT", 8, nil, 0x80)

my_proto.fields = {
    f_message_type, f_sequence_number, f_data_size, f_crc, f_data, f_is_data, f_packet_type,
    f_flag_text, f_flag_file, f_flag_ack, f_flag_syn, f_flag_heartbeat,
    f_flag_nack, f_flag_fin, f_flag_last_fragment
}

local FLAG_TEXT = 0x01
local FLAG_FILE = 0x02
local FLAG_ACK = 0x04
local FLAG_SYN = 0x08
local FLAG_HEARTBEAT = 0x10
local FLAG_NACK = 0x20
local FLAG_FIN = 0x40
local FLAG_LAST_FRAGMENT = 0x80

my_proto.prefs.port = Pref.uint("UDP Port", 12345, "UDP port to decode My Custom Protocol")

function my_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = my_proto.name

    if buffer:len() < 9 then
        pinfo.cols.info = "Packet too short"
        return
    end

    local subtree = tree:add(my_proto, buffer(), "Custom protocol data")

    local message_type = buffer(0,1):uint()
    local sequence_number = buffer(1,4):uint()
    local data_size = buffer(5,2):uint()
    local crc = buffer(7,2):uint()

    local message_type_field = subtree:add(f_message_type, buffer(0,1))

    message_type_field:add(f_flag_text, buffer(0,1))
    message_type_field:add(f_flag_file, buffer(0,1))
    message_type_field:add(f_flag_ack, buffer(0,1))
    message_type_field:add(f_flag_syn, buffer(0,1))
    message_type_field:add(f_flag_heartbeat, buffer(0,1))
    message_type_field:add(f_flag_nack, buffer(0,1))
    message_type_field:add(f_flag_fin, buffer(0,1))
    message_type_field:add(f_flag_last_fragment, buffer(0,1))

    subtree:add(f_sequence_number, buffer(1,4))
    subtree:add(f_data_size, buffer(5,2))
    subtree:add(f_crc, buffer(7,2))

    local data_len = buffer:len() - 9
    if data_len > 0 then
        subtree:add(f_data, buffer(9, data_len))
    end

    local is_data_message = (message_type == FLAG_TEXT) or (message_type == FLAG_FILE) or (bit.band(message_type, FLAG_LAST_FRAGMENT) ~= 0)
    subtree:add(f_is_data, is_data_message)

    local packet_type_str = "CONTROL"
    if is_data_message then
        packet_type_str = "DATA"
    end
    subtree:add(f_packet_type, packet_type_str)

   
    local message_type_descriptions = {}
    if bit.band(message_type, FLAG_TEXT) ~= 0 then
        table.insert(message_type_descriptions, "TEXT")
    end
    if bit.band(message_type, FLAG_FILE) ~= 0 then
        table.insert(message_type_descriptions, "FILE")
    end
    if bit.band(message_type, FLAG_ACK) ~= 0 then
        table.insert(message_type_descriptions, "ACK")
    end
    if bit.band(message_type, FLAG_SYN) ~= 0 then
        table.insert(message_type_descriptions, "SYN")
    end
    if bit.band(message_type, FLAG_HEARTBEAT) ~= 0 then
        table.insert(message_type_descriptions, "HEARTBEAT")
    end
    if bit.band(message_type, FLAG_NACK) ~= 0 then
        table.insert(message_type_descriptions, "NACK")
    end
    if bit.band(message_type, FLAG_FIN) ~= 0 then
        table.insert(message_type_descriptions, "FIN")
    end
    if bit.band(message_type, FLAG_LAST_FRAGMENT) ~= 0 then
        table.insert(message_type_descriptions, "LAST_FRAGMENT")
    end

    local message_type_string = table.concat(message_type_descriptions, " | ")

    if is_data_message then
        pinfo.cols.info = "DATA PACKET: " .. message_type_string
    else
        pinfo.cols.info = "CONTROL PACKET: " .. message_type_string
    end
end

function my_proto.init()
    local udp_port = DissectorTable.get("udp.port")
    udp_port:add(my_proto.prefs.port, my_proto)
end
