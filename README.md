# P2P Transfer Tool

A peer-to-peer program for sending text messages and files over UDP. Because UDP gives no delivery guarantees, the program implements its own transport layer on top of UDP sockets: connection setup and teardown, fragmentation, CRC16 checksums, acknowledgement of every fragment with retransmission, and a keepalive heartbeat. Both peers run the same program and have equal roles. Either peer can initiate the connection, and either one can send messages or files once it is established. A Wireshark dissector for the protocol is included.

## Packet format

Every packet is one UDP datagram: a 9 byte header followed by an optional payload of up to 1463 bytes. Multi-byte fields are big endian (`struct` format `!BIHH`).

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 1 byte | Type | message type, a combination of flag bits (see below) |
| 1 | 4 bytes | Sequence number | counter of the sending peer, increased with every packet it sends |
| 5 | 2 bytes | Payload length | number of payload bytes after the header |
| 7 | 2 bytes | CRC16 | checksum of the payload |

The CRC16 is computed with `crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, xorOut=0x0000)`. A packet without a payload carries the checksum of empty data, `0xFFFF`.

The payload is limited to 1463 bytes so that a packet fits into one standard Ethernet frame: 1500 bytes of MTU, minus 20 for the IPv4 header, 8 for the UDP header and 9 for this header.

Example, the last fragment of the text message `hello` with sequence number 2:

```
81 | 00 00 00 02 | 00 05  | cb 42 | 68 65 6c 6c 6f
type  sequence     length   crc     payload ("hello")
```

### Message types

The type byte is a set of flags:

| Bit | Value | Flag | Meaning |
|---|---|---|---|
| 0 | 0x01 | TEXT | text message data |
| 1 | 0x02 | FILE | file data |
| 2 | 0x04 | ACK | acknowledgement |
| 3 | 0x08 | SYN | connection setup |
| 4 | 0x10 | HEARTBEAT | keepalive |
| 5 | 0x20 | NACK | negative acknowledgement |
| 6 | 0x40 | FIN | connection teardown |
| 7 | 0x80 | LAST_FRAGMENT | final fragment of a message or file |

The combinations used by the program:

| Packet | Type | Sent when |
|---|---|---|
| SYN | 0x08 | the initiator opens the connection |
| SYN + ACK | 0x0C | the other peer answers the SYN |
| ACK | 0x04 | the handshake is completed, and during teardown |
| TEXT | 0x01 | a fragment of a text message |
| TEXT + LAST_FRAGMENT | 0x81 | the final fragment of a text message |
| TEXT + ACK | 0x05 | the receiver confirms a text fragment |
| TEXT + NACK | 0x21 | a text fragment arrived with a wrong CRC |
| FILE | 0x02 | the file name (first packet), then the file fragments |
| FILE + LAST_FRAGMENT | 0x82 | the final fragment of a file |
| FILE + ACK | 0x06 | the receiver confirms the file name or a file fragment |
| FILE + NACK | 0x22 | a file packet arrived with a wrong CRC |
| HEARTBEAT | 0x10 | keepalive probe |
| HEARTBEAT + ACK | 0x14 | reply to a probe |
| NACK | 0x20 | a control packet arrived with a wrong CRC |
| FIN | 0x40 | a peer closes the connection |

A NACK carries the 4 byte sequence number of the damaged packet as its payload.

## How it works

**Connection setup.** The initiating peer sends a SYN and repeats it every 2 seconds until it gets an answer. The other peer replies with SYN + ACK, and the initiator completes the handshake with an ACK. Data packets are not accepted before the handshake is finished.

**Fragmentation.** Messages and files are split into fragments of up to 1463 bytes. The fragment size can be lowered for each transfer, from 1 to 1463 bytes. A file transfer starts with a FILE packet whose payload is the file name, followed by the data fragments. The last fragment of a message or file has the LAST_FRAGMENT flag set, and the receiver then assembles the message or writes the file.

**Reliability.** The protocol uses stop-and-wait ARQ: after sending a fragment, the sender waits for its ACK before it sends the next one. The receiver verifies the CRC16 of every packet. On a mismatch it answers with a NACK that carries the sequence number of the damaged packet, and the sender transmits that fragment again under a new sequence number. Only the damaged fragment is repeated. Go-Back-N was the original plan, and stop-and-wait was chosen because it retransmits just the broken fragment, at the cost of throughput.

**Keepalive.** While a connection is idle, each peer sends a HEARTBEAT every 5 seconds and the other peer answers with HEARTBEAT + ACK. After 3 unanswered heartbeats in a row the connection is treated as lost.

**Teardown.** The peer that exits sends a FIN. The other peer answers with an ACK and then its own FIN, and the first peer closes with a final ACK. The second peer is then asked to press ENTER to finish.

## Usage

```bash
pip install -r requirements.txt
python peer.py
```

Start `peer.py` once per peer, in two terminals or on two machines. Each instance asks for the local port, the other peer's IP address, the other peer's port, and whether it should start the handshake. Answer exactly `yes` or `no`: one side says `yes`, the other says `no` and waits.

On one machine any two free ports work. Use `127.0.0.1` as the address and swap the ports:

| | Peer A | Peer B |
|---|---|---|
| local port | 5001 | 5002 |
| target IP | 127.0.0.1 | 127.0.0.1 |
| target port | 5002 | 5001 |
| initiate handshake | yes | no |

Across two machines, enter the IP address of the other machine and allow the UDP port in the firewall.

After the handshake both peers show the same menu:

| Key | Action |
|---|---|
| `m` | send a message |
| `f` | send a file |
| `p` | change the folder where received files are saved |
| `s` | corrupt a chosen fragment on purpose, to watch the retransmission |
| `e` | exit |

Received files are saved in the folder the program was started from, unless it is changed with `p`.

## Wireshark dissector

`wireshark/dissector.lua` decodes the protocol in Wireshark. For every packet it shows the type flags, sequence number, payload length, CRC and payload, and it labels the packet as control or data, so the packet list contains entries such as `CONTROL PACKET: SYN` and `DATA PACKET: TEXT | LAST_FRAGMENT`.

To install it, copy the file into Wireshark's plugins folder (Help > About Wireshark > Folders shows where it is) and restart Wireshark. The protocol is registered as AAA. Set the UDP port in its preferences (the default is 12345) or use Analyze > Decode As.

## Requirements and limitations

Python 3 (tested with 3.10) and the `crcmod` package. The program uses IPv4, handles one connection per running instance and does not encrypt or authenticate anything. Since every fragment is acknowledged before the next one is sent, throughput is limited: a 2 MB file took about 22 seconds between two peers on one machine.

Tested by transferring a 2 MB file between two local peers and by forcing CRC errors on chosen fragments with the `s` command, which exercises the NACK and retransmission path.
