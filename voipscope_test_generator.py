#!/usr/bin/env python3
"""
generate_test_pcaps.py
Generate test PCAP files with various VoIP issues for VoIPScope testing

Scenarios:
1. Normal call (baseline)
2. One-way audio (caller can't hear callee)
3. NAT routing issue (SDP has private IP)
4. Missing TAG (To-Tag absent in 200 OK)
5. High jitter and packet loss

Requirements:
    pip install scapy

Usage:
    python generate_test_pcaps.py
"""

from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.rtp import RTP
import random
import time

def create_sip_packet(src_ip, dst_ip, src_port, dst_port, sip_msg):
    """Create a SIP packet"""
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=sip_msg.encode())
    return pkt

def create_rtp_packet(src_ip, dst_ip, src_port, dst_port, seq, timestamp, ssrc, payload_type=0):
    """Create an RTP packet"""
    rtp = RTP(
        version=2,
        padding=0,
        extension=0,
        numsync=0,
        marker=0,
        payload_type=payload_type,
        sequence=seq,
        timestamp=timestamp,
        sourcesync=ssrc
    )
    payload = bytes([random.randint(0, 255) for _ in range(160)])
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / rtp / Raw(load=payload)
    return pkt

# ==================== SCENARIO 1: NORMAL CALL ====================

def generate_normal_call():
    """Generate a normal, healthy VoIP call"""
    print("📋 Scenario 1: Normal Call")
    
    packets = []
    
    caller_ip = "192.168.1.100"
    caller_pub_ip = "203.0.113.50"
    callee_ip = "198.51.100.20"
    proxy_ip = "198.51.100.10"
    
    caller_sip_port = 5060
    callee_sip_port = 5060
    caller_rtp_port = 10000
    callee_rtp_port = 20000
    
    call_id = "normal-call-abc123@voipscope.test"
    from_tag = "tag-normal-caller"
    to_tag = "tag-normal-callee"
    branch_id = "z9hG4bK-normal-001"
    
    base_time = time.time()
    current_time = base_time
    
    def add_pkt(pkt, delta=0.0):
        nonlocal current_time
        current_time += delta
        pkt.time = current_time
        packets.append(pkt)
    
    # INVITE
    invite_msg = f"""INVITE sip:1002@{proxy_ip} SIP/2.0
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id};rport
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1002@{proxy_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Contact: <sip:1001@{caller_pub_ip}:{caller_sip_port}>
Content-Type: application/sdp
Content-Length: 200

v=0
o=caller 12345 67890 IN IP4 {caller_pub_ip}
s=Normal Call
c=IN IP4 {caller_pub_ip}
t=0 0
m=audio {caller_rtp_port} RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
"""
    add_pkt(create_sip_packet(caller_ip, proxy_ip, caller_sip_port, 5060, invite_msg))
    
    # 100 TRYING
    trying_msg = f"""SIP/2.0 100 Trying
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id};received={caller_pub_ip}
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1002@{proxy_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Length: 0

"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, trying_msg), 0.05)
    
    # 180 RINGING
    ringing_msg = f"""SIP/2.0 180 Ringing
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id};received={caller_pub_ip}
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1002@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 INVITE
Contact: <sip:1002@{callee_ip}:{callee_sip_port}>
Content-Length: 0

"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ringing_msg), 0.3)
    
    # 200 OK
    ok_msg = f"""SIP/2.0 200 OK
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id};received={caller_pub_ip}
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1002@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 INVITE
Contact: <sip:1002@{callee_ip}:{callee_sip_port}>
Content-Type: application/sdp
Content-Length: 180

v=0
o=callee 98765 43210 IN IP4 {callee_ip}
s=Normal Call
c=IN IP4 {callee_ip}
t=0 0
m=audio {callee_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ok_msg), 0.5)
    
    # ACK
    ack_msg = f"""ACK sip:1002@{callee_ip}:{callee_sip_port} SIP/2.0
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id}-ack
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1002@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 ACK
Content-Length: 0

"""
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, callee_sip_port, ack_msg), 0.02)
    
    # RTP - Bidirectional, healthy
    ssrc_caller = 0x11111111
    ssrc_callee = 0x22222222
    seq_caller = 1000
    seq_callee = 2000
    ts_caller = 0
    ts_callee = 0
    
    for i in range(100):
        # Caller → Callee
        add_pkt(create_rtp_packet(
            caller_pub_ip, callee_ip,
            caller_rtp_port, callee_rtp_port,
            seq_caller, ts_caller, ssrc_caller, 0
        ), 0.020)
        seq_caller += 1
        ts_caller += 160
        
        # Callee → Caller
        add_pkt(create_rtp_packet(
            callee_ip, caller_pub_ip,
            callee_rtp_port, caller_rtp_port,
            seq_callee, ts_callee, ssrc_callee, 0
        ), 0.020)
        seq_callee += 1
        ts_callee += 160
    
    # BYE
    bye_msg = f"""BYE sip:1002@{callee_ip} SIP/2.0
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id}-bye
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1002@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 2 BYE
Content-Length: 0

"""
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, callee_sip_port, bye_msg), 0.1)
    
    # 200 OK (BYE)
    bye_ok = f"""SIP/2.0 200 OK
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id}-bye
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1002@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 2 BYE
Content-Length: 0

"""
    add_pkt(create_sip_packet(callee_ip, caller_ip, callee_sip_port, caller_sip_port, bye_ok), 0.05)
    
    filename = "test_normal_call.pcap"
    wrpcap(filename, packets)
    print(f"  ✅ Generated: {filename} ({len(packets)} packets)")
    print(f"  📊 Expected: Healthy call, MOS ~4.3, no issues\n")

# ==================== SCENARIO 2: ONE-WAY AUDIO ====================

def generate_oneway_audio():
    """Generate call with one-way audio (callee can't send RTP)"""
    print("📋 Scenario 2: One-Way Audio")
    
    packets = []
    
    caller_ip = "192.168.1.100"
    caller_pub_ip = "203.0.113.51"
    callee_ip = "198.51.100.21"
    proxy_ip = "198.51.100.10"
    
    caller_sip_port = 5060
    callee_sip_port = 5060
    caller_rtp_port = 10001
    callee_rtp_port = 20001
    
    call_id = "oneway-call-def456@voipscope.test"
    from_tag = "tag-oneway-caller"
    to_tag = "tag-oneway-callee"
    branch_id = "z9hG4bK-oneway-002"
    
    base_time = time.time()
    current_time = base_time
    
    def add_pkt(pkt, delta=0.0):
        nonlocal current_time
        current_time += delta
        pkt.time = current_time
        packets.append(pkt)
    
    # SIP signaling (same as normal)
    invite_msg = f"""INVITE sip:1003@{proxy_ip} SIP/2.0
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id};rport
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1003@{proxy_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Contact: <sip:1001@{caller_pub_ip}:{caller_sip_port}>
Content-Type: application/sdp
Content-Length: 200

v=0
o=caller 12345 67890 IN IP4 {caller_pub_ip}
s=One-Way Audio Test
c=IN IP4 {caller_pub_ip}
t=0 0
m=audio {caller_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(caller_ip, proxy_ip, caller_sip_port, 5060, invite_msg))
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, "SIP/2.0 100 Trying\r\n\r\n"), 0.05)
    
    ringing_msg = f"""SIP/2.0 180 Ringing
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1006@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Length: 0

"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ringing_msg), 0.3)
    
    ok_msg = f"""SIP/2.0 200 OK
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1006@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 180

v=0
o=callee 98765 43210 IN IP4 {callee_ip}
s=Poor Quality Test
c=IN IP4 {callee_ip}
t=0 0
m=audio {callee_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ok_msg), 0.5)
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, 5060, "ACK\r\n\r\n"), 0.02)
    
    # RTP with HIGH JITTER and PACKET LOSS
    ssrc_caller = 0x88888888
    ssrc_callee = 0x99999999
    seq_caller = 8000
    seq_callee = 9000
    ts_caller = 0
    ts_callee = 0
    
    for i in range(150):
        # Random jitter (0-60ms variance)
        jitter = random.uniform(0, 0.060)
        
        # 10% packet loss (skip packet randomly)
        if random.random() > 0.10:
            add_pkt(create_rtp_packet(
                caller_pub_ip, callee_ip,
                caller_rtp_port, callee_rtp_port,
                seq_caller, ts_caller, ssrc_caller, 0
            ), 0.020 + jitter)
        
        seq_caller += 1
        ts_caller += 160
        
        # Callee also has issues
        if random.random() > 0.10:
            add_pkt(create_rtp_packet(
                callee_ip, caller_pub_ip,
                callee_rtp_port, caller_rtp_port,
                seq_callee, ts_callee, ssrc_callee, 0
            ), 0.020 + jitter)
        
        seq_callee += 1
        ts_callee += 160
    
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, 5060, "BYE\r\n\r\n"), 0.1)
    add_pkt(create_sip_packet(callee_ip, caller_ip, 5060, caller_sip_port, "SIP/2.0 200 OK\r\n\r\n"), 0.05)
    
    filename = "test_poor_quality.pcap"
    wrpcap(filename, packets)
    print(f"  ✅ Generated: {filename} ({len(packets)} packets)")
    print(f"  📊 Expected: HIGH - Poor call quality (high jitter, ~10% packet loss, MOS < 3.0)\n")

# ==================== MAIN ====================

def main():
    print("\n" + "="*70)
    print("VoIPScope Test PCAP Generator")
    print("Generating test scenarios for diagnostic validation")
    print("="*70 + "\n")
    
    try:
        generate_normal_call()
        generate_oneway_audio()
        generate_nat_issue()
        generate_missing_tag()
        generate_poor_quality()
        
        print("="*70)
        print("✅ All test PCAPs generated successfully!")
        print("="*70)
        print("\nTest scenarios created:")
        print("  1. test_normal_call.pcap         - Baseline (healthy call)")
        print("  2. test_oneway_audio.pcap        - One-way audio issue")
        print("  3. test_nat_routing_issue.pcap   - NAT/routing problem")
        print("  4. test_missing_tag.pcap         - Missing To-Tag")
        print("  5. test_poor_quality.pcap        - High jitter + packet loss")
        print("\nRun VoIPScope on these files to test diagnostic capabilities:")
        print("  python voipscope.py")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error generating test PCAPs: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
Trying\r\n\r\n"), 0.05)
    
    ringing_msg = f"""SIP/2.0 180 Ringing
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1003@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Length: 0

"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ringing_msg), 0.3)
    
    ok_msg = f"""SIP/2.0 200 OK
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1003@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 180

v=0
o=callee 98765 43210 IN IP4 {callee_ip}
s=One-Way Audio Test
c=IN IP4 {callee_ip}
t=0 0
m=audio {callee_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ok_msg), 0.5)
    
    ack_msg = f"""ACK sip:1003@{callee_ip} SIP/2.0
Call-ID: {call_id}
CSeq: 1 ACK
Content-Length: 0

"""
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, callee_sip_port, ack_msg), 0.02)
    
    # RTP - ONLY CALLER SENDS (One-Way!)
    ssrc_caller = 0x33333333
    seq_caller = 3000
    ts_caller = 0
    
    for i in range(100):
        add_pkt(create_rtp_packet(
            caller_pub_ip, callee_ip,
            caller_rtp_port, callee_rtp_port,
            seq_caller, ts_caller, ssrc_caller, 0
        ), 0.020)
        seq_caller += 1
        ts_caller += 160
    
    # BYE
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, callee_sip_port, "BYE\r\n\r\n"), 0.1)
    add_pkt(create_sip_packet(callee_ip, caller_ip, callee_sip_port, caller_sip_port, "SIP/2.0 200 OK\r\n\r\n"), 0.05)
    
    filename = "test_oneway_audio.pcap"
    wrpcap(filename, packets)
    print(f"  ✅ Generated: {filename} ({len(packets)} packets)")
    print(f"  📊 Expected: CRITICAL - One-Way Audio detected\n")

# ==================== SCENARIO 3: NAT ROUTING ISSUE ====================

def generate_nat_issue():
    """Generate call with NAT routing problem (SDP has private IP)"""
    print("📋 Scenario 3: NAT Routing Issue")
    
    packets = []
    
    caller_ip = "192.168.1.100"
    caller_pub_ip = "203.0.113.52"
    callee_ip = "198.51.100.22"
    proxy_ip = "198.51.100.10"
    
    caller_sip_port = 5060
    caller_rtp_port = 10002
    callee_rtp_port = 20002
    
    call_id = "nat-issue-ghi789@voipscope.test"
    from_tag = "tag-nat-caller"
    to_tag = "tag-nat-callee"
    branch_id = "z9hG4bK-nat-003"
    
    base_time = time.time()
    current_time = base_time
    
    def add_pkt(pkt, delta=0.0):
        nonlocal current_time
        current_time += delta
        pkt.time = current_time
        packets.append(pkt)
    
    # INVITE with PRIVATE IP in SDP (NAT issue!)
    invite_msg = f"""INVITE sip:1004@{proxy_ip} SIP/2.0
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id};rport
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1004@{proxy_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Contact: <sip:1001@{caller_pub_ip}:{caller_sip_port}>
Content-Type: application/sdp
Content-Length: 200

v=0
o=caller 12345 67890 IN IP4 {caller_ip}
s=NAT Issue Test
c=IN IP4 {caller_ip}
t=0 0
m=audio {caller_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(caller_ip, proxy_ip, caller_sip_port, 5060, invite_msg))
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, "SIP/2.0 100 Trying\r\n\r\n"), 0.05)
    
    ringing_msg = f"""SIP/2.0 180 Ringing
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1004@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Length: 0

"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ringing_msg), 0.3)
    
    ok_msg = f"""SIP/2.0 200 OK
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1004@{proxy_ip}>;tag={to_tag}
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 180

v=0
o=callee 98765 43210 IN IP4 {callee_ip}
s=NAT Issue Test
c=IN IP4 {callee_ip}
t=0 0
m=audio {callee_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ok_msg), 0.5)
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, 5060, "ACK\r\n\r\n"), 0.02)
    
    # RTP from PUBLIC IP (not matching private IP in SDP!)
    ssrc_caller = 0x44444444
    ssrc_callee = 0x55555555
    seq_caller = 4000
    seq_callee = 5000
    ts_caller = 0
    ts_callee = 0
    
    for i in range(50):
        add_pkt(create_rtp_packet(
            caller_pub_ip, callee_ip,  # From PUBLIC IP, not private!
            caller_rtp_port, callee_rtp_port,
            seq_caller, ts_caller, ssrc_caller, 0
        ), 0.020)
        seq_caller += 1
        ts_caller += 160
        
        add_pkt(create_rtp_packet(
            callee_ip, caller_pub_ip,
            callee_rtp_port, caller_rtp_port,
            seq_callee, ts_callee, ssrc_callee, 0
        ), 0.020)
        seq_callee += 1
        ts_callee += 160
    
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, 5060, "BYE\r\n\r\n"), 0.1)
    add_pkt(create_sip_packet(callee_ip, caller_ip, 5060, caller_sip_port, "SIP/2.0 200 OK\r\n\r\n"), 0.05)
    
    filename = "test_nat_routing_issue.pcap"
    wrpcap(filename, packets)
    print(f"  ✅ Generated: {filename} ({len(packets)} packets)")
    print(f"  📊 Expected: HIGH - NAT routing issue (SDP has private IP but RTP from public IP)\n")

# ==================== SCENARIO 4: MISSING TAG ====================

def generate_missing_tag():
    """Generate call with missing To-Tag in 200 OK"""
    print("📋 Scenario 4: Missing TAG")
    
    packets = []
    
    caller_ip = "192.168.1.100"
    caller_pub_ip = "203.0.113.53"
    callee_ip = "198.51.100.23"
    proxy_ip = "198.51.100.10"
    
    caller_sip_port = 5060
    caller_rtp_port = 10003
    callee_rtp_port = 20003
    
    call_id = "missing-tag-jkl012@voipscope.test"
    from_tag = "tag-missing-caller"
    # NO To-Tag in this scenario!
    branch_id = "z9hG4bK-missing-004"
    
    base_time = time.time()
    current_time = base_time
    
    def add_pkt(pkt, delta=0.0):
        nonlocal current_time
        current_time += delta
        pkt.time = current_time
        packets.append(pkt)
    
    invite_msg = f"""INVITE sip:1005@{proxy_ip} SIP/2.0
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id};rport
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1005@{proxy_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 200

v=0
o=caller 12345 67890 IN IP4 {caller_pub_ip}
s=Missing TAG Test
c=IN IP4 {caller_pub_ip}
t=0 0
m=audio {caller_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(caller_ip, proxy_ip, caller_sip_port, 5060, invite_msg))
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, "SIP/2.0 100 Trying\r\n\r\n"), 0.05)
    
    # 180 Ringing WITHOUT To-Tag
    ringing_msg = f"""SIP/2.0 180 Ringing
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1005@{proxy_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Length: 0

"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ringing_msg), 0.3)
    
    # 200 OK WITHOUT To-Tag (Bug!)
    ok_msg = f"""SIP/2.0 200 OK
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1005@{proxy_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 180

v=0
o=callee 98765 43210 IN IP4 {callee_ip}
s=Missing TAG Test
c=IN IP4 {callee_ip}
t=0 0
m=audio {callee_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, ok_msg), 0.5)
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, 5060, "ACK\r\n\r\n"), 0.02)
    
    # Normal RTP
    ssrc_caller = 0x66666666
    ssrc_callee = 0x77777777
    seq_caller = 6000
    seq_callee = 7000
    ts_caller = 0
    ts_callee = 0
    
    for i in range(50):
        add_pkt(create_rtp_packet(
            caller_pub_ip, callee_ip,
            caller_rtp_port, callee_rtp_port,
            seq_caller, ts_caller, ssrc_caller, 0
        ), 0.020)
        seq_caller += 1
        ts_caller += 160
        
        add_pkt(create_rtp_packet(
            callee_ip, caller_pub_ip,
            callee_rtp_port, caller_rtp_port,
            seq_callee, ts_callee, ssrc_callee, 0
        ), 0.020)
        seq_callee += 1
        ts_callee += 160
    
    add_pkt(create_sip_packet(caller_ip, callee_ip, caller_sip_port, 5060, "BYE\r\n\r\n"), 0.1)
    add_pkt(create_sip_packet(callee_ip, caller_ip, 5060, caller_sip_port, "SIP/2.0 200 OK\r\n\r\n"), 0.05)
    
    filename = "test_missing_tag.pcap"
    wrpcap(filename, packets)
    print(f"  ✅ Generated: {filename} ({len(packets)} packets)")
    print(f"  📊 Expected: MEDIUM - To-Tag missing in 200 OK\n")

# ==================== SCENARIO 5: POOR QUALITY ====================

def generate_poor_quality():
    """Generate call with high jitter and packet loss"""
    print("📋 Scenario 5: Poor Quality (High Jitter + Packet Loss)")
    
    packets = []
    
    caller_ip = "192.168.1.100"
    caller_pub_ip = "203.0.113.54"
    callee_ip = "198.51.100.24"
    proxy_ip = "198.51.100.10"
    
    caller_sip_port = 5060
    caller_rtp_port = 10004
    callee_rtp_port = 20004
    
    call_id = "poor-quality-mno345@voipscope.test"
    from_tag = "tag-poor-caller"
    to_tag = "tag-poor-callee"
    branch_id = "z9hG4bK-poor-005"
    
    base_time = time.time()
    current_time = base_time
    
    def add_pkt(pkt, delta=0.0):
        nonlocal current_time
        current_time += delta
        pkt.time = current_time
        packets.append(pkt)
    
    # Normal SIP signaling
    invite_msg = f"""INVITE sip:1006@{proxy_ip} SIP/2.0
Via: SIP/2.0/UDP {caller_ip}:{caller_sip_port};branch={branch_id};rport
From: "User 1001" <sip:1001@{caller_ip}>;tag={from_tag}
To: <sip:1006@{proxy_ip}>
Call-ID: {call_id}
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 200

v=0
o=caller 12345 67890 IN IP4 {caller_pub_ip}
s=Poor Quality Test
c=IN IP4 {caller_pub_ip}
t=0 0
m=audio {caller_rtp_port} RTP/AVP 0
a=rtpmap:0 PCMU/8000
"""
    add_pkt(create_sip_packet(caller_ip, proxy_ip, caller_sip_port, 5060, invite_msg))
    add_pkt(create_sip_packet(proxy_ip, caller_ip, 5060, caller_sip_port, "SIP/2.0 100 