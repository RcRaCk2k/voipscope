# VoIPScope v1.1 - Enhanced Edition

**Professional VoIP Diagnostic & Analysis Tool**

*"See beyond the call"*

---

## 🎯 Overview

VoIPScope is an automated VoIP troubleshooting tool that analyzes PCAP files and generates comprehensive diagnostic reports. It detects common VoIP issues like one-way audio, **clipped audio**, **silent calls**, NAT problems, TAG mismatches, and call quality degradation.

### Key Features

✅ **Automatic SIP/RTP Analysis**
- Parses SIP signaling and RTP media streams
- Correlates SIP calls with RTP flows using SDP

✅ **MOS Score Calculation**
- ITU-T E-Model based quality scoring
- Real-time quality assessment (1.0 - 4.5 scale)

✅ **Clipped Audio Detection** 🆕 **NEW in v1.1**
- Detects delayed media start after call establishment
- Measures SIP-to-RTP delay (the "Hello? HELLO?!" problem)
- Identifies firewall port opening delays

✅ **Silent Call Detection** 🆕 **NEW in v1.1**
- Detects calls with no RTP media despite being established
- Identifies SDP negotiation failures
- Helps troubleshoot codec support issues

✅ **Call Setup Delay Analysis** 🆕 **NEW in v1.1**
- Measures INVITE → 200 OK delay
- Identifies slow call establishment
- Flags DNS/network latency issues

✅ **Codec Mismatch Warnings** 🆕 **NEW in v1.1**
- Detects SDP vs actual RTP codec mismatches
- Identifies transcoding scenarios
- Flags unexpected codec usage

✅ **DTMF Detection (RFC2833)** 🆕 **NEW in v1.1**
- Detects DTMF events in RTP streams
- Useful for IVR troubleshooting
- Tracks touch-tone signaling

✅ **Advanced Diagnostics**
- One-Way Audio detection
- NAT/Routing issue identification
- SIP TAG validation
- SDP vs Actual RTP comparison

✅ **Comprehensive Excel Reports**
- 6-sheet detailed analysis
- Color-coded quality indicators
- 14-column call summary with all diagnostics 🆕
- Actionable recommendations

---

## 📦 Installation

### Requirements

- Python 3.8+
- TShark (Wireshark command-line tool)

### Install Dependencies

```bash
pip install pyshark pandas openpyxl
```

### Verify TShark Installation

```bash
tshark --version
```

If TShark is not found, install Wireshark from: https://www.wireshark.org/download.html

---

## 🚀 Quick Start

### 1. Generate Test PCAPs (Optional)

```bash
python generate_test_pcaps.py
```

This creates test scenarios including:
- Normal call (baseline)
- One-way audio
- Clipped audio 🆕
- Silent call 🆕
- NAT routing issue
- Missing TAG
- Poor quality (high jitter + packet loss)

### 2. Run VoIPScope

```bash
python voipscope_v1.py
```

VoIPScope will:
1. Scan current directory for `.pcap` or `.pcapng` files
2. Analyze SIP signaling and RTP media
3. Detect issues automatically (including clipped audio 🆕)
4. Generate Excel report: `VoIPScope_Report_YYYYMMDD_HHMMSS.xlsx`

---

## 📊 Excel Report Structure

### Sheet 1: Call Summary
Overview of all calls with MOS scores and issue counts.

**Columns:**
- Call-ID
- From/To numbers
- Start/End time
- Duration
- RTP stream count
- Average MOS
- Quality rating
- **Clipped Audio** 🆕 (✅ No / ⚠️ XXXms / 🔴 XXXms)
- **Silent Call** 🆕 (✅ No / ⚠️ X pkts / 🔴 0 pkts)
- **Setup Delay** 🆕 (✅ Normal / ⚠️ XXXms / 🔴 XXXms)
- **DTMF** 🆕 (— / 📞 X pkts)
- Issue count

### Sheet 2: RTP Streams
Detailed metrics for each RTP stream.

**Columns:**
- Stream (IP:port → IP:port)
- Direction (Caller→Callee / Callee→Caller)
- SSRC
- Codec (G.711, G.729, etc.)
- Packet count
- Duration
- **Jitter (ms)** - Packet timing variance
- **Loss (%)** - Packet loss percentage
- **Delay (ms)** - One-way delay
- **MOS** - Call quality score
- Quality rating

### Sheet 3: SDP Analysis
SDP content from SIP INVITE and 200 OK messages.

**Shows:**
- Expected RTP IP/port from SDP
- Codec negotiations
- NAT warnings (private IP detection)

### Sheet 4: TAG Analysis
SIP dialog validation using From-Tag and To-Tag.

**Detects:**
- Missing TAGs
- TAG mismatches
- Dialog continuity issues

### Sheet 5: Issues & Recommendations ⭐
**Most Important Sheet!**

Lists all detected issues with:
- Severity (CRITICAL, HIGH, MEDIUM, LOW)
- Issue type (One-Way Audio, Clipped Audio, Silent Call, Slow Call Setup, Codec Mismatch, etc.) 🆕
- Description
- Root cause analysis
- **Actionable recommendations**

### Sheet 6: Quality Report
Summary statistics and interpretation guides.

**Includes:**
- MOS score interpretation
- **Clipped Audio detection guide** 🆕
- **Silent Call detection guide** 🆕
- **Call Setup Delay guide** 🆕
- Issue severity levels
- Overall health assessment

---

## 🔍 Issue Detection

### 1. One-Way Audio (CRITICAL)

**Symptoms:**
- RTP packets only in one direction
- Severe packet imbalance (>90% difference)

**Causes:**
- Firewall blocking RTP
- NAT traversal failure
- Asymmetric routing

**VoIPScope Detection:**
Compares packet counts in both directions. If one direction has 0 packets or <10% of expected, flags as one-way audio.

---

### 2. Clipped Audio (CRITICAL/HIGH) 🆕 **NEW in v1.1**

**Symptoms:**
- Call establishes successfully (SIP 200 OK received)
- But first 2-3 seconds of audio are silent
- Users say "Hello? HELLO?!" at call start
- Media starts late after signaling completes

**Causes:**
- Firewall learning rules (delayed port opening)
- NAT port allocation delay
- STUN/ICE negotiation timeout
- Jitter buffer initialization delay
- Router taking time to process SIP ALG

**VoIPScope Detection:**
Measures time between SIP 200 OK and first RTP packet:
- **Normal:** < 500ms
- **Warning:** 500ms - 2000ms (⚠️ First word may be cut)
- **Critical:** > 2000ms (🔴 Significant clipping)

**Real-World Example:**
```
Client complaint: "First 2-3 seconds of calls are silent"

VoIPScope Analysis:
- SIP 200 OK: Received at T0
- First RTP packet: Arrived at T0+2.3s
- Diagnosis: CRITICAL clipped audio
- Root cause: Firewall learning rules
- Fix: Pre-opened RTP port range on firewall
```

---

### 3. Silent Call (CRITICAL/HIGH) 🆕 **NEW in v1.1**

**Symptoms:**
- Call establishes successfully (SIP 200 OK)
- But no RTP packets are sent/received (0 or < 10 packets)
- Call duration is normal but completely silent
- Different from one-way audio (which has RTP in one direction)

**Causes:**
- Codec negotiation failure (no common codec)
- Both endpoints behind strict NAT without STUN/TURN
- Firewall blocking RTP in both directions
- SDP negotiation failure
- Endpoint not sending media despite accepting call

**VoIPScope Detection:**
Checks if call lasted >2 seconds but has very few or zero RTP packets:
- **Critical:** 0 RTP packets in >2s call
- **High:** <10 RTP packets in >2s call

**Real-World Example:**
```
Client complaint: "Calls connect but we hear nothing"

VoIPScope Analysis:
- Call duration: 15 seconds
- RTP packets: 0
- Diagnosis: CRITICAL silent call
- Root cause: Codec mismatch (caller: G.729, callee: G.711 only)
- Fix: Enable G.711 on caller endpoint
```

---

### 4. NAT/Routing Issues (HIGH)

**Symptoms:**
- SDP advertises private IP (192.168.x.x, 10.x.x.x)
- Actual RTP comes from different public IP
- No RTP received at advertised IP

**Causes:**
- NAT device not updating SDP
- Missing STUN/TURN configuration
- SIP ALG disabled

**VoIPScope Detection:**
Compares SDP `c=` line IP with actual RTP source IP. Flags mismatches and private IPs.

---

### 5. Call Setup Delay (HIGH/MEDIUM) 🆕 **NEW in v1.1**

**Symptoms:**
- Long delay between dialing and ringing
- Call takes several seconds to establish
- User frustrated by wait time

**Causes:**
- DNS resolution delay
- Network latency to SIP server
- SIP proxy processing delays
- Overloaded SIP server
- Multiple proxy hops

**VoIPScope Detection:**
Measures time between INVITE and 200 OK:
- **Normal:** < 3 seconds
- **Warning:** 3-6 seconds
- **High:** > 6 seconds

**Real-World Example:**
```
Client complaint: "Takes forever for calls to connect"

VoIPScope Analysis:
- INVITE sent: 10:00:00.000
- 200 OK received: 10:00:07.500
- Setup delay: 7500ms
- Diagnosis: HIGH slow call setup
- Root cause: DNS lookup taking 5 seconds
- Fix: Configure local DNS server or use IP address
```

---

### 6. TAG Validation (MEDIUM)

**Symptoms:**
- Missing From-Tag or To-Tag
- Inconsistent TAG values across messages

**Causes:**
- Non-compliant SIP client
- Proxy/B2BUA bug
- Configuration error

**VoIPScope Detection:**
Extracts TAGs from From/To headers. Validates presence in INVITE, 180 RINGING, and 200 OK.

---

### 7. Codec Mismatch (HIGH/MEDIUM) 🆕 **NEW in v1.1**

**Symptoms:**
- Degraded audio quality despite good network
- Unexpected transcoding overhead
- Higher CPU usage on gateway
- Codec in RTP differs from SDP negotiation

**Causes:**
- Endpoint using codec not in SDP offer
- Gateway forcing transcoding
- Misconfigured codec priority
- SDP manipulation by B2BUA

**VoIPScope Detection:**
Compares SDP codecs with actual RTP payload types:
- **High:** Transcoding detected (different codecs in each direction)
- **Medium:** Unexpected codec used (not in SDP)

**Real-World Example:**
```
Client complaint: "Audio sounds robotic/compressed"

VoIPScope Analysis:
- SDP negotiated: G.711 (both directions)
- Actual RTP: G.711 → G.729 (transcoding)
- Diagnosis: HIGH codec transcoding
- Root cause: Gateway forcing G.729 for WAN
- Fix: Allow G.711 end-to-end or upgrade bandwidth
```

---

### 8. DTMF Detection (INFORMATIONAL) 🆕 **NEW in v1.1**

**What it does:**
- Detects DTMF (touch-tone) events in RTP streams (RFC2833)
- Useful for IVR troubleshooting
- Tracks number of DTMF packets

**Use cases:**
- Verify DTMF is being sent to IVR
- Troubleshoot "menu not responding" issues
- Confirm touch-tone signaling method

**VoIPScope Detection:**
Identifies RTP payload type 101 (DTMF events):
- Counts DTMF packets per stream
- Shows which direction has DTMF
- Informational only (not an issue)

**Real-World Example:**
```
Client complaint: "IVR menu not accepting my input"

VoIPScope Analysis:
- DTMF packets detected: 0
- Diagnosis: No DTMF events in RTP
- Root cause: Phone using in-band DTMF (audio tones)
- Fix: Configure phone for RFC2833 DTMF
```

---

### 9. Call Quality Issues (HIGH/MEDIUM)

**Metrics:**

**Jitter:**
- Good: < 10ms
- Acceptable: 10-30ms
- Poor: > 30ms

**Packet Loss:**
- Good: < 1%
- Acceptable: 1-3%
- Poor: > 3%

**MOS Score:**
- Excellent: 4.3-4.5
- Good: 4.0-4.2
- Fair: 3.0-3.9
- Poor: < 3.0

**VoIPScope Detection:**
Calculates real-time jitter, packet loss, and MOS using ITU-T E-Model.

---

## 📖 Understanding MOS Scores

**MOS (Mean Opinion Score)** predicts perceived call quality on a scale of 1.0 to 4.5.

### MOS Formula (Simplified E-Model)

```
R-factor = 93.2 - Delay_Penalty - Loss_Penalty - Jitter_Penalty
MOS = 1 + 0.035*R + 0.000007*R*(R-60)*(100-R)
```

### Real-World Interpretation

| MOS   | Quality   | User Experience                          |
|-------|-----------|------------------------------------------|
| 4.3+  | Excellent | Crystal clear, like face-to-face         |
| 4.0   | Good      | Minor artifacts, barely noticeable       |
| 3.5   | Fair      | Some choppy audio, still understandable  |
| 3.0   | Poor      | Frequent drops, frustrating              |
| <3.0  | Bad       | Unusable, call should be dropped         |

---

## 🆕 What's New in v1.1

### 1. Clipped Audio Detection

The most frustrating VoIP issue for users: **calls connect but the first few seconds are silent.**

**Technical Details:**
- Measures SIP 200 OK → First RTP packet delay
- Detects firewall port opening delays
- Identifies NAT/STUN issues

**Thresholds:**
- Normal: < 500ms
- Warning: 500-2000ms (⚠️)
- Critical: > 2000ms (🔴)

---

### 2. Silent Call Detection

**Problem:** Call establishes but no media flows at all.

**Technical Details:**
- Detects calls with 0 or very few (<10) RTP packets
- Identifies codec negotiation failures
- Flags SDP issues

**Thresholds:**
- Critical: 0 packets in >2s call
- High: <10 packets in >2s call

---

### 3. Call Setup Delay Analysis

**Problem:** Slow call establishment frustrates users.

**Technical Details:**
- Measures INVITE → 200 OK delay
- Identifies DNS/network latency
- Flags overloaded SIP servers

**Thresholds:**
- Normal: < 3s
- Warning: 3-6s (⚠️)
- High: > 6s (🔴)

---

### 4. Codec Mismatch Warnings

**Problem:** Transcoding degrades quality and wastes CPU.

**Technical Details:**
- Compares SDP negotiated codecs vs actual RTP
- Detects unexpected codec usage
- Identifies transcoding scenarios

**Detection:**
- High: Different codecs in each direction (transcoding)
- Medium: Codec not in SDP negotiation

---

### 5. DTMF Detection (RFC2833)

**Problem:** IVR menus not responding to touch-tones.

**Technical Details:**
- Detects RFC2833 DTMF events (payload type 101)
- Counts DTMF packets per stream
- Useful for IVR troubleshooting

**Use cases:**
- Verify DTMF is being sent
- Troubleshoot "menu not working" issues
- Confirm touch-tone method

---

### Excel Report Enhancements

**Before v1.1:**
- 10 columns in Call Summary

**After v1.1:**
- 14 columns with new diagnostics:
  - Clipped Audio status
  - Silent Call indicator
  - Setup Delay timing
  - DTMF detection
- Quality Report includes guides for all new features
- Enhanced visual indicators (🔴 🟠 🟡 ✅ 📞)

---

### Performance Impact

All new features run automatically with **minimal overhead:**
- Analysis time: Still ~5 seconds per PCAP
- No additional dependencies required
- Same memory footprint
- Backward compatible with v1.0 PCAPs

---

## 🛠️ Troubleshooting Guide

### Issue: "No PCAP files found"
**Solution:** Place `.pcap` or `.pcapng` files in the same directory as `voipscope_v1.py`

### Issue: "tshark: command not found"
**Solution:** Install Wireshark (includes TShark):
- Windows: https://www.wireshark.org/download.html
- Linux: `sudo apt-get install tshark`
- macOS: `brew install wireshark`

### Issue: "Clipped Audio detected but calls sound fine"
**Possible Causes:**
1. Jitter buffer is compensating (good!)
2. Delay is consistent and within acceptable range
3. False positive (check PCAP for early media/PRACK)

**What to check:**
- Is delay consistent across all calls?
- Is it happening on specific routes only?
- Check firewall logs for port opening delays

### Issue: "SDP Analysis sheet is empty"
**Causes:**
1. PCAP doesn't contain SIP INVITE or 200 OK with SDP
2. TShark version too old
3. Capture filter excluded SDP content

**Solution:**
- Ensure capture includes full SIP dialog
- Update Wireshark/TShark to latest version
- Use capture filter: `port 5060 or port 5061`

### Issue: "ModuleNotFoundError: No module named 'pyshark'"
**Solution:**
```bash
pip install pyshark pandas openpyxl
```

---

## 📈 Use Cases

### 1. Troubleshooting "Hello? HELLO?!" Complaints 🆕

**Scenario:** Users complain they can't hear the first few seconds of calls.

**Before v1.1:**
- Manual analysis takes 15+ minutes per PCAP
- Hard to measure exact delay
- Difficult to identify root cause

**With v1.1:**
- ✅ Automatic detection in 5 seconds
- ✅ Exact delay: "RTP delayed 2.3s after SIP 200 OK"
- ✅ Root cause identified: Firewall port opening delay
- ✅ Fix recommended: Pre-open RTP port range

### 2. Network Optimization

**Scenario:** ISP wants to monitor VoIP quality across network

**Solution:**
- Capture PCAP at multiple points
- Run VoIPScope batch analysis
- Identify problematic routes/devices
- Track clipped audio trends 🆕
- Prioritize fixes based on issue severity

### 3. Compliance & SLA Monitoring

**Scenario:** VoIP provider guarantees:
- MOS > 4.0
- Media start < 500ms 🆕

**Solution:**
- Periodic PCAP capture
- VoIPScope generates quality reports
- Track MOS and clipped audio trends
- Prove SLA compliance with Excel reports

---

## 🧪 Testing & Validation

### Run Test Suite

```bash
# Generate test PCAPs
python generate_test_pcaps.py

# Analyze test scenarios
python voipscope_v1.py
```

### Expected Results

**test_normal_call.pcap:**
- ✅ No issues detected
- MOS: 4.3+
- Clipped Audio: ✅ No (< 100ms delay)
- Silent Call: ✅ No
- Setup Delay: ✅ Normal (< 1s)
- All metrics healthy

**test_clipped_audio.pcap:** 🆕
- 🔴 CRITICAL: Clipped Audio
- RTP delayed 2.3s after SIP 200 OK
- Recommendation: Check firewall, enable pre-opened ports

**test_silent_call.pcap:** 🆕
- 🔴 CRITICAL: Silent Call
- 0 RTP packets in 10s call
- Recommendation: Check codec support, SDP negotiation

**test_oneway_audio.pcap:**
- 🔴 CRITICAL: One-Way Audio
- Only caller sends RTP
- Recommendation: Check firewall on callee side

**test_nat_routing_issue.pcap:**
- 🟠 HIGH: NAT Routing Issue
- SDP has private IP (192.168.1.100)
- RTP from public IP (203.0.113.52)
- Recommendation: Enable STUN/TURN

**test_missing_tag.pcap:**
- 🟡 MEDIUM: TAG Missing
- To-Tag absent in 200 OK
- Recommendation: Check SIP server config

**test_poor_quality.pcap:**
- 🟠 HIGH: Poor Call Quality
- Jitter: 40-60ms
- Loss: ~10%
- MOS: < 3.0
- Recommendation: Enable QoS

---

## 🔐 Privacy & Security

- VoIPScope processes PCAP files **locally**
- No data sent to external servers
- Excel reports stored on your machine
- Safe for analyzing customer data (no cloud dependency)

---

## 🚧 Roadmap

### v1.1 (Current Release) ✅
- [x] **Clipped Audio Detection** - Detects delayed media start
- [x] **DTMF detection (RFC2833)** - Touch-tone event tracking
- [x] **Codec mismatch warnings** - SDP vs RTP validation
- [x] **Call setup delay analysis** - INVITE → 200 OK timing
- [x] **Silent call detection** - No RTP media detection

### v1.2 (Next Release)
- [ ] Enhanced DTMF analysis (decode actual digits)
- [ ] Packet reordering detection
- [ ] Advanced jitter buffer analysis
- [ ] Call hold/transfer detection
- [ ] Multi-codec call analysis

### v2.0 (Future)
- [ ] WebRTC support
- [ ] Real-time monitoring mode
- [ ] Multi-file comparison
- [ ] Graphical dashboard
- [ ] PDF report generation
- [ ] REST API for integration

---

## 📝 Changelog

### v1.1 - Enhanced Edition (December 2025)

**New Features:**
- ✨ **Clipped Audio Detection**
  - Measures SIP-to-RTP delay
  - Detects "Hello? HELLO?!" problem
  - Three severity levels: Normal, Warning, Critical
  
- ✨ **Silent Call Detection**
  - Identifies calls with no RTP media
  - Detects codec negotiation failures
  - Flags SDP issues
  
- ✨ **Call Setup Delay Analysis**
  - Measures INVITE → 200 OK timing
  - Identifies slow call establishment
  - Flags DNS/network latency
  
- ✨ **Codec Mismatch Warnings**
  - Compares SDP vs actual RTP codecs
  - Detects transcoding scenarios
  - Flags unexpected codec usage
  
- ✨ **DTMF Detection (RFC2833)**
  - Identifies touch-tone events in RTP
  - Useful for IVR troubleshooting
  - Tracks DTMF packet counts

**Improvements:**
- 📊 Enhanced Excel reporting with 14 columns (was 10)
- 🎨 New visual indicators for all diagnostics
- 📖 Quality Report includes guides for all new features
- ⚡ All features run automatically with minimal overhead

**Technical:**
- Added `detect_clipped_audio()` function
- Added `detect_silent_call()` function
- Added `analyze_call_setup_delay()` function
- Added `detect_codec_mismatch()` function
- Added `detect_dtmf()` function
- SIP 200 OK timestamp capture
- Enhanced diagnostic analysis pipeline

**Thresholds:**
- Clipped audio: 500ms (warning), 2000ms (critical)
- Silent call: <10 packets (high), 0 packets (critical)
- Call setup: 3s (warning), 6s (high)
- DTMF payload type: 101 (RFC2833 standard)

### v1.0 - Core Edition (November 2025)

**Initial Release:**
- SIP/RTP packet analysis
- MOS score calculation
- One-Way Audio detection
- NAT/Routing issue diagnosis
- TAG validation
- 6-sheet Excel reports
- Test PCAP generator

---

## 📄 License

MIT License

Copyright (c) 2025 Emre Karayazgan

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

---

## 👤 Author

**Emre Karayazgan**
- VoIP/Network Engineer
- LinkedIn: [https://www.linkedin.com/in/emre-karayazgan/]
- GitHub: [https://github.com/emrekarayazgan]

---

## 🙏 Acknowledgments

- ITU-T for E-Model standardization
- Wireshark/TShark for packet analysis capabilities
- Python community for excellent libraries
- VoIP community for feedback and feature requests

---

## 📞 Support

For bug reports, feature requests, or questions:
- Open an issue on GitHub
- Email: emre.karayazgan@gmail.com
- LinkedIn: [https://www.linkedin.com/in/emre-karayazgan/]

---

**VoIPScope v1.1 - Enhanced Edition**

*Making VoIP troubleshooting simple, fast, and accurate.*

"See beyond the call" 🚀

---

## 🌟 Star History

If you find VoIPScope useful, please consider giving it a star on GitHub! ⭐

---

**Latest Release:** v1.1 - Enhanced Edition  
**Released:** December 2025  
**Download:** [GitHub Releases](https://github.com/emrekarayazgan/voipscope/releases)
