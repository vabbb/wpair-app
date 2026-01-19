# CVE-2025-36911 Vulnerability Scanner

Cross-platform Python tool to test Fast Pair devices for the WhisperPair vulnerability.

## What This Does

This is a **defensive-only** scanner that tests if Bluetooth devices are vulnerable to CVE-2025-36911. It checks whether devices accept Key-Based Pairing (KBP) requests when NOT in pairing mode.

- **VULNERABLE**: Device accepts KBP request → affected by CVE-2025-36911
- **PATCHED**: Device rejects KBP request → properly secured

This tool does NOT exploit devices - it only performs the minimal test to determine patch status.

## Requirements

- Python 3.8+
- Bluetooth adapter with BLE support
- Platform-specific requirements:
  - **Linux**: BlueZ 5.43+ (`sudo apt install bluez`)
  - **macOS**: Works out of the box (uses CoreBluetooth)
  - **Windows**: Windows 10+ (uses WinRT)

## Installation

```bash
cd standalone
pip install -r requirements.txt
```

Or directly:

```bash
pip install bleak
```

## Usage

### Scan and test all Fast Pair devices

```bash
python scanner.py
```

### Scan only (no testing)

```bash
python scanner.py --scan-only
```

### Test a specific device

```bash
python scanner.py --target AA:BB:CC:DD:EE:FF
```

### Adjust scan duration

```bash
python scanner.py --duration 30
```

### Verbose output

```bash
python scanner.py --verbose
```

## Example Output

```
==================================================
CVE-2025-36911 Vulnerability Scanner
Defensive security testing tool
==================================================

DISCLAIMER: Only test devices you own or have
explicit authorization to test.

[*] Scanning for Fast Pair devices (10s)...
[*] Looking for service UUID: 0xFE2C

[+] Found: WH-1000XM5 (Sony)
    Address: AA:BB:CC:DD:EE:FF
    RSSI: -45 dBm
    Mode: IDLE
    Model ID: 0E30C3

[*] Scan complete. Found 1 Fast Pair device(s)

==================================================
VULNERABILITY TESTING
==================================================
[*] Testing 1 device(s) not in pairing mode...

[*] Testing device: AA:BB:CC:DD:EE:FF
[*] Connected to AA:BB:CC:DD:EE:FF
[*] Fast Pair service found
[*] KBP characteristic found
[*] Model ID: 0E30C3
    Device: WH-1000XM5 (Sony)
[*] Sending KBP test request (16 bytes)...

==================================================
[!!!] VULNERABLE - Device accepted KBP request!
==================================================
[*] Device accepts Key-Based Pairing when not in pairing mode
[*] This device is affected by CVE-2025-36911
[*] Recommendation: Update firmware or contact manufacturer

==================================================
SUMMARY
==================================================
Total devices found: 1
Vulnerable: 1
Patched: 0
Errors: 0

Vulnerable devices:
  - WH-1000XM5 (AA:BB:CC:DD:EE:FF)
```

## How the Test Works

1. **Scan**: Discovers BLE devices advertising Fast Pair service (UUID 0xFE2C)
2. **Connect**: Establishes GATT connection to the device
3. **Discover**: Finds the Key-Based Pairing characteristic
4. **Test**: Writes a 16-byte KBP request:
   - Byte 0: Message type (0x00)
   - Byte 1: Flags (0x11 - initiate bonding + extended response)
   - Bytes 2-7: Device address
   - Bytes 8-15: Random salt
5. **Evaluate**:
   - `GATT_SUCCESS` → Device is VULNERABLE
   - `GATT error` → Device is PATCHED

## Known Affected Devices

The scanner includes a database of known Fast Pair devices from the CVE research:

| Manufacturer | Device | Model ID |
|-------------|--------|----------|
| Google | Pixel Buds Pro 2 | 30018E |
| Sony | WF-1000XM4 | CD8256 |
| Sony | WH-1000XM5 | 0E30C3 |
| Sony | WH-1000XM6 | D5BC6B |
| JBL | Tune Buds | F52494 |
| Anker | Soundcore Liberty 4 | 9D3F8A |
| Nothing | Ear (a) | D0A72C |
| OnePlus | Nord Buds 3 Pro | D97EBA |
| Xiaomi | Redmi Buds 5 Pro | AE3989 |

## Troubleshooting

### Linux: Permission denied

Run with sudo or add user to bluetooth group:

```bash
sudo usermod -a -G bluetooth $USER
# Log out and back in
```

Or use sudo:

```bash
sudo python scanner.py
```

### macOS: Bluetooth permission

Grant Terminal/IDE Bluetooth permission in System Preferences → Privacy & Security → Bluetooth

### Windows: No devices found

Ensure Bluetooth is enabled and the adapter supports BLE.

### Connection timeouts

- Move closer to the device
- Ensure device is powered on
- Try increasing timeout with `--duration`

## Disclaimer

This tool is for **authorized security testing only**. Only test devices you own or have explicit permission to test. Unauthorized testing may violate laws in your jurisdiction.

## References

- [CVE-2025-36911](https://www.cve.org/CVERecord?id=CVE-2025-36911)
- [WhisperPair Research](https://whisperpair.eu)
- [Fast Pair Specification](https://developers.google.com/nearby/fast-pair/specifications/introduction)
