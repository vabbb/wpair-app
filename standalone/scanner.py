#!/usr/bin/env python3
"""
CVE-2025-36911 Vulnerability Scanner
Defensive tool to test if Fast Pair devices are patched.

This scanner ONLY tests vulnerability status - it does not exploit devices.

Usage:
    python scanner.py                    # Scan and test all Fast Pair devices
    python scanner.py --target AA:BB:CC:DD:EE:FF  # Test specific device
    python scanner.py --scan-only        # Only scan, don't test

Author: Security Research Tool
License: For authorized security testing only
"""

import asyncio
import argparse
import struct
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional
import secrets

try:
    from bleak import BleakScanner, BleakClient
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    print("Error: bleak library required")
    print("Install with: pip install bleak")
    sys.exit(1)


# Fast Pair UUIDs
FAST_PAIR_SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"
KEY_BASED_PAIRING_UUID = "fe2c1234-8366-4814-8eb0-01de32100bea"
MODEL_ID_UUID = "fe2c1233-8366-4814-8eb0-01de32100bea"

# KBP Message types
MSG_KEY_BASED_PAIRING_REQUEST = 0x00


class VulnerabilityStatus(Enum):
    NOT_TESTED = "not_tested"
    TESTING = "testing"
    VULNERABLE = "vulnerable"
    PATCHED = "patched"
    ERROR = "error"


@dataclass
class FastPairDevice:
    address: str
    name: Optional[str]
    rssi: int
    model_id: Optional[str]
    is_pairing_mode: bool
    has_account_key_filter: bool
    status: VulnerabilityStatus = VulnerabilityStatus.NOT_TESTED
    last_seen: datetime = None

    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = datetime.now()

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        if self.model_id:
            known = KNOWN_DEVICES.get(self.model_id.upper())
            if known:
                return known["name"]
        return "Unknown Fast Pair Device"

    @property
    def manufacturer(self) -> Optional[str]:
        if self.model_id:
            known = KNOWN_DEVICES.get(self.model_id.upper())
            if known:
                return known["manufacturer"]
        return None


# Known vulnerable devices from CVE-2025-36911 research
KNOWN_DEVICES = {
    # Google
    "30018E": {"name": "Pixel Buds Pro 2", "manufacturer": "Google"},
    # Sony
    "CD8256": {"name": "WF-1000XM4", "manufacturer": "Sony"},
    "0E30C3": {"name": "WH-1000XM5", "manufacturer": "Sony"},
    "D5BC6B": {"name": "WH-1000XM6", "manufacturer": "Sony"},
    "821F66": {"name": "LinkBuds S", "manufacturer": "Sony"},
    # JBL
    "F52494": {"name": "Tune Buds", "manufacturer": "JBL"},
    "718FA4": {"name": "Live Pro 2", "manufacturer": "JBL"},
    "D446A7": {"name": "Tune Beam", "manufacturer": "JBL"},
    # Anker/Soundcore
    "9D3F8A": {"name": "Soundcore Liberty 4", "manufacturer": "Anker"},
    "F0B77F": {"name": "Soundcore Liberty 4 NC", "manufacturer": "Anker"},
    # Nothing
    "D0A72C": {"name": "Ear (a)", "manufacturer": "Nothing"},
    # OnePlus
    "D97EBA": {"name": "Nord Buds 3 Pro", "manufacturer": "OnePlus"},
    # Xiaomi
    "AE3989": {"name": "Redmi Buds 5 Pro", "manufacturer": "Xiaomi"},
    # Jabra
    "D446F9": {"name": "Elite 8 Active", "manufacturer": "Jabra"},
    # Samsung (generally patched)
    "0082DA": {"name": "Galaxy Buds2 Pro", "manufacturer": "Samsung"},
    "00FA72": {"name": "Galaxy Buds FE", "manufacturer": "Samsung"},
    # Bose
    "F00002": {"name": "QuietComfort Earbuds II", "manufacturer": "Bose"},
    # Beats
    "000006": {"name": "Beats Studio Buds +", "manufacturer": "Beats"},
}


def parse_fast_pair_data(service_data: bytes) -> tuple[Optional[str], bool, bool]:
    """
    Parse Fast Pair service data to extract model ID and pairing state.

    Returns: (model_id, is_pairing_mode, has_account_key_filter)
    """
    if not service_data:
        return None, False, False

    model_id = None
    is_pairing_mode = False
    has_account_key_filter = False

    first_byte = service_data[0]

    # 3-byte Model ID with bit 7 clear = pairing mode
    if len(service_data) == 3 and (first_byte & 0x80) == 0:
        model_id = service_data.hex().upper()
        is_pairing_mode = True
    # Bits 5-6 indicate account key filter (not in pairing mode)
    elif (first_byte & 0x60) != 0:
        has_account_key_filter = True
        is_pairing_mode = False
    # Extended format
    elif len(service_data) > 3 and (first_byte & 0x80) == 0:
        model_id = service_data[:3].hex().upper()

    return model_id, is_pairing_mode, has_account_key_filter


def parse_ble_address(address: str) -> bytes:
    """
    Parse BLE address to 6 bytes.

    Handles:
    - Standard MAC: AA:BB:CC:DD:EE:FF
    - macOS UUID: CD662897-58CB-CB38-3967-D3E36893DBDD
    """
    # Standard MAC format (with colons)
    if ":" in address and len(address) == 17:
        return bytes.fromhex(address.replace(":", ""))

    # macOS UUID format (with dashes)
    if "-" in address:
        # Use first 6 bytes of UUID as address substitute
        uuid_bytes = bytes.fromhex(address.replace("-", ""))
        return uuid_bytes[:6]

    # Try raw hex (no separators)
    clean = address.replace(":", "").replace("-", "")
    if len(clean) >= 12:
        return bytes.fromhex(clean[:12])

    # Fallback: generate random address for test
    return secrets.token_bytes(6)


def build_kbp_request(target_address: str) -> bytes:
    """
    Build a Key-Based Pairing test request.

    Format (16 bytes):
    - Byte 0: Message type (0x00 = Key-Based Pairing Request)
    - Byte 1: Flags (0x11 = INITIATE_BONDING | EXTENDED_RESPONSE)
    - Bytes 2-7: Provider BLE address (6 bytes)
    - Bytes 8-15: Random salt (8 bytes)
    """
    # Parse address (handles both MAC and macOS UUID formats)
    addr_bytes = parse_ble_address(target_address)

    # Random salt
    salt = secrets.token_bytes(8)

    # Build request
    request = bytes([
        MSG_KEY_BASED_PAIRING_REQUEST,  # 0x00
        0x11,  # Flags: initiate bonding + extended response
    ]) + addr_bytes + salt

    return request


class VulnerabilityScanner:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.devices: dict[str, FastPairDevice] = {}

    def log(self, message: str):
        if self.verbose:
            print(f"[DEBUG] {message}")

    def detection_callback(self, device: BLEDevice, advertisement_data: AdvertisementData):
        """Called when a BLE device is detected."""
        # Check for Fast Pair service data
        fp_data = advertisement_data.service_data.get(FAST_PAIR_SERVICE_UUID)

        if fp_data is None:
            return

        model_id, is_pairing_mode, has_account_key_filter = parse_fast_pair_data(fp_data)

        fp_device = FastPairDevice(
            address=device.address,
            name=device.name,
            rssi=advertisement_data.rssi,
            model_id=model_id,
            is_pairing_mode=is_pairing_mode,
            has_account_key_filter=has_account_key_filter,
        )

        if device.address not in self.devices:
            self.devices[device.address] = fp_device
            self._print_device_found(fp_device)
        else:
            # Update existing device
            self.devices[device.address].rssi = advertisement_data.rssi
            self.devices[device.address].last_seen = datetime.now()

    def _print_device_found(self, device: FastPairDevice):
        mode = "PAIRING" if device.is_pairing_mode else "IDLE"
        mfr = f" ({device.manufacturer})" if device.manufacturer else ""
        print(f"\n[+] Found: {device.display_name}{mfr}")
        print(f"    Address: {device.address}")
        print(f"    RSSI: {device.rssi} dBm")
        print(f"    Mode: {mode}")
        if device.model_id:
            print(f"    Model ID: {device.model_id}")

    async def scan(self, duration: float = 10.0) -> list[FastPairDevice]:
        """Scan for Fast Pair devices."""
        print(f"\n[*] Scanning for Fast Pair devices ({duration}s)...")
        print("[*] Looking for service UUID: 0xFE2C")

        scanner = BleakScanner(detection_callback=self.detection_callback)

        await scanner.start()
        await asyncio.sleep(duration)
        await scanner.stop()

        print(f"\n[*] Scan complete. Found {len(self.devices)} Fast Pair device(s)")
        return list(self.devices.values())

    async def test_device(self, address: str) -> VulnerabilityStatus:
        """
        Test a single device for CVE-2025-36911 vulnerability.

        The test writes a KBP request to the device:
        - If accepted (no error): Device is VULNERABLE
        - If rejected (GATT error): Device is PATCHED
        """
        print(f"\n[*] Testing device: {address}")

        if address in self.devices:
            device = self.devices[address]
            if device.is_pairing_mode:
                print("[!] Device is in pairing mode - test not applicable")
                print("    (Vulnerability only affects devices NOT in pairing mode)")
                return VulnerabilityStatus.NOT_TESTED

        try:
            async with BleakClient(address, timeout=15.0) as client:
                print(f"[*] Connected to {address}")

                # Check for Fast Pair service
                services = client.services
                fp_service = None
                for service in services:
                    if service.uuid.lower() == FAST_PAIR_SERVICE_UUID:
                        fp_service = service
                        break

                if not fp_service:
                    print("[!] Fast Pair service (0xFE2C) not found")
                    return VulnerabilityStatus.ERROR

                print("[*] Fast Pair service found")

                # Find KBP characteristic
                kbp_char = None
                for char in fp_service.characteristics:
                    if char.uuid.lower() == KEY_BASED_PAIRING_UUID:
                        kbp_char = char
                        break

                if not kbp_char:
                    print("[!] Key-Based Pairing characteristic not found")
                    return VulnerabilityStatus.ERROR

                print("[*] KBP characteristic found")

                # Try to read Model ID for logging
                try:
                    for char in fp_service.characteristics:
                        if char.uuid.lower() == MODEL_ID_UUID:
                            model_data = await client.read_gatt_char(char)
                            model_id = model_data.hex().upper()
                            print(f"[*] Model ID: {model_id}")
                            known = KNOWN_DEVICES.get(model_id)
                            if known:
                                print(f"    Device: {known['name']} ({known['manufacturer']})")
                            break
                except Exception:
                    pass  # Model ID read is optional

                # Build and send KBP request
                request = build_kbp_request(address)
                print(f"[*] Sending KBP test request ({len(request)} bytes)...")
                self.log(f"    Request: {request.hex()}")

                try:
                    await client.write_gatt_char(kbp_char, request, response=True)

                    # If we get here without exception, device accepted the request
                    print("\n" + "=" * 50)
                    print("[!!!] VULNERABLE - Device accepted KBP request!")
                    print("=" * 50)
                    print("[*] Device accepts Key-Based Pairing when not in pairing mode")
                    print("[*] This device is affected by CVE-2025-36911")
                    print("[*] Recommendation: Update firmware or contact manufacturer")

                    if address in self.devices:
                        self.devices[address].status = VulnerabilityStatus.VULNERABLE

                    return VulnerabilityStatus.VULNERABLE

                except Exception as write_error:
                    error_str = str(write_error).lower()
                    self.log(f"Write error: {write_error}")

                    # GATT errors or disconnection indicate the device rejected the request = PATCHED
                    # Patched devices typically either return a GATT error OR disconnect immediately
                    rejection_indicators = [
                        "rejected", "not permitted", "authorization", "encryption",
                        "error", "failed", "disconnected", "disconnect"
                    ]
                    if any(x in error_str for x in rejection_indicators):
                        print("\n[+] PATCHED - Device rejected KBP request")
                        if "disconnect" in error_str:
                            print("[*] Device disconnected after receiving request (rejection behavior)")
                        else:
                            print("[*] Device returned GATT error (rejection behavior)")
                        print("[*] Device properly rejects pairing when not in pairing mode")

                        if address in self.devices:
                            self.devices[address].status = VulnerabilityStatus.PATCHED

                        return VulnerabilityStatus.PATCHED
                    else:
                        # Some other unexpected error
                        print(f"[!] Unexpected error: {write_error}")
                        return VulnerabilityStatus.ERROR

        except asyncio.TimeoutError:
            print("[!] Connection timeout")
            return VulnerabilityStatus.ERROR
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return VulnerabilityStatus.ERROR

    async def scan_and_test(self, scan_duration: float = 10.0, test_all: bool = True):
        """Scan for devices and optionally test them."""
        devices = await self.scan(scan_duration)

        if not devices:
            print("\n[!] No Fast Pair devices found")
            return

        if not test_all:
            return

        print("\n" + "=" * 50)
        print("VULNERABILITY TESTING")
        print("=" * 50)

        testable = [d for d in devices if not d.is_pairing_mode]

        if not testable:
            print("[!] No testable devices (all in pairing mode)")
            return

        print(f"[*] Testing {len(testable)} device(s) not in pairing mode...\n")

        for device in testable:
            await self.test_device(device.address)
            await asyncio.sleep(1)  # Brief delay between tests

        # Summary
        print("\n" + "=" * 50)
        print("SUMMARY")
        print("=" * 50)

        vulnerable = [d for d in self.devices.values() if d.status == VulnerabilityStatus.VULNERABLE]
        patched = [d for d in self.devices.values() if d.status == VulnerabilityStatus.PATCHED]
        errors = [d for d in self.devices.values() if d.status == VulnerabilityStatus.ERROR]

        print(f"Total devices found: {len(self.devices)}")
        print(f"Vulnerable: {len(vulnerable)}")
        print(f"Patched: {len(patched)}")
        print(f"Errors: {len(errors)}")

        if vulnerable:
            print("\nVulnerable devices:")
            for d in vulnerable:
                print(f"  - {d.display_name} ({d.address})")


async def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-36911 Vulnerability Scanner",
        epilog="For authorized security testing only."
    )
    parser.add_argument(
        "--target", "-t",
        help="Test specific device by address (AA:BB:CC:DD:EE:FF)"
    )
    parser.add_argument(
        "--scan-only", "-s",
        action="store_true",
        help="Only scan for devices, don't test"
    )
    parser.add_argument(
        "--duration", "-d",
        type=float,
        default=10.0,
        help="Scan duration in seconds (default: 10)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    print("=" * 50)
    print("CVE-2025-36911 Vulnerability Scanner")
    print("Defensive security testing tool")
    print("=" * 50)
    print("\nDISCLAIMER: Only test devices you own or have")
    print("explicit authorization to test.\n")

    scanner = VulnerabilityScanner(verbose=args.verbose)

    if args.target:
        # Test specific device
        result = await scanner.test_device(args.target)
        print(f"\nResult: {result.value}")
    else:
        # Scan and optionally test
        await scanner.scan_and_test(
            scan_duration=args.duration,
            test_all=not args.scan_only
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)
