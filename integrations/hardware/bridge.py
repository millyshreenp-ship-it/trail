"""Explicit USB/BLE prototype bridge; private device keys never leave hardware."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import time

import httpx

RECEIVE = "126d11b1-ef1e-4d35-a7cb-560a407c01a1"
RESPONSE = "126d11b2-ef1e-4d35-a7cb-560a407c01a1"
IDENTITY = "126d11b3-ef1e-4d35-a7cb-560a407c01a1"


def prepare(args, identity):
    if args.enroll:
        admin = os.environ["TRAIL_DEVICE_ADMIN_KEY"]
        result = httpx.post(args.api + "/api/workspace/devices", json=identity, headers={"X-API-Key": admin}, timeout=8)
        result.raise_for_status()
    key = os.environ["TRAIL_WORKSPACE_KEY"]
    headers = {"X-API-Key": key}
    response = httpx.post(args.api + f"/api/workspace/decisions/{args.event}/device-challenge", json={"device_id": identity["device_id"]}, headers=headers, timeout=8)
    response.raise_for_status()
    return response.json(), headers


def acknowledge(args, packet, headers, challenge):
    if packet.get("challenge_id") != challenge["payload"]["challenge_id"]:
        raise ValueError("device challenge mismatch")
    response = httpx.post(args.api + f"/api/workspace/device-challenges/{packet['challenge_id']}/acknowledge", json={"signature_b64": packet["signature_b64"]}, headers=headers, timeout=8)
    response.raise_for_status()
    print(json.dumps(response.json()))


def serial_bridge(args):
    import serial

    with serial.Serial(args.port, 115200, timeout=1) as device:
        deadline = time.monotonic() + 15
        identity = None
        while time.monotonic() < deadline:
            line = device.readline(2048)
            try:
                candidate = json.loads(line)
                if "public_key_b64" in candidate:
                    identity = candidate
                    break
            except (ValueError, TypeError):
                pass
        if identity is None:
            raise RuntimeError("device identity unavailable; reconnect or reset the board")
        challenge, headers = prepare(args, identity)
        device.write((json.dumps(challenge) + "\n").encode())
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            line = device.readline(2048)
            try:
                packet = json.loads(line)
                if "signature_b64" in packet:
                    acknowledge(args, packet, headers, challenge)
                    return
            except (ValueError, TypeError):
                pass
        raise TimeoutError("physical acknowledgement not received")


async def ble_bridge(args):
    from bleak import BleakClient

    async with BleakClient(args.ble_address) as device:
        identity = json.loads(bytes(await device.read_gatt_char(IDENTITY)))
        challenge, headers = prepare(args, identity)
        loop = asyncio.get_running_loop()
        result = loop.create_future()
        def notification(_sender, data):
            if not result.done():
                result.set_result(True)
        await device.start_notify(RESPONSE, notification)
        packet = (json.dumps(challenge) + "\n").encode()
        for offset in range(0, len(packet), 240):
            await device.write_gatt_char(RECEIVE, packet[offset:offset + 240], response=True)
        await asyncio.wait_for(result, 120)
        acknowledgement = json.loads(bytes(await device.read_gatt_char(RESPONSE)))
        acknowledge(args, acknowledgement, headers, challenge)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--port")
    transport.add_argument("--ble-address")
    parser.add_argument("--event", required=True)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--enroll", action="store_true")
    args = parser.parse_args()
    if not args.api.startswith("https://") and args.api not in {"http://127.0.0.1:8000", "http://localhost:8000"}:
        raise ValueError("non-local bridges require HTTPS")
    serial_bridge(args) if args.port else asyncio.run(ble_bridge(args))