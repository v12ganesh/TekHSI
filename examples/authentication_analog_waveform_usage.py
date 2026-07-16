"""Discover the scope's auth mode, connect, and plot an analog waveform.

Every run does a fresh discovery (like :mod:`authentication_check`) and
transparently handles all three modes:

- plain gRPC (no TLS, no password)
- TLS only (Mode 2)
- TLS + password (Mode 3) - prompts for the password if the server needs one
"""

from __future__ import annotations

import contextlib
import getpass
import sys
import tempfile
import time
import uuid

from pathlib import Path
from typing import TYPE_CHECKING

import grpc
import matplotlib.pyplot as plt

from tekhsi import TekHSIConnect, TekHSICredentials
from tekhsi._tek_highspeed_server_pb2 import ConnectRequest  # pylint: disable=no-name-in-module
from tekhsi._tek_highspeed_server_pb2_grpc import ConnectStub
from tekhsi.auth_basic import DEFAULT_MODE3_USERNAME
from tekhsi.security import (  # pylint: disable=import-private-name
    _build_creds_from_entry,
    _fetch_server_cert,
    _parse_host_port,
    _secure_channel,
    _try_plain_grpc_channel,
)

if TYPE_CHECKING:
    from tm_data_types import AnalogWaveform

addr = "192.168.0.1"  # Replace with the IP address of your instrument
channel = "ch2"  # Analog channel to plot
url = f"{addr}:5000"

_PROBE_TIMEOUT_S = 8.0
_DISCOVERY_DEADLINE_S = 12.0


def _probe(stub: ConnectStub) -> tuple[bool, str | None]:
    """Connect + Disconnect round trip. Returns ``(ok, grpc_error_code_name)``."""
    name = str(uuid.uuid4())
    try:
        stub.Connect(ConnectRequest(name=name), timeout=_PROBE_TIMEOUT_S)
    except grpc.RpcError as e:
        return False, e.code().name
    finally:
        with contextlib.suppress(grpc.RpcError):
            stub.Disconnect(ConnectRequest(name=name), timeout=3.0)
    return True, None


def _discover() -> tuple[bool, Path | None, dict, bool]:
    """Return ``(plain_ok, cert_path, entry, needs_password)`` from a fresh probe."""
    deadline = time.time() + _DISCOVERY_DEADLINE_S

    if (plain_channel := _try_plain_grpc_channel(url, deadline)) is not None:
        with contextlib.suppress(Exception):
            plain_channel.close()
        return True, None, {}, False

    host, port = _parse_host_port(url)
    try:
        cert = _fetch_server_cert(host, port, timeout=_PROBE_TIMEOUT_S)
    except OSError as exc:
        print(f"Could not reach TekHSI on {url}: {exc}")
        sys.exit(1)

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
        tmp.write(cert.cert_pem or b"")
        pem_path = Path(tmp.name)

    probe_entry = {
        "cert_fingerprint": cert.cert_fingerprint,
        "cert_path": str(pem_path),
        "tls_server_name": cert.tls_server_name,
        "login": None,
        "password": None,
    }

    ch = _secure_channel(url, _build_creds_from_entry(probe_entry, "tls"), entry=probe_entry)
    try:
        ok, err = _probe(ConnectStub(ch))
    finally:
        with contextlib.suppress(Exception):
            ch.close()

    if ok:
        return False, pem_path, probe_entry, False
    if err == "UNAUTHENTICATED":
        return False, pem_path, probe_entry, True

    print(f"TLS probe failed: {err}")
    pem_path.unlink(missing_ok=True)
    sys.exit(1)


def _verify_password(store_entry: dict, secret: str) -> None:
    """Probe with password; exit on auth failure."""
    auth_entry = {**store_entry, "password": secret, "login": DEFAULT_MODE3_USERNAME}
    ch = _secure_channel(url, _build_creds_from_entry(auth_entry, "token"), entry=auth_entry)
    try:
        ok, err = _probe(ConnectStub(ch))
    finally:
        with contextlib.suppress(Exception):
            ch.close()
    if not ok:
        print(f"Authentication failed: {err}")
        sys.exit(1)


# ---- 1. Discover what the server requires ---------------------------------
plain_ok, cert_path, entry, needs_password = _discover()

print(f"Server at {url} requires:")
print(f"  - Encryption (TLS): {'no' if plain_ok else 'yes'}")
print(f"  - Password:         {'yes' if needs_password else 'no'}")

# ---- 2. Prompt only when needed -------------------------------------------
password: str | None = None
if needs_password:
    if not (password := getpass.getpass(f"Password for TekHSI at {url}: ") or None):
        print("Password is required but none was provided.")
        if cert_path is not None:
            cert_path.unlink(missing_ok=True)
        sys.exit(1)
    _verify_password(entry, password)

# ---- 3. Build credentials --------------------------------------------------
if plain_ok:
    credentials = None
elif needs_password:
    credentials = TekHSICredentials.token(str(cert_path), password)
else:
    credentials = TekHSICredentials.tls(str(cert_path))

# ---- 4. Connect, capture one acquisition, and plot ------------------------
try:
    kwargs = {"credentials": credentials} if credentials is not None else {}
    with TekHSIConnect(url, **kwargs) as connection:
        print("Channels:", connection.activesymbols)
        with connection.access_data():
            waveform: AnalogWaveform = connection.get_data(channel)

        vd = waveform.normalized_vertical_values
        hd = waveform.normalized_horizontal_values

        _, ax = plt.subplots()
        ax.plot(hd, vd)
        ax.set(
            xlabel=waveform.x_axis_units,
            ylabel=waveform.y_axis_units,
            title=f"{channel} on {addr}",
        )
        plt.show()
finally:
    if cert_path is not None:
        cert_path.unlink(missing_ok=True)
