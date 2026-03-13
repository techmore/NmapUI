#!/usr/bin/env python3
"""
CLI test script to trigger generate_report API and monitor progress in real-time.

Usage:
    python test_generate_report.py <target> [customer_name]

Examples:
    python test_generate_report.py 192.168.222.0/24
    python test_generate_report.py 192.168.222.0/24 "My Customer"
"""

import os
import sys
import time
from datetime import datetime

import socketio

# Create a Socket.IO client
sio = socketio.Client()

# Track connection state
connected = False
report_completed = False
report_failed = False
start_time = None


@sio.event
def connect():
    global connected
    connected = True
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Connected to server")


@sio.event
def disconnect():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Disconnected from server")


@sio.on('scan_feedback')
def on_scan_feedback(data):
    """Receive real-time scan feedback"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    if start_time:
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"[{timestamp}] [{elapsed:6.1f}s] {data}")
    else:
        print(f"[{timestamp}] {data}")


@sio.on('report_complete')
def on_report_complete(data):
    """Report generation completed successfully"""
    global report_completed
    report_completed = True
    timestamp = datetime.now().strftime('%H:%M:%S')
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n[{timestamp}] [{elapsed:6.1f}s] ✅ REPORT COMPLETE!")
    print(f"    Status: {data.get('status')}")
    print(f"    Path: {data.get('path')}")
    print(f"    Scan Dir: {data.get('scan_dir')}")
    print(f"\nTotal time: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")


@sio.on('report_error')
def on_report_error(data):
    """Report generation failed"""
    global report_failed
    report_failed = True
    timestamp = datetime.now().strftime('%H:%M:%S')
    elapsed = (datetime.now() - start_time).total_seconds() if start_time else 0
    print(f"\n[{timestamp}] [{elapsed:6.1f}s] ❌ REPORT ERROR!")
    print(f"    Error: {data.get('error')}")
    if data.get('timeout'):
        print(f"    Timeout: {data.get('timeout_seconds')} seconds")
        print(f"    Elapsed: {data.get('elapsed_seconds', elapsed):.1f} seconds")
    print(f"\nFailed after: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")


@sio.on('customer_info')
def on_customer_info(data):
    """Customer information updated"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] Customer updated: {data.get('name')}")
    if 'metadata' in data and 'last_scan_duration' in data['metadata']:
        print(f"    Last scan duration: {data['metadata']['last_scan_duration']}")


def main():
    global start_time

    if len(sys.argv) < 2:
        print("Usage: python test_generate_report.py <target> [customer_name]")
        print("\nExamples:")
        print("  python test_generate_report.py 192.168.222.0/24")
        print("  python test_generate_report.py 192.168.222.0/24 'My Customer'")
        sys.exit(1)

    target = sys.argv[1]
    customer_name = sys.argv[2] if len(sys.argv) > 2 else "CLI Test"

    print("="*80)
    print("GENERATE REPORT CLI TEST")
    print("="*80)
    print(f"Target: {target}")
    print(f"Customer: {customer_name}")
    print("="*80)
    print()

    # Connect to the Flask-SocketIO server
    server_url = os.environ.get("NMAPUI_URL", "http://localhost:9000")
    print(f"Connecting to {server_url}...")

    try:
        sio.connect(server_url)
    except Exception as e:
        print(f"❌ Failed to connect to server: {e}")
        print("\nMake sure the Flask app is running:")
        print("  python app.py")
        sys.exit(1)

    # Wait for connection
    timeout = 5
    while not connected and timeout > 0:
        time.sleep(0.1)
        timeout -= 0.1

    if not connected:
        print("❌ Connection timeout")
        sys.exit(1)

    print()
    print("Starting report generation...")
    print("="*80)
    print()

    # Record start time
    start_time = datetime.now()

    # Emit the generate_report event
    sio.emit('generate_report', {
        'target': target,
        'customer_name': customer_name,
        'auto_scan': False
    })

    # Wait for completion or failure
    max_wait_time = 1500  # 25 minutes max
    wait_interval = 0.5
    elapsed = 0

    while not report_completed and not report_failed and elapsed < max_wait_time:
        time.sleep(wait_interval)
        elapsed += wait_interval

        # Show a heartbeat every 30 seconds
        if int(elapsed) % 30 == 0 and int(elapsed) > 0:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] [{elapsed:6.1f}s] ⏳ Still running... ({elapsed/60:.1f} minutes elapsed)")

    if report_completed:
        print("\n✅ Test completed successfully!")
        sio.disconnect()
        sys.exit(0)
    elif report_failed:
        print("\n❌ Test failed!")
        sio.disconnect()
        sys.exit(1)
    else:
        print(f"\n⏱️  Test timeout after {max_wait_time} seconds")
        sio.disconnect()
        sys.exit(1)


if __name__ == "__main__":
    main()
