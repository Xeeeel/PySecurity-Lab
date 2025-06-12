import subprocess
import time
import signal
import csv
import os

def get_adapters():
    result = subprocess.run(["iwconfig"], capture_output=True, text=True)
    output = result.stdout

    adapters = []
    for line in output.splitlines():
        if "IEEE 802.11" in line:
            adapter_name = line.split()[0]
            adapters.append(adapter_name)

    return adapters

def select_adapter(adapters):
    print("Available wireless adapters:")
    for option_number, adapter_name in enumerate(adapters, start=1):
        print(f"{option_number}. {adapter_name}")

    while True:
        try:
            selected_number = int(input("Select an adapter by number: "))
            if 1 <= selected_number <= len(adapters):
                return adapters[selected_number - 1]
            else:
                print("Invalid choice. Try again.")
        except ValueError:
            print("Please enter a valid number.")

def start_monitor_mode(adapter):
    print(f"Starting monitor mode on {adapter}...")
    subprocess.run(["airmon-ng", "start", adapter])

def run_airodump(adapter, output_prefix="scan_output"):
    print(f"Running airodump-ng on {adapter} for 30 seconds...")
    process = subprocess.Popen(
        ["airodump-ng", "--write", output_prefix, "--output-format", "csv", adapter],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    try:
        time.sleep(30)
        process.send_signal(signal.SIGINT)
        process.wait()
        print("Airodump-ng stopped.")
    except KeyboardInterrupt:
        process.terminate()
        process.wait()

    return f"{output_prefix}-01.csv"

def stop_monitor_mode(adapter):
    print(f"Stopping monitor mode on {adapter}...")
    subprocess.run(["airmon-ng", "stop", adapter])

def parse_csv(filepath):
    essids = []
    stations = []
    with open(filepath, newline='') as csvfile:
        reader = csv.reader(csvfile)
        section = "AP"

        for row in reader:
            if len(row) == 0:
                continue  # skip empty lines
            if row[0].strip() == "Station MAC":
                section = "STA"
                continue

            if section == "AP":
                if len(row) > 13 and row[0].strip() != "BSSID":
                    essids.append({
                        "BSSID": row[0].strip(),
                        "ESSID": row[13].strip()
                    })
            elif section == "STA":
                if len(row) > 5:
                    stations.append({
                        "Station": row[0].strip(),
                        "BSSID": row[5].strip()
                    })
    # Build a mapping from BSSID to ESSID
    bssid_to_essid = {ap["BSSID"]: ap["ESSID"] for ap in essids}

    return essids, stations

def display_networks(essids, stations):
    """Display each station (client) with the ESSID of the AP it's connected to."""
    print("\n[+] Device and their Associated Networks:\n")
    
    # Build BSSID → ESSID lookup
    bssid_to_essid = {ap["BSSID"]: ap["ESSID"] for ap in essids}

    # Header
    print(f"{'Device MAC':<20} {'Network (ESSID)':<30}")
    print("-" * 50)

    # List stations
    for station in stations:
        station_mac = station["Station"]
        bssid = station["BSSID"]
        essid = bssid_to_essid.get(bssid, "Unknown")

        print(f"{station_mac:<20} {essid:<30}")

def main():
    adapters = get_adapters()

    if not adapters:
        print("No wireless adapters found.")
        return

    selected_adapter = select_adapter(adapters)
    start_monitor_mode(selected_adapter)

    # Detect monitor mode adapter name
    result = subprocess.run(["iwconfig"], capture_output=True, text=True)
    monitor_adapter = None
    for line in result.stdout.splitlines():
        if "Mode:Monitor" in line:
            monitor_adapter = line.split()[0]
            break

    if monitor_adapter is None:
        print("Could not detect monitor mode adapter.")
        return

    csv_file = run_airodump(monitor_adapter)
    stop_monitor_mode(monitor_adapter)

    if os.path.exists(csv_file):
        essids, stations = parse_csv(csv_file)
        display_networks(essids, stations)
    else:
        print("No scan data found.")

if __name__ == "__main__":
    main()
