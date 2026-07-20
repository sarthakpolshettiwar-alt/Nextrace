from usbstor_parser import parse_usbstor_output
from database import setup_database, insert_usb_devices, get_all_devices
import json

SAMPLE_OUTPUT = """usbstor v.20200508
(System) Gets USBStor key info

USBStor
HKLM\\System\\CurrentControlSet\\Enum\\USBSTOR

  Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00
    S/N: 4C531001400615101031&0
    FriendlyName    : SanDisk Cruzer Blade USB Device
    ParentIdPrefix  : 7&2748a623&0
    Last Write Time : Mon May  4 12:30:15 2020 Z

  Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP
    S/N: E0D55EA573D3F121C946002A&0
    FriendlyName    : Kingston DataTraveler 3.0 USB Device
    ParentIdPrefix  : 8&1c2ab410&0
    Last Write Time : Tue Oct 20 08:15:30 2020 Z
"""

def test_pipeline():
    print("1. Initializing database...")
    setup_database()
    
    print("2. Parsing sample output...")
    devices = parse_usbstor_output(SAMPLE_OUTPUT)
    print(f"Parsed {len(devices)} devices.")
    for d in devices:
        print(f" - {d.vendor} {d.product} (S/N: {d.serial_number})")
        
    print("\n3. Inserting into database (with deduplication)...")
    insert_usb_devices(devices, source_hive="sample_SYSTEM")
    
    print("\n4. Retrieving all stored records...")
    records = get_all_devices()
    
    for row in records:
        # Format dates as string for printing
        row['last_write_time'] = str(row['last_write_time'])
        print(json.dumps(row, indent=2))
        
    print("\nPipeline test completed successfully!")

if __name__ == "__main__":
    test_pipeline()
