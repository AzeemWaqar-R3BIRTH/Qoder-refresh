#!/usr/bin/env python3
"""Test pyzbar installation and QR code decoding."""

import sys
import os

def test_pyzbar():
    """Test if pyzbar is working correctly."""
    try:
        print("🔍 Testing pyzbar installation...")
        from pyzbar import pyzbar
        from PIL import Image
        print("✅ pyzbar and PIL imported successfully")
        
        # Test with a simple QR code
        print("🔍 Testing QR code decoding...")
        
        # Check if we have any QR code files
        qr_dir = "qr_codes"
        if os.path.exists(qr_dir):
            qr_files = [f for f in os.listdir(qr_dir) if f.endswith('.png')]
            print(f"📁 Found {len(qr_files)} QR code files")
            
            if qr_files:
                # Test with the first QR code file
                test_file = os.path.join(qr_dir, qr_files[0])
                print(f"🧪 Testing with file: {test_file}")
                
                img = Image.open(test_file)
                decoded_objects = pyzbar.decode(img)
                
                print(f"🔍 Decoded {len(decoded_objects)} objects")
                
                for obj in decoded_objects:
                    print(f"📱 QR Code data: {obj.data.decode('utf-8')}")
                    print(f"📱 QR Code type: {obj.type}")
                
                if decoded_objects:
                    print("✅ QR code decoding successful!")
                    return True
                else:
                    print("❌ No QR codes found in image")
                    return False
            else:
                print("❌ No QR code files found for testing")
                return False
        else:
            print("❌ QR codes directory not found")
            return False
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Try installing: pip install pyzbar")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = test_pyzbar()
    if success:
        print("\n✅ pyzbar is working correctly!")
    else:
        print("\n❌ pyzbar is not working. This is likely the cause of QR code issues.")
        print("💡 Install with: pip install pyzbar")
        print("💡 On Windows, you may also need: pip install pyzbar[scripts]")
