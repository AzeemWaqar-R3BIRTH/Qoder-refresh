#!/usr/bin/env python3
"""
Camera QR Scanning Troubleshooting Guide
This script provides detailed debugging information for camera QR scanning issues
"""

import requests
import json
from datetime import datetime

def test_server_connectivity():
    """Test if the server is responding"""
    print("🔍 Testing server connectivity...")
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("✅ Server is responding")
            return True
        else:
            print(f"❌ Server responded with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        return False

def test_login_page():
    """Test if login page loads properly"""
    print("\n🔍 Testing login page...")
    try:
        response = requests.get("http://localhost:5000/login", timeout=5)
        if response.status_code == 200:
            print("✅ Login page loads successfully")
            
            # Check for QR scanner library
            if "qr-scanner" in response.text.lower():
                print("✅ QR Scanner library is included")
            else:
                print("❌ QR Scanner library not found in page")
                
            # Check for required elements
            required_elements = [
                'id="open-camera-btn"',
                'id="video"',
                'id="camera-modal"',
                'QrScanner'
            ]
            
            for element in required_elements:
                if element in response.text:
                    print(f"✅ Found: {element}")
                else:
                    print(f"❌ Missing: {element}")
                    
            return True
        else:
            print(f"❌ Login page failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error loading login page: {e}")
        return False

def print_debugging_instructions():
    """Print detailed debugging instructions for camera scanning"""
    print("\n" + "="*80)
    print("📋 CAMERA QR SCANNING DEBUGGING GUIDE")
    print("="*80)
    
    print("\n🔧 STEP-BY-STEP DEBUGGING:")
    
    print("\n1. 📱 OPEN THE LOGIN PAGE:")
    print("   - Go to: http://localhost:5000/login")
    print("   - Open browser Developer Tools (F12)")
    print("   - Go to Console tab")
    
    print("\n2. 🎥 CLICK 'OPEN CAMERA' BUTTON:")
    print("   - Click the 'Open Camera' button")
    print("   - Watch for console logs starting with camera symbols")
    
    print("\n3. 🔍 CHECK CONSOLE LOGS - Look for these messages:")
    print("   ✅ Expected SUCCESS messages:")
    print("      📷 Opening camera modal...")
    print("      🎥 Requesting camera access...")
    print("      ✅ Camera access granted")
    print("      ▶️ Video started playing")
    print("      📷 Starting QR scanner after video stabilization...")
    print("      📷 Initializing QR Scanner...")
    print("      ✅ QR Scanner started successfully!")
    
    print("\n   ❌ POTENTIAL ERROR messages to watch for:")
    print("      ❌ Camera access denied")
    print("      ❌ No camera found")
    print("      ❌ Video element not ready")
    print("      ❌ QrScanner library not loaded")
    
    print("\n4. 📱 TEST QR CODE SCANNING:")
    print("   - Hold a QR code in front of the camera")
    print("   - Watch for detection logs:")
    print("      🎉 QR Code detected!")
    print("      🔍 QR Code data: [your QR data]")
    print("      ✅ Valid QR data received, processing...")
    
    print("\n5. 🚨 COMMON ISSUES & SOLUTIONS:")
    
    print("\n   ISSUE: Camera permission denied")
    print("   SOLUTION:")
    print("   - Click the camera icon in browser address bar")
    print("   - Allow camera access")
    print("   - Refresh page and try again")
    
    print("\n   ISSUE: QR Scanner library not loaded")
    print("   SOLUTION:")
    print("   - Check internet connection")
    print("   - Refresh page")
    print("   - Check browser console for network errors")
    
    print("\n   ISSUE: Video not starting")
    print("   SOLUTION:")
    print("   - Ensure camera is not used by other applications")
    print("   - Try closing other browser tabs using camera")
    print("   - Restart browser")
    
    print("\n   ISSUE: QR codes not being detected")
    print("   SOLUTION:")
    print("   - Ensure QR code is clear and well-lit")
    print("   - Hold QR code steady for 2-3 seconds")
    print("   - Try moving QR code closer/further from camera")
    print("   - Check if QR code is valid by using file upload instead")
    
    print("\n6. 📊 NETWORK REQUESTS:")
    print("   - Go to Network tab in Developer Tools")
    print("   - When QR is detected, look for:")
    print("     POST /api/auth/login (should be 200 OK)")
    print("   - Check request payload contains 'qr_data'")
    
    print("\n7. 🔄 IF CAMERA SCANNING STILL DOESN'T WORK:")
    print("   - Use drag & drop instead (which is working)")
    print("   - Save QR code image from email")
    print("   - Drag the image to the upload area")
    
    print("\n" + "="*80)
    print("💡 TIP: Most camera scanning issues are browser permission related!")
    print("="*80)

def main():
    """Main debugging function"""
    print("🔍 CAMERA QR SCANNING TROUBLESHOOTING TOOL")
    print("This tool will help diagnose camera scanning issues\n")
    
    # Test server
    if not test_server_connectivity():
        print("\n❌ Cannot proceed - server is not running")
        print("Please start the server first: python securetrainer.py")
        return
    
    # Test login page
    if not test_login_page():
        print("\n❌ Cannot proceed - login page has issues")
        return
    
    # Print debugging guide
    print_debugging_instructions()
    
    print(f"\n🕒 Debug session completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()