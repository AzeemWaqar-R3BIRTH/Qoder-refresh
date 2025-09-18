import qrcode
from PIL import Image
import pyzbar.pyzbar as pyzbar
import io

# Test data - plain text
test_id = "test123"
print(f"Test data: '{test_id}'")

# Generate QR code with test data
print("Generating QR code...")
qr_img = qrcode.make(test_id)
qr_img.save("test_plain.png")
print("QR code saved as 'test_plain.png'")

# Now read it back
print("\nReading back QR code...")
with open("test_plain.png", "rb") as f:
    image = Image.open(f)
    decoded = pyzbar.decode(image)

    if not decoded:
        print("ERROR: No QR code detected in image")
    else:
        # Get the raw data
        raw_data = decoded[0].data

        # Convert to string
        decoded_text = raw_data.decode('utf-8')

        print(f"Decoded text: '{decoded_text}'")

        # Verify it matches
        if decoded_text == test_id:
            print("SUCCESS: Decoded text matches original")
        else:
            print(f"ERROR: Decoded text doesn't match. Expected '{test_id}', got '{decoded_text}'")
