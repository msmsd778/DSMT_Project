import base64
from tkinter import Tk
from tkinter.filedialog import askopenfilename

def select_and_convert():
    # Open file dialog
    Tk().withdraw()
    file_path = askopenfilename(
        title="Select an Image File",
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"), ("All Files", "*.*")]
    )
    if not file_path:
        return ""

    # Convert the image to Base64
    with open(file_path, "rb") as img_file:
        img_data = img_file.read()
    return base64.b64encode(img_data).decode('utf-8')

if __name__ == "__main__":
    print(select_and_convert())
