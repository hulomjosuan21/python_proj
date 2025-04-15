import os
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

ASSETS_DIR = os.path.join(os.getcwd(), 'assets')
IMAGE_DIR = os.path.join(ASSETS_DIR, 'images')
OTHER_DIR = os.path.join(ASSETS_DIR, 'others')

os.makedirs(IMAGE_DIR, exist_ok=True)
os.makedirs(OTHER_DIR, exist_ok=True)

@app.post('/upload')
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)

    file_type = file.content_type
    print(f"File type: {file_type}")

    if file_type.startswith('image/'):
        save_path = os.path.join(IMAGE_DIR, filename)
        category = 'image'
    else:
        save_path = os.path.join(OTHER_DIR, filename)
        category = 'other'

    file.save(save_path)

    return jsonify({
        'message': f'File {filename} uploaded successfully',
        'category': category,
        'saved_to': save_path
    }), 200