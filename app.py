import os
from flask import Flask, request, render_template, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

app = Flask(__name__)

# --- Setup Upload Folder ---
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Database Model (Activity Log Table) ---
class DocumentLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(50), nullable=False) # 'Signed' or 'Verified'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create the database and tables automatically
with app.app_context():
    db.create_all()

# --- Persistent RSA Key Storage ---
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

def load_or_generate_keys():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            loaded_private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        with open(PUBLIC_KEY_FILE, "rb") as key_file:
            loaded_public_key = serialization.load_pem_public_key(key_file.read())
        return loaded_private_key, loaded_public_key
    else:
        new_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        new_public_key = new_private_key.public_key()
        with open(PRIVATE_KEY_FILE, "wb") as key_file:
            key_file.write(new_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(PUBLIC_KEY_FILE, "wb") as key_file:
            key_file.write(new_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        return new_private_key, new_public_key

private_key, public_key = load_or_generate_keys()

# --- Web Routes ---

@app.route('/', methods=['GET'])
def home():
    # Fetch all logs from the database, newest first
    logs = DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all()
    return render_template('index.html', logs=logs)

@app.route('/upload', methods=['POST'])
def upload_and_sign():
    if 'file' not in request.files or request.files['file'].filename == '':
        return render_template('index.html', error="No file selected.", logs=DocumentLog.query.all())
    
    file = request.files['file']
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    with open(filepath, 'rb') as f:
        file_data = f.read()

    signature = private_key.sign(
        file_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    sig_filepath = filepath + '.sig'
    with open(sig_filepath, 'wb') as f:
        f.write(signature)

    # NEW: Save action to database
    new_log = DocumentLog(filename=file.filename, action="Signed")
    db.session.add(new_log)
    db.session.commit()

    logs = DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all()
    return render_template('index.html', message=f"✅ Success! File '{file.filename}' signed.", sig_filename=f"{file.filename}.sig", logs=logs)

@app.route('/verify', methods=['POST'])
def verify_signature():
    if 'file' not in request.files or 'signature' not in request.files:
        return render_template('index.html', error="Both files are required.", logs=DocumentLog.query.all())

    file = request.files['file']
    sig_file = request.files['signature']

    if file.filename == '' or sig_file.filename == '':
        return render_template('index.html', error="Both files are required.", logs=DocumentLog.query.all())

    file_data = file.read()
    signature_data = sig_file.read()

    logs = DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all()

    try:
        public_key.verify(
            signature_data,
            file_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        # NEW: Save successful verification to database
        new_log = DocumentLog(filename=file.filename, action="Verified (Valid)")
        db.session.add(new_log)
        db.session.commit()
        
        # Refresh logs after adding new entry
        logs = DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all()
        return render_template('index.html', message="✅ Signature is VALID. Document integrity verified.", logs=logs)
    except Exception:
        # Save failed verification attempt
        new_log = DocumentLog(filename=file.filename, action="Verification FAILED")
        db.session.add(new_log)
        db.session.commit()

        logs = DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all()
        return render_template('index.html', error="❌ Signature verification FAILED. The document was tampered with or the signature is invalid.", logs=logs)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)