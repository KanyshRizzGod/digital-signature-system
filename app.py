import os
from flask import Flask, request, render_template, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

app = Flask(__name__)

# --- Setup ---
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Updated Database Model ---
class DocumentLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="User") # Manager, Director, etc.
    action = db.Column(db.String(50), nullable=False) 
    status = db.Column(db.String(50), default="Pending") # Approved, Rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# --- RSA Key Logic (Remains same as previous) ---
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
def load_keys():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_FILE, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub
private_key, public_key = load_keys()

# --- Updated Routes ---

@app.route('/', methods=['GET'])
def home():
    logs = DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all()
    return render_template('index.html', logs=logs)

@app.route('/upload', methods=['POST'])
def upload_and_sign():
    role = request.form.get('role', 'User') # Get role from form
    file = request.files.get('file')
    
    if not file or file.filename == '':
        return render_template('index.html', error="No file selected.", logs=DocumentLog.query.all())

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

    # Log with Role and Status
    status = "Approved" if role in ["Manager", "Director"] else "Signed (Pending Approval)"
    new_log = DocumentLog(filename=file.filename, role=role, action="Signed", status=status)
    db.session.add(new_log)
    db.session.commit()

    return render_template('index.html', 
                           message=f"✅ {role} Signature Applied to '{file.filename}'.", 
                           sig_filename=f"{file.filename}.sig", 
                           logs=DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all())

@app.route('/verify', methods=['POST'])
def verify_signature():
    file = request.files.get('file')
    sig_file = request.files.get('signature')
    
    try:
        public_key.verify(
            sig_file.read(),
            file.read(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        new_log = DocumentLog(filename=file.filename, role="System", action="Verified", status="Integrity Confirmed")
        db.session.add(new_log)
        db.session.commit()
        return render_template('index.html', message="✅ Signature VALID.", logs=DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all())
    except:
        return render_template('index.html', error="❌ Verification FAILED.", logs=DocumentLog.query.order_by(DocumentLog.timestamp.desc()).all())

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)