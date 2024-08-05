import os
from flask import Flask, request, jsonify, send_file, current_app
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import tempfile
import secrets
import shutil
import pyzipper
import io
from werkzeug.utils import secure_filename, safe_join
from pypdf import PdfReader, PdfWriter
import argparse,sys

from flask_mail import *
import smtplib, ssl 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import date

app = Flask(__name__)




port = 26  # For starttls
smtp_server = "sslmx.safeserverhost.com"
sender_email = "hostemail"
receiver_email = "martinallen722@gmail.com"
password = "password"

api_keys = {}

@app.route('/get-api-key', methods=['GET'])
def get_api_key():
    api_key = secrets.token_urlsafe(16)
    api_keys[api_key] = True
    return jsonify({"api_key": api_key, "expires_in": 600})

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    # api_key = request.args['mykey']
    
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key not in api_keys:
        return jsonify({"error": "Invalid or missing API key"}), 403
   

    password ='iiii'
    # file = request.
    # file = request.files['file']
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()

    try:
        # Create a temporary file to write encrypted contents
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            for chunk in file.stream:
                temp_file.write(encryptor.update(chunk))
            temp_file.write(encryptor.finalize())

        encrypted_file_path = temp_file.name

        return send_file(encrypted_file_path, as_attachment=True, download_name='encrypted_file')

    except Exception as e:
        return jsonify({"error": f"Failed to encrypt file: {str(e)}"}), 500
    finally:
        if 'encrypted_file_path' in locals() and os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)

@app.route('/zip', methods=['POST'])
def zip_file():
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key not in api_keys:
        return jsonify({"error": "Invalid or missing API khey"}), 401

    password = request.form['password']
    file = request.files['file']
    filename = secure_filename(file.filename)

    try:
        # Create an in-memory buffer for the ZIP file
        zip_buffer = io.BytesIO()

        # Create a ZipFile object with encryption
        with pyzipper.AESZipFile(zip_buffer, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password.encode())  # Set the password for encryption
            zf.writestr(filename, file.read())  # Write the file contents to the ZIP

        zip_buffer.seek(0)
        os.remove(filename)
        # Return the ZIP file as a Flask response
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name=f"{filename}.zip",
            mimetype='application/zip'
        )

    except Exception as e:
        return jsonify({"error": f"Failed to create encrypted ZIP file: {str(e)}"}), 500

@app.route('/allen', methods=['POST'])
def allen():

    try:

        id = request.args.get('id')
        membeno=request.args.get('membeno')
        # path = rf"Desktop"

        base_path = "C:/Users/administrator.KMASACCO/Documents/AL/NonEncrypted"
        file_name = membeno

        save_path = 'C:/Users/administrator.KMASACCO/Documents/AL/NonEncrypted/Encrypted'
        completeName = os.path.join(save_path, file_name) 
    
    
        # Using os.path.join() 
        file_path = os.path.join(base_path, file_name) 
        isFile = os.path.isfile(file_path)
        
        # Usage 
        if isFile:

            reader = PdfReader(str(file_path))

            writer = PdfWriter()
            writer.append_pages_from_reader(reader)
            writer.encrypt(id)

            with open(completeName, "wb") as out_file:
                writer.write(out_file)

        
    except:
        id = request.args.get('id')
        membeno=request.args.get('membeno')
        # path = rf"Desktop"

        base_path = "C:/Users/administrator.KMASACCO/Documents/AL/KMA_SACCO/Encryption"
        file_name = membeno

        save_path = 'C:/example/'

    
    
        # Using os.path.join() 
        file_path = os.path.join(base_path, file_name) 
        isFile = os.path.isfile(file_path)
        print(isFile)
        reader = PdfReader(str(file_path))

        writer = PdfWriter()
        writer.append_pages_from_reader(reader)
        writer.encrypt(id)
        with open("output.pdf", "wb") as out_file:
            writer.write(out_file)
    #     return '''<h1>The source value is: {}</h1>'''.format(file_path)
    return '''<h1>The source value is: {}</h1>'''.format(file_path)

@app.route('/unzip', methods=['POST'])
def unzipall():
    filename = "C:/Users/administrator.KMASACCO/Documents/AL/NonEncrypted/MemberStatement.zip"
    extract_dir = "C:/Users/administrator.KMASACCO/Documents/AL/NonEncrypted"
    shutil.unpack_archive(filename, extract_dir)
    os.remove(filename)
    return 'Success'

@app.route('/clearpdf', methods=['POST'])
def clearpdf():
    dir_name = "C:/Users/administrator.KMASACCO/Documents/AL/NonEncrypted/"
    objectFile = os.listdir(dir_name)

    for item in objectFile:
        if item.endswith(".pdf"):
            os.remove(os.path.join(dir_name, item))
    return 'Success'

@app.route('/sendmail', methods=['POST'])
def sendmail():
    try:
        message = MIMEText(text, "plain")
        message["Subject"] = "Plain text email"
        message["From"] = sender_email
        message["To"] = receiver_email
       
        with smtplib.SMTP(smtp_server, port) as server:
            server.ehlo()  # Can be omitted
            server.starttls(context=context)
            server.ehlo()  # Can be omitted
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
            print(message)
    except:
        message = f"""From: {sender_email}
            To: {receiver_email}

            This message is sent from Python."""
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, port) as server:
            
            server.ehlo()  # Can be omitted
            server.starttls(context=context)
            server.ehlo()  # Can be omitted
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
        
    return "Mail Sent, Please check the mail id"

@app.route('/sendmail1', methods=['POST'])
def sendmail1():
    try:
        email = request.args.get('email')
        membeno=request.args.get('membeno')
        salutation=request.args.get('salutation')
        name=request.args.get('name')
        print(name)
        # Email content
        subject = "KMA REGULATED NWDT SACCO MEMBER STATEMENT"
        body = f"""
        
        Dear {salutation} {name} \n
        Thank you for your continued patronage.\n
        Please Find Attached your member statement as at {date.today()} \n
        Kindly click on the below link to access the member portal.\n
        LINK: https://portal.kmasacco.com:449 \n
        For any queries kindly contact customercare@kmasacco.com or call 0722519037.\n

        Kind Regards\n

        Customer Care Team
        """

        # Create a multipart message and set headers

        message = MIMEMultipart()
        message["Subject"] = subject
        message["From"] = sender_email
        message["To"] = email
        message.attach(MIMEText(body, "plain"))

        # Specify the attachment file path
        filename = "C:/Users/administrator.KMASACCO/Documents/AL/NonEncrypted/Encrypted/"+membeno+".pdf" 

        # Open the file in binary mode
        with open(filename, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())

        # Encode file in ASCII characters to send by email
        encoders.encode_base64(part)

        # Add header as key/value pair to attachment part
        # filename
        part.add_header("Content-Disposition", f"attachment; filename= {membeno+"-Monthly Member Statement.pdf"}")

        # Add attachment to message
        message.attach(part)
       
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls()  # Secure the connection
          
            server.login(sender_email, password)
            server.sendmail(sender_email, email, message.as_string())
            print(message)
    except:
        email = request.args.get('email')
        membeno=request.args.get('membeno')
        salutation=request.args.get('salutation')
        name=request.args.get('name')
        # Email content
        subject = "KMA REGULATED NWDT SACCO MEMBER STATEMENT"
        body = f""" 

            Dear {salutation} {name} \n
            Thank you for your continued patronage.\n
            Please Find Attached your member statement as at {date.today()} \n
            Kindly click on the below link to access the member portal.\n
            LINK: https://portal.kmasacco.com:449 \n
            For any queries kindly contact customercare@kmasacco.com or call 0722519037.\n

            Kind Regards\n

            Customer Care Team

            """
        print(date.today())
        # Create a multipart message and set headers

        message = MIMEMultipart()
        message["Subject"] = subject
        message["From"] = sender_email
        message["To"] = email
        message.attach(MIMEText(body, "plain"))

        # Specify the attachment file path
        filename = "C:/Users/administrator.KMASACCO/Documents/AL/NonEncrypted/Encrypted/"+membeno+".pdf"

        # Open the file in binary mode
        with open(filename, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())

        # Encode file in ASCII characters to send by email
        encoders.encode_base64(part)

        # Add header as key/value pair to attachment part
        # filename
        part.add_header("Content-Disposition", f"attachment; filename= {membeno+"-Monthly Member Statement.pdf"}")

        # Add attachment to message
        message.attach(part)
       
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls()  # Secure the connection
          
            server.login(sender_email, password)
            server.sendmail(sender_email, email, message.as_string())
            print(message)
        
    return "Mail Sent, Please check the mail id"

