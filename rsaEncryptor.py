#RSAEncryptor
#Author: FSociety
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.padding import MGF1 as uno #had issues going to another package, so just a random nickname
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from tkinter import Tk #used for GUI file picker
from tkinter.filedialog import askopenfilename, asksaveasfilename
from pathlib import Path #used to get file ext 

def Myencrypt(message, key):
	if len(key) < 32:
		print("The key legth is too short. A key length of 32 bytes is required.")
		return None, None;
        
	padder = padding.PKCS7(128).padder() #Message must be padded to match block size
	try:
		message = message.encode() #encode() is used to turn message into byte representation
	except (AttributeError): #handles exception if mesage is already a byte
		pass
	padded_message = padder.update(message)
	padded_message += padder.finalize()

	backend = default_backend()
	IV = os.urandom(16) #Generates IV
	cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
	encryptor = cipher.encryptor()
	C = encryptor.update(padded_message) + encryptor.finalize() #Generates ciphertext
	return C, IV

#Used for writing the cipher text to a file
def WritetoFile(cipher, ext):
	Tk().withdraw()
	if ext != None: #used to see if a file ext was passed in
		filename = asksaveasfilename(title="Select Save Location", filetypes = [(ext, ext)] )
	else:
		filename = asksaveasfilename(title="Select Save Location", filetypes = [("All Files","*.*")])
	file = open(filename, "wb")
	file.write(cipher)
	file.close
	print ("File succesfully created")

def MyfileEncrypt(filepath):
	key = os.urandom(32);
	message = open(filepath, 'rb') #opens the file in its byte representation
	C, IV = Myencrypt(message.read(), key) #reads file as a string of bytes
	message.close
	ext = Path(filepath).suffix # grabs extension of file
	input("Press [enter] to select new or existing save location of encyrpted file")
	WritetoFile(C, None)
	return C, IV, key, ext

def Decryptor(IV, key, ext):
	Tk().withdraw()
	filename = askopenfilename(title = "Select File to Decrypt")
	EncMessage = open(filename, "rb")

	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
	decryptor = cipher.decryptor() #decrypts
	m = decryptor.update(EncMessage.read()) + decryptor.finalize()
	EncMessage.close

	unpadder = padding.PKCS7(128).unpadder() #unpads
	data = unpadder.update(m) 
	data += unpadder.finalize()
	input("Press [enter] to select save location of decrypted file")
	WritetoFile(data, ext) #saves to file

def MyRSAencrypt(filepath, RSA_Publickey_filepath):
        backend=default_backend()
        C, IV, key, ext = MyfileEncrypt(filepath)    #encrypts message   
        
        RSACipher = public_key.encrypt(         #use RSA encrypt to encrypt the public key
                key,
                OAEP(
                        mgf=MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                )       
        )
        return RSACipher, C, IV, ext
        
        
def MyRSAdecrypt (RSACipher, C, IV, ext, RSA_Privatekey_filepath):
        key = private_key.decrypt(      #uses private key to decrypt key used for message
        RSACipher,
        OAEP(
         mgf=uno(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
     )
 )
        Decryptor(IV, key, ext)         #decrypt the message using decrypted key
        
        
private_key = rsa.generate_private_key( #generate a private key
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
)
	 
public_key = private_key.public_key()   # generate public key

private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
)
#WritetoFile(private_pem, None) #Writes private key to file
private_file = open ("private_key.pem", "wb")
private_file.write(private_pem)

public_file = open ("public_key.pem", "wb")
public_file.write(public_pem)

input("Press [enter] to select the file you would like to encrypt")
Tk().withdraw()
filename = askopenfilename(title = "Select File to Encrypt")
RSACipher, C, IV, ext = MyRSAencrypt(filename, "public_key.pem") #Encrypt
input("Press [enter] to select file to decrypt")
MyRSAdecrypt(RSACipher, C, IV, ext, "private_key.pem") #Decrypt

















        
