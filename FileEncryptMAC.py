#FileEncryptMAC
#Author: FSociety
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.padding import MGF1 as uno #had issues going to another package, so just a random nickname
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from tkinter import Tk #used for GUI file picker
from tkinter.filedialog import askopenfilename, asksaveasfilename
from pathlib import Path #used to get file ext 

def MyencryptMAC(message, Enckey, HMACKey):
	if len(Enckey) < 32:
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
	cipher = Cipher(algorithms.AES(Enckey), modes.CBC(IV), backend=backend)
	encryptor = cipher.encryptor()
	C = encryptor.update(padded_message) + encryptor.finalize() #Generates ciphertext
	
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend()) #Generates tag
	h.update(C)
	tag = h.finalize()
	return C, IV, tag

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

def MyfileEncryptMAC(filepath):
	EncKey = os.urandom(32);
	HMACKey = os.urandom(32); #Generates HMACKey using random number
	message = open(filepath, 'rb') #opens the file in its byte representation
	C, IV, tag = MyencryptMAC(message.read(), EncKey, HMACKey) #reads file as a string of bytes
	message.close
	ext = Path(filepath).suffix # grabs extension of file
	input("Press [enter] to select new or existing save location of encyrpted file")
	WritetoFile(C, None)
	return C, IV, EncKey, ext, HMACKey, tag

def Decryptor(IV, EncKey, ext, HMACKey, tag):
	Tk().withdraw()
	filename = askopenfilename(title = "Select File to Decrypt")
	EncMessage = open(filename, "rb")
	C = EncMessage.read()
	EncMessage.close
	
	try: #Used to verify tag
		h = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
		h.update(C)
		h.verify(tag)
	except cryptography.exceptions.InvalidSignature:
		print("Signature does not match")
		raise SystemExit
	
	backend = default_backend()
	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend=backend)
	decryptor = cipher.decryptor() #decrypts
	m = decryptor.update(C) + decryptor.finalize()

	unpadder = padding.PKCS7(128).unpadder() #unpads
	data = unpadder.update(m) 
	data += unpadder.finalize()
	input("Press [enter] to select save location of decrypted file")
	WritetoFile(data, ext) #saves to file

def MyRSAencrypt(filepath, RSA_Publickey_filepath):
        backend=default_backend()
        C, IV, EncKey, ext, HMACKey, tag  = MyfileEncryptMAC(filepath)    #encrypts message   
        
        RSACipher = public_key.encrypt(         #use RSA encrypt to encrypt the public key
                EncKey+HMACKey,
                OAEP(
                        mgf=MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                )       
        )
        return RSACipher, C, IV, ext, tag
        
        
def MyRSAdecrypt (RSACipher, C, IV, ext, RSA_Privatekey_filepath, tag):
		key = private_key.decrypt(      #uses private key to decrypt key used for message
		RSACipher,
		OAEP(
		mgf=uno(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
		EncKey = key[0:32]
		HMACKey = key[len(EncKey):]
		Decryptor(IV, EncKey, ext, HMACKey, tag) #decrypt the message using decrypted key
        
def generate_key_pair():  
    private_key = rsa.generate_private_key( #generate a private key
         public_exponent=65537,
         key_size=2048,
         backend=default_backend()
    )
    public_key = private_key.public_key()   # generate public key
    return public_key, private_key

if(os.path.exists('./public_key.pem') == False):
    public_key, private_key = generate_key_pair()

private_pem = private_key.private_bytes( #Used to create private_key PEM file
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes( #USed to create public_key PEM file
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
)
private_file = open ("private_key.pem", "wb") #Writes private_key to file
private_file.write(private_pem)

public_file = open ("public_key.pem", "wb") #Writes public_key to file
public_file.write(public_pem)



input("Press [enter] to select the file you would like to encrypt")
Tk().withdraw()
filename = askopenfilename(title = "Select File to Encrypt")
RSACipher, C, IV, ext, tag = MyRSAencrypt(filename, "public_key.pem") #Encrypt
input("Press [enter] to select file to decrypt")
MyRSAdecrypt(RSACipher, C, IV, ext, "private_key.pem", tag) #Decrypt


    
    















        
