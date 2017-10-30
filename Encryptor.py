#Encryptor
#Author: FSociety
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from tkinter import Tk #used for GUI file picker
from tkinter.filedialog import askopenfilename, asksaveasfilename #Dialog for opening/saving files
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
	WritetoFile(C,None)
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

input("Press [enter] to select the file you would like to encyrpt")
Tk().withdraw()
filename = askopenfilename(title="Select File to Encrypt")
C, IV, key, ext = MyfileEncrypt(filename)
input("Press [enter] to select file to decrypt")
Decryptor(IV, key, ext)

print("Program ran succesfully")



