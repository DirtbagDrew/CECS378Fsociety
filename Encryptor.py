#Encryptor
#Author: FSociety
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from tkinter import Tk #used for GUI file picker
from tkinter.filedialog import askopenfilename, asksaveasfilename

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
def WritetoFile(cipher):
	input("Press [enter] to select new or existing save location of encyrpted file")
	Tk().withdraw()
	filename = asksaveasfilename(title="Select Save Location")
	file = open(filename, "wb")
	#print(cipher)
	file.write(cipher)
	file.close
	print ("File succesfully created")

def MyfileEncrypt(filepath):
	key = os.urandom(32);
	message = open(filepath, 'rb') #opens the file in its byte representation
	#print(message)
	C, IV = Myencrypt(message.read(), key) #reads file as a string of bytes
	message.close
	WritetoFile(C)
	return C, IV, key

input("Press [enter] to select the file you would like to encyrpt")
Tk().withdraw()
filename = askopenfilename(title="Select File to Encrypt")
C, IV, key = MyfileEncrypt(filename)
print("Program ran succesfully")

#######################################################################
#Starting the Decryption process; Not currently working
#######################################################################
"""
Tk().withdraw()
filename = askopenfilename()
EncMessage = open(filename, "rb")

#Peliminal Decryptor; Needs formating
backend = default_backend()
cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
decryptor = cipher.decryptor()
#print(EncMessage)
m = decryptor.update(C) + decryptor.finalize()
#print(m)

unpadder = padding.PKCS7(128).unpadder()
data = unpadder.update(m)
data += unpadder.finalize()
WritetoFile(data)
"""
