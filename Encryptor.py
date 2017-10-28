#Encryptor
#Author: FSociety
import os 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from tkinter import Tk #used for GUI file picker
from tkinter.filedialog import askopenfilename

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
	padded_message = padder.finalize()
	
	backend = default_backend()
	IV = os.urandom(16) #Generates IV
	cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
	encryptor = cipher.encryptor()
	C = encryptor.update(padded_message) + encryptor.finalize() #Generates ciphertext 
	return C, IV

#For testing of Myencrypt
"""
message = input("Enter your message: ")
key = os.urandom(32) #The test key is a random nuber of 32bytes 
C,IV = Myencrypt(message,key)
print ("Cipher Text: ",C)
"""

#Used for writing the cipher text to a file
def WritetoFile(cipher):
	while True: #Loop used to ensure correct user input
		selection = input("Select an Option: \n1. Write to existing File \n2. Create new File\n")
		if selection == '1':
			Tk().withdraw()
			filename = askopenfilename()
			break
		elif selection == '2':
			filename = input("Enter the name of the txt file you would like to create: ")
			break
		else:
			print ("Incorrect Input. Please try again and type 1 or 2.")
	file = open(filename, 'wb') 
	file.write(cipher)
	file.close
	print ("File succesfully created")

def MyfileEncrypt(filepath):
	key = os.urandom(32)
	message = open(filepath, 'rb') #opens the file in its byte representation
	C, IV = Myencrypt(message.read(), key) #reads file as a string of bytes
	message.close
	WritetoFile(C)
	return C, IV, key
	
input("Press [enter] to select the file you would like to encyrpt") 	
Tk().withdraw()
filename = askopenfilename()
C, IV, key = MyfileEncrypt(filename)
print("Program ran succesfully")