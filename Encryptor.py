#Encryptor
#Author: FSociety
import os 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def Myencrypt(message, key):
	if len(key) < 32:
		print("The key legth is too short. A key length of 32 bytes is required.")
		return None, None;
	
	padder = padding.PKCS7(128).padder() #Message must be padded to match block size
	padded_message = padder.update(message.encode()) #encode() is used to turn message into byte representation
	padded_message = padder.finalize()
	
	backend = default_backend()
	IV = os.urandom(16) #Generates IV
	cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
	encryptor = cipher.encryptor()
	C = encryptor.update(padded_message) + encryptor.finalize() #Generates ciphertext 
	return C, IV

#For testing purposes
message = input("Enter your message: ")
key = os.urandom(32) #The test key is a random nuber of 32bytes 
C,IV = Myencrypt(message,key)
print ("Cipher Text: ",C)

#Used if you want to write the cipher text to a file
file = open('Ciphertext.txt', 'wb') 
file.write(C)
file.close
print ("File succesfully created")