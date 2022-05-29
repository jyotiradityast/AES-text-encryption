from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode, b64decode
import hashlib
from tkinter import *
from tkinter import messagebox
#^^^The Essentials^^^------------------------

#The Root Window and GUI elements------------

bgcolour="#a2e1ff"
root=Tk()
root.title("AES|128 bits block|256 bits key|Ciphertext Block Chaining Mode")
icon=PhotoImage(file="icon.png")
root.iconphoto(True, icon)

#--------------------------------------------

#Clear---------------------------------------

def clear():
    entry_pt.delete(0, END)
    entry_cipher.delete(0, END)
    entry_iv.delete(0, END)
    entry_key.delete(0, END)

#--------------------------------------------

#Encryption----------------------------------

def encrypt():
    plaintext=entry_pt.get()
    byte_plaintext=plaintext.encode('utf-8')

    key_original=entry_key.get()
    key_encode=key_original.encode()
    
    key_hash=hashlib.sha256(key_encode).digest()
    #Hashing the encoded key to get a 256 bit key

    cipher=AES.new(key_hash,AES.MODE_CBC)
    #Instantiating a cipher object

    ciphertext=cipher.encrypt(pad(byte_plaintext,AES.block_size))
    #Encrytpting the byte_plaintext after padding

    ciphertext_display=b64encode(ciphertext).decode('utf-8')
    #Converting the ciphertext in base64 byte sequence to string for display.

    entry_cipher.insert(0,ciphertext_display)
    #Displaying the Ciphertext in utf-8.

    iv_display=b64encode(cipher.IV).decode('utf-8')
    #Retrieving the Initial Vector that was assigned randomly in utf-8 from base64 byte sequence

    entry_iv.insert(0,iv_display)
    #Displaying the Initial Vector in utf-8
    
    #for testing----------------------------------------#
    print("Cipher Text: ",ciphertext)                   #
    print("Cipher Text Display: ",ciphertext_display)   #
    print("Cipher IV: ",cipher.iv)                      #
    print("Display IV: ",iv_display)                    #
    #---------------------------------------------------#

    return

#--------------------------------------------

#Decryption----------------------------------

def decrypt():
    try:
        entry_pt.delete(0, END)
        ciphertext=entry_cipher.get()
        decode_ciphertext=b64decode(ciphertext)
        #Retrieving ciphertext

        iv_entered=entry_iv.get()
        decode_iv=b64decode(iv_entered)
        #Retrieving Initial Vector

        key_original=entry_key.get()
        #Retrieving the key

        key_encode=key_original.encode()
        #encoding the key for hashing

        key_hash=hashlib.sha256(key_encode).digest()
        #Hashing the entered key to get a 256 bit key

        cipher=AES.new(key_hash,AES.MODE_CBC,decode_iv)
        #Instantiating a cipher object

        plaintext=unpad(cipher.decrypt(decode_ciphertext), AES.block_size)
        #decrytpting and unpadding to get the plaintext in form of bytes 

        plaintext_display=plaintext.decode()
        #converting the plaintext from byte sequence to normal string.

        entry_pt.insert(0,plaintext_display)
        #Displaying the Ciphertext in utf-8

        #for testing----------------------------------------#
        print("Decode Ciphertext: ",decode_ciphertext)      #
        print("Decode IV: ",decode_iv)                      #
        #---------------------------------------------------#

    except:
        message=messagebox.showerror("Error","Please enter correct info.")
        #If any element(s) is(/are) missing or if the entered element(s) is(/are) not correct,
        #there will be incorrect padding.

    return

#--------------------------------------------

#Copy to clipboard functions-----------------

def clip_encrypt():

    root.clipboard_clear()
    #clears the clipboard

    root.clipboard_append("Ciphertext: "+entry_cipher.get())
    #copies encrypted text to clipboard

    return

def clip_decrypt():

    root.clipboard_clear()
    #clears the clipboard

    root.clipboard_append(entry_pt.get())
    #copies decrypted text to clipboard

    return

def clip_iv():

    root.clipboard_clear()
    #clears the clipboard

    root.clipboard_append("Initial Vector: "+entry_iv.get())
    #copies Initial Vector to clipboard

    return

def clip_all():

    root.clipboard_clear()
    #clears the clipboard

    all_string="Ciphertext: "+entry_cipher.get()+"\n"+"Initial Vector: "+entry_iv.get()

    root.clipboard_append(all_string)
    #copies Encrypted Text and Initial Vector to clipboard

    return

#--------------------------------------------

#Info----------------------------------------

def info():

    info_title="191B134 | OSS Lab/IS Project"
    info_string='''OSS Lab/Information Security Project         

    Submitted to-
    Dr. Amit Kumar
    Dr. Ravindra Kumar Singh\n
    Submitted by-
    191B134 Jyotiraditya Singh Tomar
    '''

    info=messagebox.showinfo(info_title,info_string)

    return

#--------------------------------------------

#GUI Elements--------------------------------

lf=LabelFrame(root, text="Plain Text")
lf.grid(row=1,column=1,sticky="nesw",pady=7,padx=10,columnspan=2)
entry_pt=Entry(lf)
entry_pt.grid(row=1,column=1,sticky="nesw",ipadx=200)

key_frame=LabelFrame(root, text="Enter Key")
key_frame.grid(row=2,column=1,sticky="nesw",pady=7,padx=10,columnspan=2)
entry_key=Entry(key_frame, show="*")
entry_key.grid(row=1,column=1,sticky="nesw",ipadx=200)

cipher_frame=LabelFrame(root, text="Cipher Text(En)")
cipher_frame.grid(row=3,column=1,sticky="nesw",pady=7,padx=10,columnspan=2)
entry_cipher=Entry(cipher_frame)
entry_cipher.grid(row=1,column=1,sticky="nesw",ipadx=200)

iv_frame=LabelFrame(root, text="Initial Vector(IV)")
iv_frame.grid(row=4,column=1,sticky="nesw",pady=7,padx=10,columnspan=2)
entry_iv=Entry(iv_frame)
entry_iv.grid(row=1,column=1,sticky="nesw",ipadx=200)

button_encrypt=Button(root,text="Encrypt", command=encrypt)
button_encrypt.grid(row=5,column=1,sticky="nesw",padx=10, pady=7)

button_encrypt_clip=Button(root,text="Copy encrypted text to clipboard", command=clip_encrypt)
button_encrypt_clip.grid(row=5,column=2,sticky="nesw",padx=10, pady=7)

button_decrypt=Button(root,text="Decrypt", command=decrypt)
button_decrypt.grid(row=6,column=1,sticky="nesw",padx=10, pady=7)

button_decrypt_clip=Button(root,text="Copy decrypted text to clipboard", command=clip_decrypt)
button_decrypt_clip.grid(row=6,column=2,sticky="nesw",padx=10, pady=7)

button_iv_clip=Button(root,text="Copy initial vector to clipboard", command=clip_iv)
button_iv_clip.grid(row=7,column=2,sticky="nesw",padx=10, pady=7)

button_clip_all=Button(root,text="Copy En+IV to clipboard", command=clip_all)
button_clip_all.grid(row=8,column=2,sticky="nesw",padx=10, pady=7)

button_reset=Button(root,text="     Reset     ",command=clear)
button_reset.grid(row=7,column=1,sticky="nesw",padx=10, pady=7)

button_info=Button(root,text="Info", command=info)
button_info.grid(row=8,column=1,sticky="nesw",padx=10, pady=7)

#--------------------------------------------

root.mainloop()

#--------------------------------------------
#Code: JST