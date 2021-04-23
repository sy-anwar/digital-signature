from tkinter import *
from tkinter import scrolledtext
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from time import time
from hashlib import sha1
from bs4 import BeautifulSoup
from re import search
from rsa import *
import string

class Gui:
	def __init__(self):
		self.window = Tk()
		self.window.title("Tugas Kecil 4 II4031 - 13517055 13517139")
		self.window.geometry('670x640')
		self.window.resizable(False, False)

		self.rsa = RSA()

		self.key_length = [ 16, 64, 256, 1024 ]

		self.label_choose_key_length = Label(self.window, text='Key Length (bit) ')
		self.label_choose_key_length.grid(column=0, row=3, pady=10, padx=10, sticky=SW)

		self.combobox_key_length = ttk.Combobox(self.window, values=self.key_length, width=10, state="readonly")
		self.combobox_key_length.grid(column=1, row=3, pady=10, sticky=SW)
		self.combobox_key_length.current(0)
		self.combobox_key_length.bind('<<ComboboxSelected>>', self.handler)

		self.btn_generate_key = Button(self.window, text="Generate Keys", width=15, command=self.generate_key_clicked)
		self.btn_generate_key.grid(column=2, row=3, sticky='E', padx=20)

		self.label_public_key = Label(self.window, text='Public Key ')
		self.label_public_key.grid(column=0, row=4, sticky=W, padx=10)

		self.public_key = Entry(self.window, width=40)
		self.public_key.grid(column=1, row=4, sticky=W)

		self.btn_open_public_key = Button(self.window, text="Open Public Key", width=15, command=self.open_pub_key_clicked)
		self.btn_open_public_key.grid(column=2, row=4, sticky='E', padx=20)

		self.label_private_key = Label(self.window, text='Private Key')
		self.label_private_key.grid(column=0, row=5, sticky=W, padx=10)

		self.private_key = Entry(self.window, width=40)
		self.private_key.grid(column=1, row=5, sticky=W)

		self.btn_open_private_key = Button(self.window, text="Open Private Key", width=15, command=self.open_pri_key_clicked)
		self.btn_open_private_key.grid(column=2, row=5, sticky='E', padx=20)
		
		self.btn_save_keys = Button(self.window, text="Save Keys", width=15, command=self.save_keys_clicked)
		self.btn_save_keys.grid(column=0, row=6, sticky=E, pady=5, padx=10)

		self.label_space_break = Label(self.window, text="_"*92)
		self.label_space_break.grid(column=0, row=7, sticky=W, padx=10, pady=(20, 5), columnspan=3)

		self.label_signing = Label(self.window, text="Signing")
		self.label_signing.grid(column=0, row=8, sticky=W, padx=10, pady=(20, 5))

		self.file_to_sign = []
		self.btn_openfile_to_sign = Button(self.window, text="Open File to Sign", width=15, command=self.choose_file_to_sign)
		self.btn_openfile_to_sign.grid(column=0, row=9, sticky=E, pady=5, padx=10)

		self.label_file_to_sign_path = Label(self.window, text="")
		self.label_file_to_sign_path.grid(column=1, row=9, columnspan=3, sticky=W, padx=10)

		self.combobox_sign_options_signing = ttk.Combobox(self.window, values=["Sign in the file", "Sign in a separate file"], state="readonly")
		self.combobox_sign_options_signing.grid(column=1, row=10, pady=10, sticky=SW, columnspan=2)
		self.combobox_sign_options_signing.current(0)
		self.combobox_sign_options_signing.bind('<<ComboboxSelected>>', self.sign_options_signing_handler)

		self.btn_generate_signature = Button(self.window, text="Generate Signature", width=15, command=self.generate_signature)
		self.btn_generate_signature.grid(column=0, row=11, sticky='E', pady=5, padx=10)

		self.digi_sign = StringVar(())
		self.sign = Entry(self.window, width=60, state="readonly", textvariable=self.digi_sign)
		self.sign.grid(column=1, row=11, sticky=W, columnspan=2)

		self.btn_sign = Button(self.window, text="Sign", width=15, command=self.sign_btn_clicked)
		self.btn_sign.grid(column=2, row=12, sticky='E', padx=20)

		self.label_space_break = Label(self.window, text="_"*92)
		self.label_space_break.grid(column=0, row=13, sticky=W, padx=10, pady=(20, 5), columnspan=3)

		self.label_verifying = Label(self.window, text="Verifying")
		self.label_verifying.grid(column=0, row=14, sticky=W, padx=10, pady=(20, 5))

		self.file_to_verify = []
		self.btn_openfile_to_verify = Button(self.window, text="Open File", width=15, command=self.choose_file_to_verify)
		self.btn_openfile_to_verify.grid(column=0, row=15, sticky=E, pady=5, padx=10)

		self.label_file_to_verify_path = Label(self.window, text="")
		self.label_file_to_verify_path.grid(column=1, row=15, columnspan=3, sticky=W, padx=10)

		self.combobox_sign_options_verifying = ttk.Combobox(self.window, values=["Sign in the file", "Sign in a separate file"], state="readonly")
		self.combobox_sign_options_verifying.grid(column=1, row=16, pady=10, sticky=SW, columnspan=2)
		self.combobox_sign_options_verifying.current(0)
		self.combobox_sign_options_verifying.bind('<<ComboboxSelected>>', self.sign_options_verifying_handler)

		self.btn_load_signature = Button(self.window, text="Load Signature", width=15, command=self.load_signature)
		self.btn_load_signature.grid(column=0, row=17, sticky='E', pady=5, padx=10)

		self.digi_sign_to_verified =StringVar()
		self.sign_to_verify = Entry(self.window, width=60, state="readonly", textvariable=self.digi_sign_to_verified)
		self.sign_to_verify.grid(column=1, row=17, sticky=W, columnspan=2)

		self.btn_verify = Button(self.window, text="Verify", width=15, command=self.verify_btn_clicked)
		self.btn_verify.grid(column=2, row=18, sticky='E', padx=20)

	def generate_key_clicked(self):
		length = self.key_length[self.combobox_key_length.current()]
		self.rsa.generate_key_pairs(int(length))
		self.public_key.delete("1", END)
		self.public_key.insert("1", self.rsa.public_key)
		self.private_key.delete("1", END)
		self.private_key.insert("1", self.rsa.private_key)

	def open_pub_key_clicked(self):
		filename = filedialog.askopenfilename()
		if filename != '' and type(filename) == str:
			with open(filename, "r") as file:
				self.public_key.delete("1", END)
				self.public_key.insert("1", file.read())

	def open_pri_key_clicked(self):
		filename = filedialog.askopenfilename()
		if filename != '' and type(filename) == str:
			with open(filename, "r") as file:
				self.private_key.delete("1", END)
				self.private_key.insert("1", file.read())

	def save_keys_clicked(self):
		filename = filedialog.asksaveasfilename()
		if filename != '' and type(filename) == str:
			with open(filename+".pub", "wb") as file:
				content = self.public_key.get()
				file.write(bytes(content.encode()))
			with open(filename+".pri", "wb") as file:
				content = self.private_key.get()
				file.write(bytes(content.encode()))	
	
	def choose_file_to_sign(self) :
		filename = filedialog.askopenfilename(title="Open the file to sign")
		if filename != '' and type(filename) == str:
			with open(filename, "rb") as file:
				self.file_to_sign = file.read()
				self.label_file_to_sign_path.config(text=filename)
	
	def choose_file_to_verify(self) :
		filename = filedialog.askopenfilename(title="Open the file to be verified")
		if filename != '' and type(filename) == str:
			with open(filename, "rb") as file:
				self.file_to_verify = file.read()
				self.label_file_to_verify_path.config(text=filename)

	def sign_options_signing_handler(self, event):
		current = self.combobox_sign_options_signing.current()

	def sign_options_verifying_handler(self, event):
		current = self.combobox_sign_options_verifying.current()

	def handler(self, event):
		current = self.combobox_key_length.current()
	
	def generate_signature(self):
		if self.label_file_to_sign_path["text"] == "":
			messagebox.showerror("Error", "Open file to sign first")
			return

		if self.private_key.get() == "":
			messagebox.showerror("Error", "Private key is missing")
			return

		data_hash = sha1(self.file_to_sign).digest()

		ds = self.rsa.encrypt(data_hash)
		self.digi_sign.set("<ds>"+ds+"</ds>")

	def sign_btn_clicked(self) :
		if self.sign.get() == "":
			messagebox.showerror("Error", "Generate The Digital Signature first!")
			return

		if self.combobox_sign_options_signing.current() == 0:
			filename = filedialog.asksaveasfilename(title="Save the signed document")
			if filename != '' and type(filename) == str:
				content = self.digi_sign.get()
				with open(filename, "wb") as file:
					file.write(self.file_to_sign+bytes(content.encode()))

		elif self.combobox_sign_options_signing.current() == 1:
			filename = filedialog.asksaveasfilename(title="Save the digital signature document")
			if filename != '' and type(filename) == str:
				content = self.digi_sign.get()
				with open(filename, "wb") as file:
					file.write(bytes(content.encode()))

	def load_signature(self):
		if self.combobox_sign_options_verifying.current() == 0:
			if self.label_file_to_verify_path["text"] == "":
				messagebox.showerror("Error", "Open the file to be verified first!")
				return
			
			soup = BeautifulSoup(self.file_to_verify, "html.parser")
			if soup.ds == None:
				messagebox.showerror("Error", "Digital signature not found")
				return
			self.digi_sign_to_verified.set("<ds>"+soup.ds.text+"</ds>")

		elif self.combobox_sign_options_verifying.current() == 1:
			filename = filedialog.askopenfilename(title="Open digital signature file")
			if filename != '' and type(filename) == str:
				with open(filename, "rb") as file:
					file_ds = file.read().decode()
					soup = BeautifulSoup(file_ds, "html.parser")
					if soup.ds == None:
						messagebox.showerror("Error", "Digital signature not found")
						return
					self.digi_sign_to_verified.set("<ds>"+soup.ds.text+"</ds>")

	def verify_btn_clicked(self) :
		if self.sign_to_verify.get() == "":
			messagebox.showerror("Error", "Load The Digital Signature first!")
			return

		if self.public_key.get() == "":
			messagebox.showerror("Error", "Public key is missing")
			return

		# hash data
		data = []
		data_hash = []
		if self.combobox_sign_options_verifying.current() == 0:
			ds_idx = search('<ds>', self.file_to_verify.decode())
			data = self.file_to_verify.decode()[:ds_idx.start()]
			print(data)
			data_hash = sha1(data.encode()).digest()

		elif self.combobox_sign_options_verifying.current() == 1:
			data = self.file_to_verify
			data_hash = sha1(data).digest()

		# decrypt ds
		print(self.digi_sign_to_verified.get())
		ds = BeautifulSoup(self.digi_sign_to_verified.get(), "html.parser").ds.text
		ds_decrypted = self.rsa.decrypt(ds)

		print(list(data_hash))
		print(ds_decrypted)
		# compare
		if list(data_hash) == ds_decrypted:
			messagebox.showinfo("Verification is Successful", "Verified Document")
		else:
			messagebox.showerror("Verification Failed", "Unverified Document")
		

if __name__ == "__main__":
   gui = Gui()
   gui.window.mainloop()