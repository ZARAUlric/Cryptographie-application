import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import os
from pathlib import Path

class ModernOpensslKeyGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Générateur de Clé OpenSSL")
        self.root.geometry("1200x900")
        self.root.resizable(True, True)
        self.root.configure(bg="#f8f9fa")

        # Variables
        self.algo_var = tk.StringVar()
        self.cipher_var = tk.StringVar()
        self.hash_var = tk.StringVar()
        self.keysize_var = tk.StringVar(value="2048")
        self.passphrase_var = tk.StringVar()
        self.outfile_var = tk.StringVar(value=str(Path.home() / "key.pem"))
        self.file_to_encrypt_var = tk.StringVar()
        self.file_to_decrypt_var = tk.StringVar()
        self.signature_file_var = tk.StringVar()
        self.file_to_verify_var = tk.StringVar()
        self.file_to_view_var = tk.StringVar()
        self.sign_var = tk.BooleanVar(value=False)
        self.dark_mode = tk.BooleanVar(value=False)
        self.show_password = tk.BooleanVar(value=False)

        # Charger les données
        self.load_algos_and_ciphers()
        self.load_hash_algorithms()

        # Configurer les styles
        self.setup_styles()

        # Créer l'interface
        self.create_widgets()

        # Centrer la fenêtre
        self.center_window()

    def center_window(self):
        """Centre la fenêtre sur l'écran"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def setup_styles(self):
        """Configure les styles visuels de l'application"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.colors = {
            'primary': '#4f46e5',
            'secondary': '#6b7280',
            'success': '#10b981',
            'danger': '#ef4444',
            'warning': '#f59e0b',
            'light': '#f8f9fa',
            'dark': '#1e293b',
            'text-light': '#f8fafc',
            'text-dark': '#1e293b'
        }

        self.style.configure('.', font=('Segoe UI', 10))
        self.style.configure('TFrame', background=self.colors['light'])
        self.style.configure('TLabel', background=self.colors['light'], foreground=self.colors['text-dark'])
        self.style.configure('TLabelframe', background=self.colors['light'], bordercolor=self.colors['secondary'], relief='solid', borderwidth=1)
        self.style.configure('TLabelframe.Label', background=self.colors['light'], foreground=self.colors['text-dark'])
        self.style.configure('TButton', padding=6, relief='flat', background=self.colors['light'])
        self.style.map('TButton',
                     background=[('active', self.colors['primary']), ('pressed', self.colors['primary'])],
                     foreground=[('active', self.colors['text-light']), ('pressed', self.colors['text-light'])])
        self.style.configure('Primary.TButton', background=self.colors['primary'], foreground=self.colors['text-light'], font=('Segoe UI', 10, 'bold'))
        self.style.map('Primary.TButton',
                     background=[('active', '#4338ca'), ('pressed', '#3730a3')])
        self.style.configure('Secondary.TButton', background=self.colors['secondary'], foreground=self.colors['text-light'])
        self.style.map('Secondary.TButton',
                     background=[('active', '#4b5563'), ('pressed', '#374151')])
        self.style.configure('TEntry', fieldbackground='white', foreground=self.colors['text-dark'], bordercolor=self.colors['secondary'], lightcolor=self.colors['secondary'], darkcolor=self.colors['secondary'])
        self.style.map('TEntry',
                     bordercolor=[('focus', self.colors['primary']), ('!focus', self.colors['secondary'])],
                     lightcolor=[('focus', self.colors['primary']), ('!focus', self.colors['secondary'])],
                     darkcolor=[('focus', self.colors['primary']), ('!focus', self.colors['secondary'])])
        self.style.configure('TCombobox', fieldbackground='white', foreground=self.colors['text-dark'])
        self.style.map('TCombobox',
                     fieldbackground=[('readonly', 'white')],
                     selectbackground=[('readonly', self.colors['primary'])],
                     selectforeground=[('readonly', self.colors['text-light'])])
        self.style.configure('Status.TLabel', background=self.colors['secondary'], foreground=self.colors['text-light'], font=('Segoe UI', 9), padding=5, relief='sunken')

    def toggle_dark_mode(self):
        """Bascule entre les modes clair et sombre"""
        self.dark_mode.set(not self.dark_mode.get())
        if self.dark_mode.get():
            self.colors['light'] = '#1e293b'
            self.colors['text-dark'] = '#f8fafc'
            self.root.configure(bg='#0f172a')
        else:
            self.colors['light'] = '#f8f9fa'
            self.colors['text-dark'] = '#1e293b'
            self.root.configure(bg='#f8f9fa')
        self.setup_styles()
        self.create_widgets()

    def toggle_password_visibility(self):
        """Bascule entre l'affichage et le masquage de la phrase secrète"""
        self.show_password.set(not self.show_password.get())
        if hasattr(self, 'passphrase_entry'):
            self.passphrase_entry.config(show="" if self.show_password.get() else "•")
        if hasattr(self, 'toggle_btn'):
            self.toggle_btn.config(text="Masquer" if self.show_password.get() else "Afficher")

    def load_algos_and_ciphers(self):
        """Charge les algorithmes et chiffrements disponibles depuis OpenSSL"""
        self.algos = ["RSA", "DSA", "DH", "EC", "X25519", "X448", "ED25519", "ED448"]
        self.ciphers = self.get_ciphers()
        if self.algos:
            self.algo_var.set("RSA")
        if self.ciphers:
            self.cipher_var.set("aes256")

    def load_hash_algorithms(self):
        """Charge les algorithmes de hashage disponibles"""
        try:
            output = subprocess.check_output(["openssl", "list", "-digestalgorithms"], text=True, stderr=subprocess.STDOUT)
            self.hashes = []
            for line in output.strip().splitlines():
                if line.strip() and not line.startswith("="):
                    parts = line.split()
                    if parts:
                        self.hashes.append(parts[0])

            if not self.hashes:
                self.hashes = ["sha256", "sha512", "sha3-256", "sha3-512", "blake2b512", "blake2s256"]

            self.hash_var.set("sha256")
        except:
            self.hashes = ["sha256", "sha512", "sha3-256", "sha3-512", "blake2b512", "blake2s256"]
            self.hash_var.set("sha256")

    def get_ciphers(self):
        """Récupère la liste des algorithmes de chiffrement disponibles"""
        try:
            output = subprocess.check_output(["openssl", "list", "-cipheralgorithms"], text=True, stderr=subprocess.STDOUT)
            ciphers = set()
            for line in output.strip().splitlines():
                cipher = line.split()[0]
                if cipher and cipher.lower() not in ("cipher", "algorithms"):
                    ciphers.add(cipher)
            return sorted(ciphers)
        except subprocess.CalledProcessError:
            try:
                output = subprocess.check_output(["openssl", "enc", "-list"], text=True, stderr=subprocess.STDOUT)
                ciphers = set()
                for line in output.strip().splitlines():
                    if line.startswith("-"):
                        cipher = line.strip("-")
                        if cipher:
                            ciphers.add(cipher)
                return sorted(ciphers)
            except:
                return ["aes128", "aes192", "aes256", "aria128", "aria192", "aria256", "des3"]
        except Exception as e:
            return ["aes128", "aes192", "aes256", "aria128", "aria192", "aria256", "des3"]

    def browse_outfile(self):
        """Ouvre une boîte de dialogue pour sélectionner le fichier de sortie de la clé"""
        current_path = self.outfile_var.get()
        initial_dir = os.path.dirname(current_path) if current_path and os.path.exists(os.path.dirname(current_path)) else str(Path.home())
        initial_file = os.path.basename(current_path) if current_path else "key.pem"

        filename = filedialog.asksaveasfilename(
            initialdir=initial_dir,
            initialfile=initial_file,
            title="Enregistrer la clé sous",
            defaultextension=".pem"
        )

        if filename:
            self.outfile_var.set(filename)

    def browse_file_to_encrypt(self):
        """Ouvre une boîte de dialogue pour sélectionner un fichier à chiffrer"""
        filename = filedialog.askopenfilename(title="Sélectionnez un fichier à chiffrer")
        if filename:
            self.file_to_encrypt_var.set(filename)
            self.update_file_viewer(filename)

    def browse_file_to_decrypt(self):
        """Ouvre une boîte de dialogue pour sélectionner un fichier à déchiffrer"""
        filename = filedialog.askopenfilename(title="Sélectionnez un fichier à déchiffrer")
        if filename:
            self.file_to_decrypt_var.set(filename)

    def browse_file(self, target_var, callback=None):
        """Ouvre une boîte de dialogue pour sélectionner un fichier"""
        filename = filedialog.askopenfilename(title="Sélectionnez un fichier")
        if filename:
            target_var.set(filename)
            if callback:
                callback(filename)

    def update_file_viewer(self, filename=None):
        """Met à jour la visualisation du fichier avec le contenu du fichier sélectionné"""
        if not filename:
            filename = self.file_to_view_var.get()

        if not filename or not os.path.exists(filename):
            return

        try:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()
        except UnicodeDecodeError:
            try:
                with open(filename, 'r', encoding='latin-1') as file:
                    content = file.read()
            except:
                content = "<Contenu binaire ou non lisible>"
        except:
            content = "<Impossible de lire le fichier>"

        self.file_viewer.configure(state='normal')
        self.file_viewer.delete(1.0, tk.END)
        self.file_viewer.insert(tk.END, content)
        self.file_viewer.configure(state='disabled')

    def update_decrypted_file_viewer(self, filename):
        """Met à jour la visualisation du fichier déchiffré"""
        if not filename or not os.path.exists(filename):
            return

        try:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()
        except UnicodeDecodeError:
            try:
                with open(filename, 'r', encoding='latin-1') as file:
                    content = file.read()
            except:
                content = "<Contenu binaire ou non lisible>"
        except:
            content = "<Impossible de lire le fichier>"

        self.decrypted_file_viewer.configure(state='normal')
        self.decrypted_file_viewer.delete(1.0, tk.END)
        self.decrypted_file_viewer.insert(tk.END, content)
        self.decrypted_file_viewer.configure(state='disabled')

    def log_message(self, message):
        """Ajoute un message aux logs"""
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.configure(state='disabled')
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def reset_form(self):
        """Réinitialise le formulaire avec les valeurs par défaut"""
        self.keysize_var.set("2048")
        self.passphrase_var.set("")
        self.outfile_var.set(str(Path.home() / "key.pem"))
        self.file_to_encrypt_var.set("")
        self.file_to_decrypt_var.set("")
        self.file_to_verify_var.set("")
        self.signature_file_var.set("")
        self.file_to_view_var.set("")
        self.sign_var.set(False)
        if self.algos:
            self.algo_var.set("RSA")
        if self.ciphers:
            self.cipher_var.set("aes256")
        if self.hashes:
            self.hash_var.set("sha256")
        self.show_password.set(False)
        if hasattr(self, 'passphrase_entry'):
            self.passphrase_entry.config(show="•")
        if hasattr(self, 'toggle_btn'):
            self.toggle_btn.config(text="Afficher")
        if hasattr(self, 'file_viewer'):
            self.file_viewer.configure(state='normal')
            self.file_viewer.delete(1.0, tk.END)
            self.file_viewer.configure(state='disabled')
        if hasattr(self, 'decrypted_file_viewer'):
            self.decrypted_file_viewer.configure(state='normal')
            self.decrypted_file_viewer.delete(1.0, tk.END)
            self.decrypted_file_viewer.configure(state='disabled')
        if hasattr(self, 'signature_result_viewer'):
            self.signature_result_viewer.configure(state='normal')
            self.signature_result_viewer.delete(1.0, tk.END)
            self.signature_result_viewer.configure(state='disabled')

    def generate_key(self):
        """Génère la clé avec OpenSSL selon les paramètres spécifiés"""
        algo = self.algo_var.get()
        cipher = self.cipher_var.get()
        keysize = self.keysize_var.get()
        passphrase = self.passphrase_var.get()
        outfile = self.outfile_var.get()
        if not all([algo, cipher, keysize, outfile]):
            messagebox.showerror("Erreur", "Tous les champs obligatoires doivent être remplis.")
            return
        self.status_var.set("Génération de la clé en cours...")
        self.log_message("=== Début de la génération de clé ===")
        self.log_message(f"Algorithme: {algo}, Taille: {keysize}, Chiffrement: {cipher}")
        self.root.update_idletasks()

        try:
            cmd = [
                "openssl", "genpkey",
                "-algorithm", algo,
                "-out", outfile,
                f"-{cipher}",
                "-pass", f"pass:{passphrase}" if passphrase else "pass:"
            ]

            if algo.upper() == "RSA":
                cmd.extend(["-pkeyopt", f"rsa_keygen_bits:{keysize}"])
            elif algo.upper() == "DSA":
                cmd.extend(["-pkeyopt", f"dsa_paramgen_bits:{keysize}"])
            elif algo.upper() == "EC":
                curve = "prime256v1"
                if keysize.isdigit():
                    if int(keysize) >= 384:
                        curve = "secp384r1"
                    if int(keysize) >= 521:
                        curve = "secp521r1"
                else:
                    curve = keysize
                cmd.extend(["-pkeyopt", f"ec_paramgen_curve:{curve}"])

            self.log_message("Commande: " + " ".join(cmd))
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)

            if result.stderr:
                self.log_message("Erreurs: " + result.stderr)

            pubfile = os.path.splitext(outfile)[0] + "_pub.pem"
            pub_cmd = [
                "openssl", "pkey",
                "-in", outfile,
                "-out", pubfile,
                "-pubout",
                "-passin", f"pass:{passphrase}" if passphrase else "pass:"
            ]

            self.log_message("Génération de la clé publique...")
            self.log_message("Commande: " + " ".join(pub_cmd))
            pub_result = subprocess.run(pub_cmd, check=True, capture_output=True, text=True)

            if pub_result.stderr:
                self.log_message("Erreurs clé publique: " + pub_result.stderr)

            self.status_var.set(f"Clé générée avec succès dans '{outfile}'")
            self.log_message(f"Clé privée enregistrée dans '{outfile}'")
            self.log_message(f"Clé publique générée dans '{pubfile}'")
            messagebox.showinfo("Succès", f"Clé générée avec succès :\nPrivée: {outfile}\nPublique: {pubfile}")

        except subprocess.CalledProcessError as e:
            self.status_var.set("Échec de la génération")
            self.log_message(f"Erreur lors de la génération: {e.stderr}")
            messagebox.showerror("Erreur", f"Échec de la génération de la clé:\n{e.stderr}")
        except Exception as e:
            self.status_var.set("Erreur inattendue")
            self.log_message(f"Erreur inattendue: {str(e)}")
            messagebox.showerror("Erreur", f"Une erreur inattendue s'est produite:\n{str(e)}")

    def encrypt_file(self):
        """Chiffre un fichier avec la clé publique"""
        algo = self.algo_var.get()
        passphrase = self.passphrase_var.get()
        outfile = self.outfile_var.get()
        file_to_encrypt = self.file_to_encrypt_var.get()
        hash_algo = self.hash_var.get()
        sign = self.sign_var.get()
        if not file_to_encrypt:
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier à chiffrer.")
            return

        if not os.path.exists(file_to_encrypt):
            messagebox.showerror("Erreur", "Le fichier spécifié n'existe pas.")
            return

        if not os.path.exists(outfile):
            messagebox.showerror("Erreur", "La clé privée spécifiée n'existe pas.")
            return

        self.status_var.set("Chiffrement en cours...")
        self.log_message("\n=== Début du chiffrement ===")
        self.root.update_idletasks()

        try:
            pubfile = os.path.splitext(outfile)[0] + "_pub.pem"
            if not os.path.exists(pubfile):
                messagebox.showerror("Erreur", "La clé publique n'existe pas.")
                return

            output_chiffre = os.path.splitext(file_to_encrypt)[0] + "_chiffre.bin"
            cmd = [
                "openssl", "pkeyutl", "-encrypt",
                "-pubin", "-inkey", pubfile,
                "-in", file_to_encrypt,
                "-out", output_chiffre
            ]

            self.log_message("Commande de chiffrement: " + " ".join(cmd))
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)

            if result.stderr:
                self.log_message("Erreurs: " + result.stderr)

            hash_source = os.path.splitext(file_to_encrypt)[0] + "_source.hash"
            hash_cmd = [
                "openssl", "dgst", f"-{hash_algo}",
                "-out", hash_source,
                file_to_encrypt
            ]

            self.log_message("Génération du hash du fichier source...")
            subprocess.run(hash_cmd, check=True)

            self.status_var.set(f"Fichier chiffré dans '{output_chiffre}'")
            self.log_message(f"Fichier chiffré: {output_chiffre}")
            self.log_message(f"Empreinte du fichier source générée dans '{hash_source}'")

            if sign:
                signature_file = os.path.splitext(file_to_encrypt)[0] + ".sig"
                sign_cmd = [
                    "openssl", "dgst", f"-{hash_algo}",
                    "-sign", outfile,
                    "-out", signature_file,
                    "-passin", f"pass:{passphrase}" if passphrase else "pass:",
                    file_to_encrypt
                ]

                self.log_message("Signature du fichier source...")
                self.log_message("Commande: " + " ".join(sign_cmd))
                sign_result = subprocess.run(sign_cmd, check=True, capture_output=True, text=True)

                if sign_result.stderr:
                    self.log_message("Erreurs signature: " + sign_result.stderr)

                verify_cmd = [
                    "openssl", "dgst", f"-{hash_algo}",
                    "-verify", pubfile,
                    "-signature", signature_file,
                    file_to_encrypt
                ]

                self.log_message("Vérification de la signature...")
                verify_result = subprocess.run(verify_cmd, check=True, capture_output=True, text=True)

                if verify_result.returncode == 0:
                    self.log_message("Signature vérifiée avec succès. Le fichier est authentique.")
                else:
                    self.log_message("La signature est invalide. Le fichier a peut-être été modifié.")

                self.log_message(f"Signature numérique enregistrée dans: {signature_file}")

            messagebox.showinfo("Succès", f"Fichier chiffré avec succès:\n{output_chiffre}")

        except subprocess.CalledProcessError as e:
            self.status_var.set("Échec du chiffrement")
            self.log_message(f"Erreur lors du chiffrement: {e.stderr}")
            messagebox.showerror("Erreur", f"Échec du chiffrement:\n{e.stderr}")
        except Exception as e:
            self.status_var.set("Erreur inattendue")
            self.log_message(f"Erreur inattendue: {str(e)}")
            messagebox.showerror("Erreur", f"Une erreur inattendue s'est produite:\n{str(e)}")

    def decrypt_file(self):
        """Déchiffre un fichier avec la clé privée"""
        algo = self.algo_var.get()
        passphrase = self.passphrase_var.get()
        outfile = self.outfile_var.get()
        file_to_decrypt = self.file_to_decrypt_var.get()
        hash_algo = self.hash_var.get()
        if not file_to_decrypt:
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier à déchiffrer.")
            return

        if not os.path.exists(file_to_decrypt):
            messagebox.showerror("Erreur", "Le fichier spécifié n'existe pas.")
            return

        if not os.path.exists(outfile):
            messagebox.showerror("Erreur", "La clé privée spécifiée n'existe pas.")
            return

        self.status_var.set("Déchiffrement en cours...")
        self.log_message("\n=== Début du déchiffrement ===")
        self.root.update_idletasks()

        try:
            output_dechiffre = os.path.splitext(file_to_decrypt)[0] + "_dechiffre.txt"
            cmd = [
                "openssl", "pkeyutl", "-decrypt",
                "-inkey", outfile,
                "-in", file_to_decrypt,
                "-out", output_dechiffre,
                "-passin", f"pass:{passphrase}" if passphrase else "pass:"
            ]

            self.log_message("Commande de déchiffrement: " + " ".join(cmd))
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)

            if result.stderr:
                self.log_message("Erreurs: " + result.stderr)

            hash_dechiffre = os.path.splitext(output_dechiffre)[0] + ".hash"
            hash_cmd = [
                "openssl", "dgst", f"-{hash_algo}",
                "-out", hash_dechiffre,
                output_dechiffre
            ]

            self.log_message("Génération du hash du fichier déchiffré...")
            subprocess.run(hash_cmd, check=True)

            self.status_var.set(f"Fichier déchiffré dans '{output_dechiffre}'")
            self.log_message(f"Fichier déchiffré: {output_dechiffre}")
            self.log_message(f"Empreinte du fichier déchiffré générée dans '{hash_dechiffre}'")

            self.update_decrypted_file_viewer(output_dechiffre)

            messagebox.showinfo("Succès", f"Fichier déchiffré avec succès:\n{output_dechiffre}")

        except subprocess.CalledProcessError as e:
            self.status_var.set("Échec du déchiffrement")
            self.log_message(f"Erreur lors du déchiffrement: {e.stderr}")
            messagebox.showerror("Erreur", f"Échec du déchiffrement:\n{e.stderr}")
        except Exception as e:
            self.status_var.set("Erreur inattendue")
            self.log_message(f"Erreur inattendue: {str(e)}")
            messagebox.showerror("Erreur", f"Une erreur inattendue s'est produite:\n{str(e)}")

    def verify_signature(self):
        """Vérifie la signature d'un fichier"""
        file_to_verify = self.file_to_verify_var.get()
        signature_file = self.signature_file_var.get()
        pubkey_file = self.pubkey_var.get()
        hash_algo = self.hash_var.get()
        if not all([file_to_verify, signature_file, pubkey_file]):
            messagebox.showerror("Erreur", "Tous les champs doivent être remplis.")
            return

        if not os.path.exists(file_to_verify):
            messagebox.showerror("Erreur", "Le fichier à vérifier n'existe pas.")
            return

        if not os.path.exists(signature_file):
            messagebox.showerror("Erreur", "Le fichier de signature n'existe pas.")
            return

        if not os.path.exists(pubkey_file):
            messagebox.showerror("Erreur", "La clé publique n'existe pas.")
            return

        self.status_var.set("Vérification de signature en cours...")
        self.log_message("\n=== Début de la vérification de signature ===")
        self.root.update_idletasks()

        try:
            cmd = [
                "openssl", "dgst", f"-{hash_algo}",
                "-verify", pubkey_file,
                "-signature", signature_file,
                file_to_verify
            ]

            self.log_message("Commande: " + " ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True)

            self.signature_result_viewer.configure(state='normal')
            self.signature_result_viewer.delete(1.0, tk.END)

            if result.returncode == 0:
                self.status_var.set("Signature vérifiée avec succès")
                self.log_message("Signature vérifiée avec succès. Le fichier est authentique.")
                self.signature_result_viewer.insert(tk.END, "Signature vérifiée avec succès.\nLe fichier est authentique et n'a pas été modifié.")
                messagebox.showinfo("Succès", "Signature vérifiée avec succès.\nLe fichier est authentique et n'a pas été modifié.")
            else:
                self.status_var.set("Échec de la vérification")
                self.log_message("La signature est invalide. Le fichier a peut-être été modifié ou la signature est corrompue.")
                self.signature_result_viewer.insert(tk.END, "La signature est invalide.\nLe fichier a peut-être été modifié ou la signature est corrompue.")
                messagebox.showerror("Erreur", "La signature est invalide.\nLe fichier a peut-être été modifié ou la signature est corrompue.")

            if result.stdout:
                self.signature_result_viewer.insert(tk.END, f"\n\nSortie OpenSSL:\n{result.stdout}")
                self.log_message("Sortie: " + result.stdout)
            if result.stderr:
                self.signature_result_viewer.insert(tk.END, f"\n\nErreurs OpenSSL:\n{result.stderr}")
                self.log_message("Erreurs: " + result.stderr)

            self.signature_result_viewer.configure(state='disabled')

        except Exception as e:
            self.status_var.set("Erreur inattendue")
            self.log_message(f"Erreur inattendue: {str(e)}")
            messagebox.showerror("Erreur", f"Une erreur inattendue s'est produite:\n{str(e)}")

    def create_widgets(self):
        """Crée tous les widgets de l'interface"""
        for widget in self.root.winfo_children():
            widget.destroy()

        main_frame = ttk.Frame(self.root, padding=(20, 15))
        main_frame.pack(fill=tk.BOTH, expand=True)

        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))

        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        title_label = ttk.Label(title_frame, text="Générateur de Clé OpenSSL", font=("Segoe UI", 18, "bold"))
        title_label.pack(anchor="w")

        desc_label = ttk.Label(title_frame,
                             text="Générez des clés cryptographiques sécurisées et effectuez des opérations de chiffrement",
                             font=("Segoe UI", 10))
        desc_label.pack(anchor="w", pady=(5, 0))

        mode_btn = ttk.Button(header_frame, text="☀️" if self.dark_mode.get() else "🌙",
                            command=self.toggle_dark_mode, width=3)
        mode_btn.pack(side=tk.RIGHT, padx=(10, 0))

        card_frame = ttk.Frame(main_frame)
        card_frame.pack(fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(card_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        config_tab = ttk.Frame(notebook)
        notebook.add(config_tab, text="Configuration Clé")

        algo_frame = ttk.LabelFrame(config_tab, text="Algorithmes", padding=15)
        algo_frame.pack(fill=tk.X, pady=10, padx=10)

        ttk.Label(algo_frame, text="Algorithme de clé :").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        algo_combo = ttk.Combobox(algo_frame, textvariable=self.algo_var, values=self.algos, width=30)
        algo_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(algo_frame, text="Taille de la clé :").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        keysize_entry = ttk.Entry(algo_frame, textvariable=self.keysize_var, width=30)
        keysize_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        tip_label = ttk.Label(algo_frame,
                            text="Tailles recommandées: RSA/DSA: 2048 ou 4096, EC: dépend de la courbe",
                            font=("Segoe UI", 8), foreground=self.colors['secondary'])
        tip_label.grid(row=2, column=0, columnspan=2, sticky="w", padx=5)

        security_frame = ttk.LabelFrame(config_tab, text="Sécurité", padding=15)
        security_frame.pack(fill=tk.X, pady=10, padx=10)

        ttk.Label(security_frame, text="Algorithme de chiffrement :").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        cipher_combo = ttk.Combobox(security_frame, textvariable=self.cipher_var, values=self.ciphers, width=30)
        cipher_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(security_frame, text="Fonction de hachage :").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        hash_combo = ttk.Combobox(security_frame, textvariable=self.hash_var, values=self.hashes, width=30)
        hash_combo.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(security_frame, text="Phrase secrète :").grid(row=2, column=0, sticky="w", padx=5, pady=5)

        passphrase_frame = ttk.Frame(security_frame)
        passphrase_frame.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.passphrase_entry = ttk.Entry(passphrase_frame, textvariable=self.passphrase_var, show="•", width=25)
        self.passphrase_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.toggle_btn = ttk.Button(passphrase_frame, text="Afficher", width=8,
                                   command=self.toggle_password_visibility)
        self.toggle_btn.pack(side=tk.RIGHT, padx=(5, 0))

        output_frame = ttk.LabelFrame(config_tab, text="Sortie", padding=15)
        output_frame.pack(fill=tk.X, pady=10, padx=10)

        ttk.Label(output_frame, text="Chemin du fichier :").grid(row=0, column=0, sticky="w", padx=5, pady=5)

        file_frame = ttk.Frame(output_frame)
        file_frame.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        outfile_entry = ttk.Entry(file_frame, textvariable=self.outfile_var)
        outfile_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_button = ttk.Button(file_frame, text="Parcourir",
                                command=self.browse_outfile, style='Secondary.TButton')
        browse_button.pack(side=tk.RIGHT, padx=(5, 0))

        button_frame = ttk.Frame(config_tab)
        button_frame.pack(fill=tk.X, pady=(20, 0), padx=10)

        reset_button = ttk.Button(button_frame, text="Réinitialiser",
                                command=self.reset_form, style='Secondary.TButton')
        reset_button.pack(side=tk.LEFT, padx=5)

        generate_button = ttk.Button(button_frame, text="Générer la clé",
                                   command=self.generate_key, style='Primary.TButton')
        generate_button.pack(side=tk.RIGHT, padx=5)

        operations_tab = ttk.Frame(notebook)
        notebook.add(operations_tab, text="Opérations")

        ops_notebook = ttk.Notebook(operations_tab)
        ops_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        encrypt_tab = ttk.Frame(ops_notebook)
        ops_notebook.add(encrypt_tab, text="Chiffrement")

        encrypt_frame = ttk.LabelFrame(encrypt_tab, text="Chiffrement de fichier", padding=15)
        encrypt_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)

        encrypt_controls_frame = ttk.Frame(encrypt_frame)
        encrypt_controls_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(encrypt_controls_frame, text="Fichier à chiffrer :").grid(row=0, column=0, sticky="w", padx=5, pady=5)

        file_encrypt_frame = ttk.Frame(encrypt_controls_frame)
        file_encrypt_frame.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        file_encrypt_entry = ttk.Entry(file_encrypt_frame, textvariable=self.file_to_encrypt_var)
        file_encrypt_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_encrypt_button = ttk.Button(file_encrypt_frame, text="Parcourir",
                                         command=self.browse_file_to_encrypt,
                                         style='Secondary.TButton')
        browse_encrypt_button.pack(side=tk.RIGHT, padx=(5, 0))

        ttk.Checkbutton(encrypt_controls_frame, text="Signer le fichier après chiffrement",
                      variable=self.sign_var).grid(row=1, column=0, columnspan=2, pady=5, sticky="w")

        encrypt_button = ttk.Button(encrypt_controls_frame, text="Chiffrer le fichier",
                                  command=self.encrypt_file, style='Primary.TButton')
        encrypt_button.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

        view_frame = ttk.LabelFrame(encrypt_frame, text="Visualisation du fichier", padding=15)
        view_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(view_frame, text="Fichier à visualiser :").grid(row=0, column=0, sticky="w", padx=5, pady=5)

        file_view_frame = ttk.Frame(view_frame)
        file_view_frame.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        file_view_entry = ttk.Entry(file_view_frame, textvariable=self.file_to_view_var)
        file_view_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_view_button = ttk.Button(file_view_frame, text="Parcourir",
                                      command=lambda: self.browse_file(self.file_to_view_var, self.update_file_viewer),
                                      style='Secondary.TButton')
        browse_view_button.pack(side=tk.RIGHT, padx=(5, 0))

        self.file_viewer = scrolledtext.ScrolledText(view_frame, height=10, wrap=tk.WORD)
        self.file_viewer.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(5, 0))
        self.file_viewer.configure(state='disabled')

        view_frame.grid_rowconfigure(1, weight=1)
        view_frame.grid_columnconfigure(1, weight=1)

        decrypt_tab = ttk.Frame(ops_notebook)
        ops_notebook.add(decrypt_tab, text="Déchiffrement")

        decrypt_frame = ttk.LabelFrame(decrypt_tab, text="Déchiffrement de fichier", padding=15)
        decrypt_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)

        decrypt_controls_frame = ttk.Frame(decrypt_frame)
        decrypt_controls_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(decrypt_controls_frame, text="Fichier à déchiffrer :").grid(row=0, column=0, sticky="w", padx=5, pady=5)

        file_decrypt_frame = ttk.Frame(decrypt_controls_frame)
        file_decrypt_frame.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        file_decrypt_entry = ttk.Entry(file_decrypt_frame, textvariable=self.file_to_decrypt_var)
        file_decrypt_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_decrypt_button = ttk.Button(file_decrypt_frame, text="Parcourir",
                                         command=lambda: self.browse_file(self.file_to_decrypt_var, self.update_file_viewer),
                                         style='Secondary.TButton')
        browse_decrypt_button.pack(side=tk.RIGHT, padx=(5, 0))

        decrypt_button = ttk.Button(decrypt_controls_frame, text="Déchiffrer le fichier",
                                  command=self.decrypt_file, style='Primary.TButton')
        decrypt_button.grid(row=1, column=0, columnspan=2, pady=10, sticky="ew")

        decrypt_view_frame = ttk.LabelFrame(decrypt_frame, text="Visualisation du fichier déchiffré", padding=15)
        decrypt_view_frame.pack(fill=tk.BOTH, expand=True)

        self.decrypted_file_viewer = scrolledtext.ScrolledText(decrypt_view_frame, height=10, wrap=tk.WORD)
        self.decrypted_file_viewer.pack(fill=tk.BOTH, expand=True)
        self.decrypted_file_viewer.configure(state='disabled')

        sign_tab = ttk.Frame(ops_notebook)
        ops_notebook.add(sign_tab, text="Signature")

        sign_frame = ttk.LabelFrame(sign_tab, text="Vérification de signature", padding=15)
        sign_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)

        sign_controls_frame = ttk.Frame(sign_frame)
        sign_controls_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(sign_controls_frame, text="Fichier :").grid(row=0, column=0, sticky="w", padx=5, pady=5)

        file_verify_frame = ttk.Frame(sign_controls_frame)
        file_verify_frame.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        file_verify_entry = ttk.Entry(file_verify_frame, textvariable=self.file_to_verify_var)
        file_verify_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_verify_button = ttk.Button(file_verify_frame, text="Parcourir",
                                        command=lambda: self.browse_file(self.file_to_verify_var, self.update_file_viewer),
                                        style='Secondary.TButton')
        browse_verify_button.pack(side=tk.RIGHT, padx=(5, 0))

        ttk.Label(sign_controls_frame, text="Fichier de signature :").grid(row=1, column=0, sticky="w", padx=5, pady=5)

        signature_file_frame = ttk.Frame(sign_controls_frame)
        signature_file_frame.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        signature_file_entry = ttk.Entry(signature_file_frame, textvariable=self.signature_file_var)
        signature_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_signature_button = ttk.Button(signature_file_frame, text="Parcourir",
                                           command=lambda: self.browse_file(self.signature_file_var),
                                           style='Secondary.TButton')
        browse_signature_button.pack(side=tk.RIGHT, padx=(5, 0))

        ttk.Label(sign_controls_frame, text="Clé publique :").grid(row=2, column=0, sticky="w", padx=5, pady=5)

        pubkey_frame = ttk.Frame(sign_controls_frame)
        pubkey_frame.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.pubkey_var = tk.StringVar()
        pubkey_entry = ttk.Entry(pubkey_frame, textvariable=self.pubkey_var)
        pubkey_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        browse_pubkey_button = ttk.Button(pubkey_frame, text="Parcourir",
                                        command=lambda: self.browse_file(self.pubkey_var),
                                        style='Secondary.TButton')
        browse_pubkey_button.pack(side=tk.RIGHT, padx=(5, 0))

        verify_button = ttk.Button(sign_controls_frame, text="Vérifier la signature",
                                 command=self.verify_signature,
                                 style='Primary.TButton')
        verify_button.grid(row=3, column=0, columnspan=2, pady=10, sticky="ew")

        sign_view_frame = ttk.LabelFrame(sign_frame, text="Résultat de la vérification", padding=15)
        sign_view_frame.pack(fill=tk.BOTH, expand=True)

        self.signature_result_viewer = scrolledtext.ScrolledText(sign_view_frame, height=5, wrap=tk.WORD)
        self.signature_result_viewer.pack(fill=tk.BOTH, expand=True)
        self.signature_result_viewer.configure(state='disabled')

        help_tab = ttk.Frame(notebook)
        notebook.add(help_tab, text="Aide")

        help_text = """
        Ce générateur vous permet de créer des clés cryptographiques sécurisées
        en utilisant OpenSSL et d'effectuer des opérations de chiffrement.
        1. Sélectionnez l'algorithme de clé (RSA, DSA, EC, etc.)
        2. Choisissez la taille de la clé (en bits)
        3. Sélectionnez un algorithme de chiffrement pour protéger la clé
        4. Entrez une phrase secrète forte
        5. Spécifiez le chemin du fichier de sortie
        6. Cliquez sur "Générer la clé"
        Opérations disponibles :
        - Chiffrement de fichiers avec la clé publique
        - Déchiffrement avec la clé privée
        - Signature numérique des fichiers
        - Vérification des signatures
        - Visualisation du contenu des fichiers
        Conseils de sécurité :
        - Utilisez toujours une phrase secrète forte
        - RSA 2048 bits est un bon choix pour la plupart des usages
        - Stockez vos clés dans un endroit sécurisé
        """

        help_label = ttk.Label(help_tab, text=help_text, justify=tk.LEFT, padding=20)
        help_label.pack(fill=tk.BOTH, expand=True)

        log_tab = ttk.Frame(notebook)
        notebook.add(log_tab, text="Logs")

        self.log_text = scrolledtext.ScrolledText(log_tab, height=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log_text.configure(state='disabled')

        self.status_var = tk.StringVar(value="Prêt")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, style='Status.TLabel')
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.iconbitmap("key_icon.ico")
    except:
        pass
    app = ModernOpensslKeyGenerator(root)
    root.mainloop()
