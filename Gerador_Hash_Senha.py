import hashlib
import secrets
import base64
import tkinter as tk
from tkinter import ttk, messagebox

ITERACOES = 600000


# =====================================
# 1. GERAR HASH DA SENHA
# =====================================

def gerar_hash(senha):
    salt = secrets.token_bytes(16)
    hash_senha = hashlib.pbkdf2_hmac(
        'sha256',
        senha.encode('utf-8'),
        salt,
        ITERACOES
    )
    return (
        base64.b64encode(salt).decode(),
        base64.b64encode(hash_senha).decode()
    )


# =====================================
# 2. VERIFICAR SENHA
# =====================================

def verificar_senha(senha, salt_b64, hash_original):
    salt = base64.b64decode(salt_b64)
    novo_hash = hashlib.pbkdf2_hmac(
        'sha256',
        senha.encode('utf-8'),
        salt,
        ITERACOES
    )
    novo_hash = base64.b64encode(novo_hash).decode()
    return secrets.compare_digest(novo_hash, hash_original)


# =====================================
# 3. INTERFACE GRÁFICA
# =====================================

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Senhas e Hash")
        self.geometry("620x520")
        self.minsize(560, 480)

        self.salt = ""
        self.hash = ""

        self.var_senha = tk.StringVar()
        self.var_mostrar = tk.BooleanVar(value=False)
        self.var_salt = tk.StringVar()
        self.var_hash = tk.StringVar()
        self.var_tentativa = tk.StringVar()
        self.var_status = tk.StringVar()

        self._montar()

    def _montar(self):
        pad = {"padx": 12, "pady": 4}

        # --- Gerar hash ---
        frame1 = ttk.LabelFrame(self, text=" 1. Gerar hash ")
        frame1.pack(fill="x", padx=12, pady=(12, 6))

        ttk.Label(frame1, text="Digite sua senha:").pack(anchor="w", **pad)

        self.entry_senha = ttk.Entry(frame1, textvariable=self.var_senha, show="•")
        self.entry_senha.pack(fill="x", **pad)
        self.entry_senha.bind("<Return>", lambda e: self.gerar())

        ttk.Checkbutton(
            frame1, text="Mostrar senha",
            variable=self.var_mostrar, command=self._alternar_visibilidade
        ).pack(anchor="w", **pad)

        ttk.Button(frame1, text="Gerar hash", command=self.gerar).pack(
            anchor="e", padx=12, pady=(4, 10)
        )

        # --- Resultado ---
        frame2 = ttk.LabelFrame(self, text=" Resultado ")
        frame2.pack(fill="x", padx=12, pady=6)

        self._campo_resultado(frame2, "Salt (base64):", self.var_salt)
        self._campo_resultado(frame2, "Hash (base64):", self.var_hash)

        # --- Verificação ---
        frame3 = ttk.LabelFrame(self, text=" 2. Teste de autenticação ")
        frame3.pack(fill="x", padx=12, pady=6)

        ttk.Label(frame3, text="Digite novamente sua senha:").pack(anchor="w", **pad)

        entry_tent = ttk.Entry(frame3, textvariable=self.var_tentativa, show="•")
        entry_tent.pack(fill="x", **pad)
        entry_tent.bind("<Return>", lambda e: self.verificar())

        ttk.Button(frame3, text="Verificar", command=self.verificar).pack(
            anchor="e", padx=12, pady=4
        )

        self.lbl_status = tk.Label(
            frame3, textvariable=self.var_status,
            font=("Segoe UI", 12, "bold")
        )
        self.lbl_status.pack(pady=(2, 10))

    def _campo_resultado(self, parent, rotulo, variavel):
        ttk.Label(parent, text=rotulo).pack(anchor="w", padx=12, pady=(6, 0))
        linha = ttk.Frame(parent)
        linha.pack(fill="x", padx=12, pady=(0, 6))

        ttk.Entry(linha, textvariable=variavel, state="readonly").pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            linha, text="Copiar", width=8,
            command=lambda: self._copiar(variavel.get())
        ).pack(side="left", padx=(6, 0))

    def _alternar_visibilidade(self):
        self.entry_senha.config(show="" if self.var_mostrar.get() else "•")

    def _copiar(self, texto):
        if not texto:
            return
        self.clipboard_clear()
        self.clipboard_append(texto)

    def gerar(self):
        senha = self.var_senha.get()
        if not senha:
            messagebox.showwarning("Atenção", "Digite uma senha primeiro.")
            return

        self.var_status.set("")
        self.config(cursor="watch")
        self.update_idletasks()

        self.salt, self.hash = gerar_hash(senha)
        self.var_salt.set(self.salt)
        self.var_hash.set(self.hash)

        self.config(cursor="")

    def verificar(self):
        if not self.hash:
            messagebox.showwarning("Atenção", "Gere o hash antes de verificar.")
            return

        self.config(cursor="watch")
        self.update_idletasks()

        ok = verificar_senha(self.var_tentativa.get(), self.salt, self.hash)

        self.config(cursor="")
        if ok:
            self.var_status.set("ACESSO PERMITIDO!")
            self.lbl_status.config(fg="#1a7f37")
        else:
            self.var_status.set("ACESSO NEGADO!")
            self.lbl_status.config(fg="#cf222e")


if __name__ == "__main__":
    App().mainloop()