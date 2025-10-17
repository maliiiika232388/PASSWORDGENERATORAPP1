#PasswordGeneratorApp

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import secrets
import string
import math
from datetime import datetime


MIN_LEN = 4
MAX_LEN = 64
DEFAULT_LEN = 16


class PasswordGeneratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Генератор паролей 🔐")
        self.resizable(False, False)
        self.configure(padx=12, pady=12)

       
        self.length_var = tk.IntVar(value=DEFAULT_LEN)
        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.exclude_similar_var = tk.BooleanVar(value=True)
        self.count_var = tk.IntVar(value=5)

        self._build_ui()

    def _build_ui(self):
        
        settings = ttk.LabelFrame(self, text="Настройки")
        settings.grid(row=0, column=0, sticky="ew", padx=4, pady=4)

    
        length_frame = ttk.Frame(settings)
        length_frame.pack(fill="x", padx=6, pady=6)
        ttk.Label(length_frame, text="Длина:").pack(side="left")
        length_scale = ttk.Scale(length_frame, from_=MIN_LEN, to=MAX_LEN, orient="horizontal",
                                 variable=self.length_var, command=lambda e: self._on_length_change())
        length_scale.pack(side="left", fill="x", expand=True, padx=(6,6))
        self.length_label = ttk.Label(length_frame, text=str(self.length_var.get()))
        self.length_label.pack(side="left")

        
        chars_frame = ttk.Frame(settings)
        chars_frame.pack(fill="x", padx=6, pady=(0,6))
        ttk.Checkbutton(chars_frame, text="Заглавные (A-Z)", variable=self.upper_var).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(chars_frame, text="Строчные (a-z)", variable=self.lower_var).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(chars_frame, text="Цифры (0-9)", variable=self.digits_var).grid(row=0, column=1, sticky="w", padx=12)
        ttk.Checkbutton(chars_frame, text="Символы (!@#...)", variable=self.symbols_var).grid(row=1, column=1, sticky="w", padx=12)

        
        opts_frame = ttk.Frame(settings)
        opts_frame.pack(fill="x", padx=6, pady=(0,6))
        ttk.Checkbutton(opts_frame, text="Исключать похожие (i I l 1 O 0)", variable=self.exclude_similar_var).pack(side="left")
        ttk.Label(opts_frame, text="  Количество:").pack(side="left", padx=(8,6))
        ttk.Spinbox(opts_frame, from_=1, to=50, width=4, textvariable=self.count_var).pack(side="left")

        
        actions = ttk.Frame(self)
        actions.grid(row=1, column=0, sticky="ew", padx=4, pady=6)

        gen_btn = ttk.Button(actions, text="Сгенерировать", command=self.generate_passwords)
        gen_btn.pack(side="left")

        copy_btn = ttk.Button(actions, text="Копировать выбранный", command=self.copy_selected)
        copy_btn.pack(side="left", padx=(6,0))

        save_btn = ttk.Button(actions, text="Сохранить в файл...", command=self.save_to_file)
        save_btn.pack(side="left", padx=(6,0))

       
        results_frame = ttk.LabelFrame(self, text="Результаты")
        results_frame.grid(row=2, column=0, sticky="nsew", padx=4, pady=4)

        self.results_listbox = tk.Listbox(results_frame, width=58, height=10, activestyle="none")
        self.results_listbox.pack(side="left", fill="both", expand=True, padx=(6,0), pady=6)
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_listbox.yview)
        scrollbar.pack(side="left", fill="y", padx=(0,6), pady=6)
        self.results_listbox.config(yscrollcommand=scrollbar.set)
        self.results_listbox.bind("<<ListboxSelect>>", lambda e: self._update_strength_display())

       
        bottom = ttk.Frame(self)
        bottom.grid(row=3, column=0, sticky="ew", padx=4, pady=(2,0))

        ttk.Label(bottom, text="Сила:").pack(side="left")
        self.strength_var = tk.StringVar(value="—")
        self.strength_label = ttk.Label(bottom, textvariable=self.strength_var, font=("Segoe UI", 10, "bold"))
        self.strength_label.pack(side="left", padx=(6,12))

        ttk.Label(bottom, text="Энтропия:").pack(side="left")
        self.entropy_var = tk.StringVar(value="—")
        ttk.Label(bottom, textvariable=self.entropy_var).pack(side="left", padx=(6,0))

       
        hint = ttk.Label(self, text="Выбери настройки, нажми «Сгенерировать». Двойной клик по паролю копирует.", foreground="#444")
        hint.grid(row=4, column=0, sticky="w", padx=4, pady=(6,0))

        
        self.results_listbox.bind("<Double-Button-1>", lambda e: self.copy_selected())

        
        self.generate_passwords()

    def _on_length_change(self):
        self.length_label.config(text=str(self.length_var.get()))

    def _build_charset(self):
        parts = []
        if self.upper_var.get():
            parts.append(string.ascii_uppercase)
        if self.lower_var.get():
            parts.append(string.ascii_lowercase)
        if self.digits_var.get():
            parts.append(string.digits)
        if self.symbols_var.get():
            
            parts.append("!@#$%^&*()-_=+[]{};:,.<>?/|~")
        charset = "".join(parts)
        if self.exclude_similar_var.get():
            for ch in "ilIoO0":
                charset = charset.replace(ch, "")
        
        seen = set()
        final = []
        for c in charset:
            if c not in seen:
                seen.add(c)
                final.append(c)
        return "".join(final)

    def _estimate_entropy(self, length, pool_size):
        """Оценка энтропии в битах: length * log2(pool_size)"""
        if pool_size <= 0 or length <= 0:
            return 0.0
        return length * math.log2(pool_size)

    def _strength_from_entropy(self, bits):
        """Классификация силы по энтропии (приблизительно)."""
        if bits < 28:
            return "Очень слабый"
        elif bits < 40:
            return "Слабый"
        elif bits < 60:
            return "Средний"
        elif bits < 80:
            return "Сильный"
        else:
            return "Очень сильный"

    def _color_for_strength(self, bits):
        """Возвращает эстетичный цвет для метки силы (hex) — необязательно строго доступный."""
        if bits < 28:
            return "#b00020"  
        elif bits < 40:
            return "#e06c00"  
        elif bits < 60:
            return "#c6a700"  
        elif bits < 80:
            return "#2e8b57"  
        else:
            return "#006400"  

    def generate_passwords(self):
        charset = self._build_charset()
        if not charset:
            messagebox.showwarning("Набор пуст", "Выберите хотя бы один тип символов (заглавные/строчные/цифры/символы).")
            return

        length = int(self.length_var.get())
        count = int(self.count_var.get())
        self.results_listbox.delete(0, tk.END)

        for _ in range(count):
            pwd = "".join(secrets.choice(charset) for _ in range(length))
            self.results_listbox.insert(tk.END, pwd)

       
        if count > 0:
            self.results_listbox.select_set(0)
            self.results_listbox.event_generate("<<ListboxSelect>>")
            self._update_strength_display()

    def _update_strength_display(self):
        sel = self.results_listbox.curselection()
        if not sel:
            self.strength_var.set("—")
            self.entropy_var.set("—")
            self.strength_label.config(foreground="black")
            return
        pwd = self.results_listbox.get(sel[0])
        pool = len(set(self._inferred_pool_from_pwd(pwd)))
        
        pool_from_options = len(self._build_charset())
        
        pool_size = pool_from_options or pool
        bits = self._estimate_entropy(len(pwd), pool_size)
        bits_rounded = round(bits, 1)
        self.entropy_var.set(f"{bits_rounded} бит")
        strength = self._strength_from_entropy(bits)
        self.strength_var.set(strength)
        color = self._color_for_strength(bits)
        self.strength_label.config(foreground=color)

    def _inferred_pool_from_pwd(self, pwd):
        """Помогает оценить какие символы использовались — не обязательно точная мера."""
        pool = set()
        if any(c.islower() for c in pwd):
            pool.update(string.ascii_lowercase)
        if any(c.isupper() for c in pwd):
            pool.update(string.ascii_uppercase)
        if any(c.isdigit() for c in pwd):
            pool.update(string.digits)
        
        syms = set("!@#$%^&*()-_=+[]{};:,.<>?/|~")
        if any(c in syms for c in pwd):
            pool.update(syms)
        return pool

    def copy_selected(self):
        sel = self.results_listbox.curselection()
        if not sel:
            messagebox.showinfo("Не выбрано", "Выберите пароль в списке, который хотите скопировать.")
            return
        pwd = self.results_listbox.get(sel[0])
        
        try:
            self.clipboard_clear()
            self.clipboard_append(pwd)
           
            self.after(1, lambda: self._flash_message("Скопировано в буфер обмена"))
        except Exception as e:
            messagebox.showerror("Ошибка копирования", f"Не удалось скопировать: {e}")

    def _flash_message(self, msg, ms=900):
        
        old = self.title()
        self.title(msg)
        self.after(ms, lambda: self.title(old))

    def save_to_file(self):
        items = self.results_listbox.get(0, tk.END)
        if not items:
            messagebox.showinfo("Нет паролей", "Нет паролей для сохранения. Сначала сгенерируйте.")
            return
        default_name = datetime.now().strftime("passwords_%Y%m%d_%H%M%S.txt")
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default_name,
                                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("# Generated by PasswordGenerator\n")
                f.write(f"# {datetime.now().isoformat()}\n\n")
                for p in items:
                    f.write(p + "\n")
            messagebox.showinfo("Сохранено", f"Пароли сохранены в:\n{path}")
        except Exception as e:
            messagebox.showerror("Ошибка сохранения", f"Не удалось сохранить файл: {e}")

if __name__ == "__main__":
    app = PasswordGeneratorApp()
    app.mainloop()

