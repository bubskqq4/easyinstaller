#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, PhotoImage
import subprocess
import os
from PIL import Image, ImageTk

class ThemeCustomizer:
    def __init__(self, root):
        self.root = root
        root.title("Advanced Linux Theme Customizer")
        root.geometry("800x600")
        
        # Detect desktop environment
        self.desktop_env = self.detect_desktop_environment()
        
        # Available theme packages
        self.themes = {
            "GTK Themes": {
                "Adwaita": "gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita'",
                "Adwaita-dark": "gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita-dark'",
                "Yaru": "gsettings set org.gnome.desktop.interface gtk-theme 'Yaru'",
                "Arc": "gsettings set org.gnome.desktop.interface gtk-theme 'Arc'",
                "Arc-Dark": "gsettings set org.gnome.desktop.interface gtk-theme 'Arc-Dark'"
            },
            "Icon Themes": {
                "Adwaita": "gsettings set org.gnome.desktop.interface icon-theme 'Adwaita'",
                "Yaru": "gsettings set org.gnome.desktop.interface icon-theme 'Yaru'",
                "Papirus": "gsettings set org.gnome.desktop.interface icon-theme 'Papirus'",
                "Numix": "gsettings set org.gnome.desktop.interface icon-theme 'Numix'"
            },
            "Cursor Themes": {
                "Adwaita": "gsettings set org.gnome.desktop.interface cursor-theme 'Adwaita'",
                "Bibata": "gsettings set org.gnome.desktop.interface cursor-theme 'Bibata-Original-Classic'",
                "DMZ-White": "gsettings set org.gnome.desktop.interface cursor-theme 'DMZ-White'",
                "DMZ-Black": "gsettings set org.gnome.desktop.interface cursor-theme 'DMZ-Black'"
            }
        }

        # Desktop environment specific commands
        self.desktop_commands = {
            "gnome": {
                "gtk": "gsettings set org.gnome.desktop.interface gtk-theme",
                "icon": "gsettings set org.gnome.desktop.interface icon-theme",
                "cursor": "gsettings set org.gnome.desktop.interface cursor-theme"
            },
            "kde": {
                "gtk": "kwriteconfig5 --file ~/.config/kdeglobals --group KDE --key widgetStyle",
                "icon": "kwriteconfig5 --file ~/.config/kdeglobals --group Icons --key Theme",
                "cursor": "kwriteconfig5 --file ~/.config/kcminputrc --group Mouse --key cursorTheme"
            },
            "xfce": {
                "gtk": "xfconf-query -c xsettings -p /Net/ThemeName -s",
                "icon": "xfconf-query -c xsettings -p /Net/IconThemeName -s",
                "cursor": "xfconf-query -c xsettings -p /Gtk/CursorThemeName -s"
            }
        }

        # Theme preview images (placeholder paths)
        self.preview_images = {
            "Adwaita": "previews/adwaita.png",
            "Adwaita-dark": "previews/adwaita-dark.png",
            "Yaru": "previews/yaru.png",
            "Arc": "previews/arc.png",
            "Arc-Dark": "previews/arc-dark.png"
        }

        self.create_ui()

    def detect_desktop_environment(self):
        de = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()
        if "gnome" in de:
            return "gnome"
        elif "kde" in de:
            return "kde"
        elif "xfce" in de:
            return "xfce"
        else:
            return "unknown"

    def create_ui(self):
        # Desktop environment label
        self.de_label = ttk.Label(self.root, text=f"Detected Desktop: {self.desktop_env.capitalize()}", font=('Arial', 12))
        self.de_label.pack(pady=5)

        # Notebook for different theme types
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.create_gtk_tab()
        self.create_icon_tab()
        self.create_cursor_tab()

        # Preview frame
        self.preview_frame = ttk.LabelFrame(self.root, text="Theme Preview")
        self.preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.preview_label = ttk.Label(self.preview_frame, text="Select a theme to see preview")
        self.preview_label.pack(pady=20)

        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def create_gtk_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="GTK Themes")

        self.gtk_list = tk.Listbox(tab, selectmode=tk.SINGLE, font=('Arial', 11))
        for theme in self.themes["GTK Themes"]:
            self.gtk_list.insert(tk.END, theme)
        self.gtk_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.gtk_list.bind('<<ListboxSelect>>', self.show_preview)

        apply_btn = ttk.Button(tab, text="Apply GTK Theme", command=lambda: self.apply_theme("GTK Themes"))
        apply_btn.pack(pady=5)

    def create_icon_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Icon Themes")

        self.icon_list = tk.Listbox(tab, selectmode=tk.SINGLE, font=('Arial', 11))
        for theme in self.themes["Icon Themes"]:
            self.icon_list.insert(tk.END, theme)
        self.icon_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.icon_list.bind('<<ListboxSelect>>', self.show_preview)

        apply_btn = ttk.Button(tab, text="Apply Icon Theme", command=lambda: self.apply_theme("Icon Themes"))
        apply_btn.pack(pady=5)

    def create_cursor_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Cursor Themes")

        self.cursor_list = tk.Listbox(tab, selectmode=tk.SINGLE, font=('Arial', 11))
        for theme in self.themes["Cursor Themes"]:
            self.cursor_list.insert(tk.END, theme)
        self.cursor_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.cursor_list.bind('<<ListboxSelect>>', self.show_preview)

        apply_btn = ttk.Button(tab, text="Apply Cursor Theme", command=lambda: self.apply_theme("Cursor Themes"))
        apply_btn.pack(pady=5)

    def show_preview(self, event):
        widget = event.widget
        if widget.curselection():
            index = widget.curselection()[0]
            theme = widget.get(index)
            
            # Try to load preview image
            try:
                img_path = self.preview_images.get(theme, "")
                if img_path and os.path.exists(img_path):
                    img = Image.open(img_path)
                    img.thumbnail((400, 300))
                    photo = ImageTk.PhotoImage(img)
                    
                    # Update preview
                    if hasattr(self, 'preview_image'):
                        self.preview_image.destroy()
                    self.preview_image = ttk.Label(self.preview_frame, image=photo)
                    self.preview_image.image = photo
                    self.preview_image.pack()
                    self.preview_label.pack_forget()
                else:
                    self.preview_label.config(text=f"Preview for {theme} not available")
                    self.preview_label.pack()
                    if hasattr(self, 'preview_image'):
                        self.preview_image.destroy()
            except Exception as e:
                self.preview_label.config(text=f"Error loading preview: {str(e)}")
                self.preview_label.pack()

    def apply_theme(self, theme_type):
        if theme_type == "GTK Themes":
            widget = self.gtk_list
            theme_key = "gtk"
        elif theme_type == "Icon Themes":
            widget = self.icon_list
            theme_key = "icon"
        elif theme_type == "Cursor Themes":
            widget = self.cursor_list
            theme_key = "cursor"
        else:
            return

        if not widget.curselection():
            messagebox.showwarning("No Selection", f"Please select a {theme_type[:-1]} first!")
            return

        theme = widget.get(widget.curselection()[0])
        
        try:
            if self.desktop_env in self.desktop_commands:
                cmd_template = self.desktop_commands[self.desktop_env][theme_key]
                if self.desktop_env == "gnome":
                    subprocess.run(f"{cmd_template} '{theme}'", shell=True, check=True)
                else:
                    subprocess.run(f"{cmd_template} {theme}", shell=True, check=True)
                
                # Additional command for KDE to apply changes
                if self.desktop_env == "kde":
                    subprocess.run("kbuildsycoca5", shell=True)
                
                self.status_bar.config(text=f"Successfully applied {theme} {theme_type[:-1]}")
                messagebox.showinfo("Success", f"{theme} {theme_type[:-1]} applied successfully!")
            else:
                messagebox.showerror("Error", f"Unsupported desktop environment: {self.desktop_env}")
        except subprocess.CalledProcessError as e:
            self.status_bar.config(text=f"Failed to apply theme: {str(e)}")
            messagebox.showerror("Error", f"Failed to apply theme: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ThemeCustomizer(root)
    root.mainloop()