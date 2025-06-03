import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess
import stat
import logging
import urllib.request
import urllib.error
import sys
import tarfile
import shutil

class KaliAppInstaller:
    def __init__(self, root):
        # Set up logging
        logging.basicConfig(
            filename='installer_log.txt',
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.info("Application started")
        
        # Check for tkinter
        try:
            import tkinter.font
        except ImportError:
            logging.error("tkinter not installed")
            print("Error: tkinter not installed. Run 'sudo apt install python3-tk' and try again.")
            sys.exit(1)
        
        self.root = root
        self.root.title("Kali App Installer")
        self.root.geometry("450x450")
        self.root.configure(bg='#1C2526')  # Kali dark background
        
        # Font and style
        self.font = ("DejaVu Sans Mono", 10) if "DejaVu Sans Mono" in tk.font.families() else ("Courier", 10)
        self.bg_color = '#1C2526'
        self.fg_color = '#FFFFFF'
        self.button_bg = '#0055A4'  # Kali blue
        self.button_fg = '#FFFFFF'
        self.entry_bg = '#2E3B3E'
        
        # Variables
        self.selected_file = tk.StringVar()
        self.url = tk.StringVar()
        self.product_key = tk.StringVar()
        self.app_name = tk.StringVar()
        
        # Create installed apps tracking file
        self.installed_apps_file = "installed_apps.txt"
        self.create_system_group()
        
        # GUI Elements
        self.url_label = tk.Label(root, text="Enter Package URL (or leave blank to select file):",
                                 bg=self.bg_color, fg=self.fg_color, font=self.font)
        self.url_label.pack(pady=10)
        
        self.url_entry = tk.Entry(root, textvariable=self.url, width=40, bg=self.entry_bg, fg=self.fg_color,
                                 insertbackground=self.fg_color, font=self.font)
        self.url_entry.pack(pady=5)
        
        self.label = tk.Label(root, text="Or Select a .deb, .snap, .AppImage, .flatpak, .rpm, .tar.gz, .tar.xz, .tgz, .run, or .sh File:",
                             bg=self.bg_color, fg=self.fg_color, font=self.font, wraplength=400)
        self.label.pack(pady=10)
        
        self.file_entry = tk.Entry(root, textvariable=self.selected_file, width=40, bg=self.entry_bg, fg=self.fg_color,
                                  insertbackground=self.fg_color, font=self.font)
        self.file_entry.pack(pady=5)
        
        self.select_button = tk.Button(root, text="Select File", command=self.select_file,
                                     bg=self.button_bg, fg=self.button_fg, font=self.font,
                                     activebackground='#003366', activeforeground=self.fg_color,
                                     relief='flat', padx=10, pady=5)
        self.select_button.pack(pady=10)
        
        self.key_label = tk.Label(root, text="Product Key:", bg=self.bg_color, fg=self.fg_color, font=self.font)
        self.key_label.pack(pady=10)
        
        self.key_entry = tk.Entry(root, textvariable=self.product_key, width=40, bg=self.entry_bg, fg=self.fg_color,
                                 insertbackground=self.fg_color, font=self.font)
        self.key_entry.pack(pady=5)
        
        self.app_name_label = tk.Label(root, text="Application Command (e.g., vlc):",
                                      bg=self.bg_color, fg=self.fg_color, font=self.font)
        self.app_name_label.pack(pady=10)
        
        self.app_name_entry = tk.Entry(root, textvariable=self.app_name, width=40, bg=self.entry_bg, fg=self.fg_color,
                                      insertbackground=self.fg_color, font=self.font)
        self.app_name_entry.pack(pady=5)
        
        self.install_button = tk.Button(root, text="Install & Launch", command=self.install_and_launch,
                                      bg=self.button_bg, fg=self.button_fg, font=self.font,
                                      activebackground='#003366', activeforeground=self.fg_color,
                                      relief='flat', padx=10, pady=5)
        self.install_button.pack(pady=20)
        
        # Check for package managers and tools
        self.package_managers = self.check_package_managers()
        if not any(self.package_managers.values()):
            messagebox.showerror("Error", "No required tools (apt, dpkg, snap, flatpak, wget, alien, tar, bash) found. Install with 'sudo apt install apt dpkg snapd flatpak wget alien tar bash'.")
            logging.error("No required tools found")
            sys.exit(1)
        logging.info(f"Available tools: {self.package_managers}")
    
    def create_system_group(self):
        try:
            result = subprocess.run(['getent', 'group', 'Installed Apps'], capture_output=True, text=True)
            if result.returncode != 0:
                subprocess.run(['sudo', 'groupadd', 'Installed Apps'], check=True)
                logging.info("Created system group 'Installed Apps'")
            if not os.path.exists(self.installed_apps_file):
                with open(self.installed_apps_file, 'w') as f:
                    f.write("")
                logging.info("Created installed_apps.txt")
        except Exception as e:
            logging.exception("Failed to create system group or tracking file")
            messagebox.showwarning("Warning", f"Failed to initialize system group: {e}. Continuing without group tracking.")
    
    def check_package_managers(self):
        managers = {}
        for cmd in ['apt', 'dpkg', 'snap', 'flatpak', 'wget', 'alien', 'tar', 'bash']:
            try:
                subprocess.run(['which', cmd], capture_output=True, text=True, check=True)
                managers[cmd] = True
            except subprocess.CalledProcessError:
                managers[cmd] = False
        return managers
    
    def select_file(self):
        try:
            file_path = filedialog.askopenfilename(filetypes=[
                ("Linux packages", "*.deb *.snap *.AppImage *.flatpak *.rpm *.tar.gz *.tar.xz *.tgz *.run *.sh")
            ])
            if file_path:
                if not any(file_path.lower().endswith(ext) for ext in ['.deb', '.snap', '.AppImage', '.flatpak', '.rpm', '.tar.gz', '.tar.xz', '.tgz', '.run', '.sh']):
                    messagebox.showerror("Error", "Only .deb, .snap, .AppImage, .flatpak, .rpm, .tar.gz, .tar.xz, .tgz, .run, or .sh files are supported.")
                    logging.error(f"Invalid file type selected: {file_path}")
                    self.selected_file.set("")
                    return
                self.selected_file.set(file_path)
                logging.info(f"File selected: {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to select file: {e}")
            logging.exception("Error in select_file")
    
    def download_file(self, url):
        if not self.package_managers['wget']:
            messagebox.showerror("Error", "wget is not installed. Install with 'sudo apt install wget'.")
            logging.error("wget not installed")
            return None
        try:
            file_name = os.path.basename(url)
            if not any(file_name.lower().endswith(ext) for ext in ['.deb', '.snap', '.AppImage', '.flatpak', '.rpm', '.tar.gz', '.tar.xz', '.tgz', '.run', '.sh']):
                messagebox.showerror("Error", "URL must point to a .deb, .snap, .AppImage, .flatpak, .rpm, .tar.gz, .tar.xz, .tgz, .run, or .sh file.")
                logging.error(f"Invalid file type in URL: {file_name}")
                return None
            download_path = os.path.join(os.getcwd(), file_name)
            subprocess.run(['wget', '-O', download_path, url], check=True, capture_output=True, text=True)
            logging.info(f"Downloaded file from {url} to {download_path}")
            return download_path
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to download file: {e.stderr}")
            logging.exception(f"Failed to download from {url}")
            return None
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {e}")
            logging.exception(f"Failed to download from {url}")
            return None
    
    def install_and_launch(self):
        try:
            # Validate product key
            entered_key = self.product_key.get().strip()
            if entered_key != "free":
                messagebox.showerror("Error", "Invalid product key. Please enter 'free'.")
                logging.error(f"Invalid product key: {entered_key}")
                return
            
            source = self.selected_file.get()
            url = self.url.get().strip()
            app_command = self.app_name.get().strip()
            
            # Download file if URL is provided
            if url and not source:
                source = self.download_file(url)
                if not source:
                    return
                self.selected_file.set(source)
            
            if not source:
                messagebox.showerror("Error", "Please select a file or provide a valid URL.")
                logging.error("No file or URL provided")
                return
            
            if not os.path.exists(source):
                messagebox.showerror("Error", "Selected file does not exist.")
                logging.error(f"Selected file does not exist: {source}")
                return
            
            file_ext = os.path.splitext(source)[1].lower()
            if file_ext in ['.tar.gz', '.tgz']:
                file_ext = '.tar.gz'  # Normalize .tgz to .tar.gz
            elif file_ext == '.AppImage':
                file_ext = '.AppImage'  # Ensure consistent case
            
            if file_ext == '.AppImage':
                if not app_command:
                    app_command = source
                try:
                    os.chmod(source, os.stat(source).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    logging.info(f"Made AppImage executable: {source}")
                    subprocess.Popen([app_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    messagebox.showinfo("Success", f"Launching AppImage: {app_command}")
                    logging.info(f"Launched AppImage: {app_command}")
                    self.track_installed_app(app_command)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to launch AppImage: {e}")
                    logging.exception(f"Failed to launch AppImage: {app_command}")
            
            elif file_ext == '.run' or file_ext == '.sh':
                if not app_command:
                    messagebox.showerror("Error", "Please enter the application command to launch.")
                    logging.error("No application command provided")
                    return
                try:
                    os.chmod(source, os.stat(source).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    logging.info(f"Made {file_ext} executable: {source}")
                    install_cmd = ['bash', source] if file_ext == '.sh' else [source]
                    process = subprocess.run(install_cmd, capture_output=True, text=True, timeout=300)
                    if process.returncode != 0:
                        raise subprocess.CalledProcessError(process.returncode, install_cmd, process.stderr)
                    logging.info(f"Executed {file_ext} installer: {source}")
                    messagebox.showinfo("Success", f"Installed {file_ext} package: {os.path.basename(source)}")
                    try:
                        subprocess.Popen([app_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        messagebox.showinfo("Success", f"Launching application: {app_command}")
                        logging.info(f"Launched application: {app_command}")
                        self.track_installed_app(app_command)
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to launch application: {e}")
                        logging.exception(f"Failed to launch application: {app_command}")
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("Error", f"Installation failed: {e.stderr}")
                    logging.exception(f"Failed to execute {file_ext}: {source}")
                    return
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to execute {file_ext}: {e}")
                    logging.exception(f"Failed to execute {file_ext}: {source}")
                    return
            
            elif file_ext in ['.tar.gz', '.tar.xz']:
                if not app_command:
                    messagebox.showerror("Error", "Please enter the application command to launch.")
                    logging.error("No application command provided")
                    return
                try:
                    extract_dir = os.path.join(os.getcwd(), "extracted_temp")
                    os.makedirs(extract_dir, exist_ok=True)
                    with tarfile.open(source, 'r:*') as tar:
                        tar.extractall(extract_dir)
                    logging.info(f"Extracted {file_ext} to {extract_dir}")
                    
                    # Look for install.sh or configure script
                    install_script = None
                    for root, _, files in os.walk(extract_dir):
                        if 'install.sh' in files:
                            install_script = os.path.join(root, 'install.sh')
                            break
                        elif 'configure' in files:
                            install_script = os.path.join(root, 'configure')
                            break
                    
                    if install_script:
                        os.chmod(install_script, os.stat(install_script).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                        if install_script.endswith('install.sh'):
                            install_cmd = ['bash', install_script]
                        else:
                            install_cmd = [install_script]
                            # Run configure, make, make install
                            process = subprocess.run(install_cmd, cwd=os.path.dirname(install_script), capture_output=True, text=True, timeout=300)
                            if process.returncode != 0:
                                raise subprocess.CalledProcessError(process.returncode, install_cmd, process.stderr)
                            process = subprocess.run(['make'], cwd=os.path.dirname(install_script), capture_output=True, text=True, timeout=300)
                            if process.returncode != 0:
                                raise subprocess.CalledProcessError(process.returncode, ['make'], process.stderr)
                            process = subprocess.run(['sudo', 'make', 'install'], cwd=os.path.dirname(install_script), capture_output=True, text=True, timeout=300)
                            if process.returncode != 0:
                                raise subprocess.CalledProcessError(process.returncode, ['sudo', 'make', 'install'], process.stderr)
                        logging.info(f"Installed {file_ext} package: {source}")
                        messagebox.showinfo("Success", f"Installed {file_ext} package: {os.path.basename(source)}")
                    else:
                        messagebox.showerror("Error", "No install.sh or configure script found in tar archive.")
                        logging.error(f"No install script found in {source}")
                        shutil.rmtree(extract_dir, ignore_errors=True)
                        return
                    
                    try:
                        subprocess.Popen([app_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        messagebox.showinfo("Success", f"Launching application: {app_command}")
                        logging.info(f"Launched application: {app_command}")
                        self.track_installed_app(app_command)
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to launch application: {e}")
                        logging.exception(f"Failed to launch application: {app_command}")
                    finally:
                        shutil.rmtree(extract_dir, ignore_errors=True)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to install {file_ext} package: {e}")
                    logging.exception(f"Failed to install {file_ext}: {source}")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    return
            
            else:
                if not app_command:
                    messagebox.showerror("Error", "Please enter the application command to launch.")
                    logging.error("No application command provided")
                    return
                
                if file_ext == '.deb' and not (self.package_managers['apt'] or self.package_managers['dpkg']):
                    messagebox.showerror("Error", "Neither apt nor dpkg is available. Install with 'sudo apt install apt dpkg'.")
                    logging.error("No deb package manager available")
                    return
                if file_ext == '.snap' and not self.package_managers['snap']:
                    messagebox.showerror("Error", "snap is not available. Install with 'sudo apt install snapd'.")
                    logging.error("No snap package manager available")
                    return
                if file_ext == '.flatpak' and not self.package_managers['flatpak']:
                    messagebox.showerror("Error", "flatpak is not available. Install with 'sudo apt install flatpak'.")
                    logging.error("No flatpak package manager available")
                    return
                if file_ext == '.rpm' and not self.package_managers['alien']:
                    messagebox.showerror("Error", "alien is not available for .rpm conversion. Install with 'sudo apt install alien'.")
                    logging.error("No alien package manager available")
                    return
                
                if file_ext == '.deb':
                    try:
                        if self.package_managers['apt']:
                            install_cmd = ["sudo", "apt", "install", "-y", source]
                            process = subprocess.run(install_cmd, capture_output=True, text=True, timeout=300)
                            if process.returncode != 0:
                                raise subprocess.CalledProcessError(process.returncode, install_cmd, process.stderr)
                        else:
                            install_cmd = ["sudo", "dpkg", "-i", source]
                            process = subprocess.run(install_cmd, capture_output= True, text=True, check=True, timeout=300)
                        logging.info(f"Installed .deb package: {source}")
                    except subprocess.CalledProcessError as e:
                        messagebox.showerror("Error", f"Installation failed: {e.stderr}")
                        logging.exception(f"Failed to install .deb package: {source}")
                        return
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to install .deb package: {e}")
                        logging.exception(f"Failed to install .deb package: {source}")
                        return
                
                elif file_ext == '.snap':
                    try:
                        install_cmd = ["sudo", "snap", "install", source]
                        process = subprocess.run(install_cmd, capture_output=True, text=True, check=True, timeout=300)
                        logging.info(f"Installed .snap package: {source}")
                    except subprocess.CalledProcessError as e:
                        messagebox.showerror("Error", f"Installation failed: {e.stderr}")
                        logging.exception(f"Failed to install .snap package: {source}")
                        return
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to install .snap package: {e}")
                        logging.exception(f"Failed to install .snap package: {source}")
                        return
                
                elif file_ext == '.flatpak':
                    try:
                        install_cmd = ["flatpak", "install", "-y", source]
                        process = subprocess.run(install_cmd, capture_output=True, text=True, check=True, timeout=300)
                        logging.info(f"Installed .flatpak package: {source}")
                    except subprocess.CalledProcessError as e:
                        messagebox.showerror("Error", f"Installation failed: {e.stderr}")
                        logging.exception(f"Failed to install .flatpak package: {source}")
                        return
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to install .flatpak package: {e}")
                        logging.exception(f"Failed to install .flatpak package: {source}")
                        return
                
                elif file_ext == '.rpm':
                    try:
                        if self.package_managers['alien']:
                            # Convert .rpm to .deb using alien
                            converted_deb = os.path.splitext(source)[0] + ".deb"
                            subprocess.run(["sudo", "alien", "-k", "-d", source], check=True, capture_output=True, text=True, timeout=300)
                            install_cmd = ["sudo", "apt", "install", "-y", converted_deb] if self.package_managers['apt'] else ["sudo", "dpkg", "-i", converted_deb]
                            process = subprocess.run(install_cmd, capture_output=True, text=True, timeout=300)
                            if process.returncode != 0:
                                raise subprocess.CalledProcessError(process.returncode, install_cmd, process.stderr)
                            logging.info(f"Converted and installed .rpm package: {source}")
                            os.remove(converted_deb)  # Clean up
                        else:
                            messagebox.showerror("Error", "alien is not available for .rpm conversion.")
                            logging.error("No alien for .rpm conversion")
                            return
                    except subprocess.CalledProcessError as e:
                        messagebox.showerror("Error", f"Installation failed: {e.stderr}")
                        logging.exception(f"Failed to install .rpm package: {source}")
                        return
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to install .rpm package: {e}")
                        logging.exception(f"Failed to install .rpm package: {source}")
                        return
                
                messagebox.showinfo("Success", f"Package installed successfully: {os.path.basename(source)}")
                
                try:
                    subprocess.Popen([app_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    messagebox.showinfo("Success", f"Launching application: {app_command}")
                    logging.info(f"Launched application: {app_command}")
                    self.track_installed_app(app_command)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to launch application: {e}")
                    logging.exception(f"Failed to launch application: {app_command}")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {e}")
            logging.exception("Error in install_and_launch")
    
    def track_installed_app(self, app_command):
        try:
            with open(self.installed_apps_file, 'a') as f:
                f.write(f"{app_command}\n")
            logging.info(f"Tracked installed app: {app_command}")
        except Exception as e:
            logging.exception(f"Failed to track installed app: {app_command}")
            messagebox.showwarning("Warning", f"Failed to track app: {e}")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = KaliAppInstaller(root)
        root.mainloop()
    except Exception as e:
        logging.exception("Application crashed")
        print(f"Application crashed. Check installer_log.txt for details: {e}")
        sys.exit(1)