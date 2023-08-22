import os
import subprocess

def install_lynis_scan():
    subprocess.run(["apt-get", "install", "lynis", "-y"])

def run_lynis_scan():
    subprocess.run(["lynis", "audit", "system"])

def display_hardening_index():
    with open("/var/log/lynis-report.dat", "r") as report_file:
        for line in report_file:
            if "Hardening index" in line:
                hardening_index = line.split(":")[1].strip()
                print("Hardening Index:", hardening_index)
                return hardening_index

def run_pavi_bash_script():
    subprocess.run(["bash", "pavi_bash.sh"])

# def edit_directory():

def main():
    install_lynis_scan()
    run_lynis_scan()
    hardening_index = display_hardening_index()
    
    user_input = input("Do you want to apply additional hardening? (yes/no): ")
    if user_input.lower() == "yes":
        # run_pavi_bash_script()
        # edit_directory()
        run_lynis_scan()  
        new_hardening_index = display_hardening_index()
        print("New Hardening Index:", new_hardening_index)

if __name__ == "__main__":
    main()
