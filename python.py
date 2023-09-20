# Importing necessary libraries
import os
import subprocess
import re

# Get the current logged-in user
current_user = os.getlogin()

# Function to check if Lynis is installed and install it if not
def install_lynis_scan():
    # Check if Lynis is already installed
    result = subprocess.run(["dpkg", "-l", "lynis"], capture_output=True, text=True)
    # If Lynis is not found in the installed packages, install it
    if "ii  lynis" not in result.stdout:
        print("Installing lynis...")
        subprocess.run(["sudo", "apt-get", "install", "lynis", "-y"])
    else:
        print("lynis is already installed.")

# Function to execute a Lynis system audit
def run_lynis_scan():
    subprocess.run(["sudo","lynis", "audit", "system"])

# Function to display the system's hardening index from the Lynis report
def display_hardening_index():
    try:
        with open("/var/log/lynis.log", "r") as report_file:
            log_data = report_file.read()
            match = re.search(r"Hardening index.*?\[([\d]+)\]", log_data)
            if match:
                hardening_index = match.group(1)
                print("Hardening Index:", hardening_index)
                return hardening_index
            else:
                print("Hardening index not found")
    except FileNotFoundError:
        print("Lynis log file not found")
    except Exception as e:
        print(f"An error occurred while reading the log file: {e}")

    
# Function to execute a bash script for hardening
def run_hardening_bash_script():
    subprocess.run(["sudo","bash", "hardening_bash.sh"])

# Function to apply various system hardening measures
def edit_directory():

    # Edit the system's limits configuration
    print("limits.conf...........")
    subprocess.run(["sudo","echo", "* hard core 0 >> /etc/security/limits.conf"])
    
    # Edit the sysctl configuration for suid_dumpable
    print("sysctl.conf...........")
    subprocess.run(["sudo","echo", "fs.suid_dumpable = 0 >> /etc/sysctl.conf"])
    subprocess.run(["sudo","sysctl", "-w", "fs.suid_dumpable=0"])
    
    # Edit the systemd coredump configuration
    print("coredump_config...........")
    coredump_config = """
    Storage=none
    ProcessSizeMax=0
    """
    print("daemon-reload...........")
    with open("/etc/systemd/coredump.conf", "w") as f:
        f.write(coredump_config)
    subprocess.run(["sudo","systemctl", "daemon-reload"])
    
    # Edit the grub configuration for apparmor
    print("update-grub...........")
    subprocess.run(["sudo","sed", "-i", 's/GRUB_CMDLINE_LINUX=".*"/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"/', "/etc/default/grub"])
    subprocess.run(["sudo","update-grub"])
    
    # Edit the NTP configuration to add restrictions
    print("ntp.conf...........")
    ntp_config = """
    restrict -4 default kod nomodify notrap nopeer noquery
    restrict -6 default kod nomodify notrap nopeer noquery
    """
    with open("/etc/ntp.conf", "a") as f:
        f.write(ntp_config)
    subprocess.run(["sudo","systemctl", "restart", "ntp"])
    
    # Edit the NTP service configuration
    print("ntp.service restart...........")
    subprocess.run(["sudo","sed", "-i", 's/RUNASUSER=.*/RUNASUSER=ntp/', "/etc/init.d/ntp"])
    subprocess.run(["sudo","systemctl", "restart", "ntp.service"])
    
    # Edit the SSH configuration for enhanced security
    print("ssh_config...........")
    ssh_config = """
    LogLevel VERBOSE
    UsePAM yes
    PermitRootLogin no
    HostbasedAuthentication no
    PermitEmptyPasswords no
    PermitUserEnvironment no
    IgnoreRhosts yes
    X11Forwarding no
    AllowTcpForwarding no
    Banner /etc/issue.net
    MaxAuthTries 4
    MaxStartups 10:30:60
    MaxSessions 10
    LoginGraceTime 60
    ClientAliveInterval 15
    ClientAliveCountMax 3
    """
    with open("/etc/ssh/sshd_config", "a") as f:
        f.write(ssh_config)
    
    # Install and configure pam_pwquality module
    print("installing libpam-pwquality...........")
    subprocess.run(["sudo","apt", "install", "libpam-pwquality", "-y"])
    pwquality_config = """
    minlen = 14
    minclass = 4
    """
    print("pwquality_config...........")
    with open("/etc/security/pwquality.conf", "w") as f:
        f.write(pwquality_config)
    
    # Modify password policies
    print("current_user...........")
    subprocess.run(["sudo","sed", "-i", 's/PASS_MIN_DAYS .*/PASS_MIN_DAYS 1/', "/etc/login.defs"])
    subprocess.run(["sudo","chage", "--mindays", "1", current_user]) 
    
    subprocess.run(["sudo","sed", "-i", 's/PASS_MAX_DAYS .*/PASS_MAX_DAYS 365/', "/etc/login.defs"])
    subprocess.run(["sudo","chage", "--maxdays", "365", current_user]) 

    subprocess.run(["sudo","sed", "-i", 's/PASS_WARN_AGE .*/PASS_WARN_AGE 7/', "/etc/login.defs"])
    subprocess.run(["sudo","chage", "--warndays", "7", current_user])  
    
    subprocess.run(["sudo","useradd", "-D", "-f", "30"])
    subprocess.run(["sudo","chage", "--inactive", "30", current_user])  
    print("END...........")

# Main function
def main():

    # Start Lynis installation and system audit
    install_lynis_scan()
    run_lynis_scan()
    hardening_index = display_hardening_index()
    
    # Prompt user for additional hardening actions
    user_input = input("Do you want to apply additional hardening? (yes/no): ")
    if user_input.lower() == "yes":
         run_hardening_bash_script()
         print("edit dir function started")
         edit_directory()
         print("edit dir function ended")
         run_lynis_scan()      
         new_hardening_index = display_hardening_index()
         if float(new_hardening_index) > float(hardening_index):
            print("Hardening successful!")
            print("New Hardening Index:", new_hardening_index)
         else:
            print("Hardening unsuccessful!")
    else:
        print("Hardening process Terminated!")


# Execute the main function when the script is run
if __name__ == "__main__":
    main()