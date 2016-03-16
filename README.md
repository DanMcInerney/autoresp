1. Connect to jumpbox VPN
2. Connect to cracking box's VPN (if its not on your local network)
3. ```sudo python autoresp.py -c <crackerbox IP> -w <wordlist_path> -r <rule_path> -x <hashcat_path>```


Script will launch Responder on the drone device in a screen session. It will then pull down any NTLM hashes that Responder finds to the local machine, and upload them to the cracking machine to kick off a hashcat session. It will then look for the cracked hash on the crackerbox, alert you when one appears, and write it to cracked.txt locally. Hitting Ctrl+C will cause it to kill Responder on the drone but continue looking for cracked hashes. If you want to exit entirely then cit Ctrl+C again.
