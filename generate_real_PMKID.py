#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from hashlib import pbkdf2_hmac, sha1
import hmac
import subprocess

essid = input('ESSID: ')
passphrase = input('Passphrase: ')
bssid = input('BSSID: ').lower().replace(':', '').replace('-', '').replace('.', '')
sta_mac = input('Client MAC: ').lower().replace(':', '').replace('-', '').replace('.', '')


pmk = pbkdf2_hmac(
    'sha1', bytes(passphrase, 'utf-8'), bytes(essid, 'utf-8'),
    iterations=4096, dklen=32
)

print(pmk.hex())

pmkid = hmac.new(pmk, (b'PMK Name' + bytes.fromhex(bssid) + bytes.fromhex(sta_mac)), sha1).hexdigest()[:32]

pmkid_string = '{}*{}*{}*{}'.format(pmkid, bssid, sta_mac, bytes(essid, 'utf-8').hex())
print('PMKID string:', pmkid_string)

# Writing result to Hashcat 16800 file
with open(essid + '.16800', 'w') as file:
    file.write(pmkid_string)

# Writing result to pcap file
cmd = 'hcxhash2cap --pmkid {}.16800 -c {}.cap'.format(essid, essid)
r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, encoding='utf-8')
if 'not found' in r.stderr:
    print('You need to install hcxtools to generate pcap capture file: https://github.com/ZerBea/hcxtools')

print('Result writed to {}'.format(essid))
