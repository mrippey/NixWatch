#!/usr/bin/env python
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi


AUTHOR = 'Michael Rippey, Twitter: @nahamike01'
LAST_SEEN = '2022 03 31'
DESCRIPTION = ''''Linux Indicator of Compromise (IOC) Assessment Tool

usage: python nix_watch.py -- <<arg>>  "/path/to/folder"'''

VT_API = 'your VT API Key'


def send_files_vt(files):
    
    vt_client = VirusTotalPublicApi(VT_API)
    results = vt_client.get_file_report(files)
    
    print(json.dumps(results, sort_keys=False, indent=4))

    #if len(files) >= 5:
        #sleep(16)


def check_folder_status(targ_pth):

    if targ_pth.is_dir() and any(Path(targ_pth).iterdir()):
        print('[*] Folder not empty, prcoeeding...\n')
    else:
        print(f'[!] Didnt recognize the path: {targ_pth}. Exiting...')
        sys.exit(1)


def hash_files_send_to_vt(targ_pth):
    print()
    print('[*] If a file extension match is found, file is sent to VirusTotal. Exits if none...\n')

    if targ_pth.is_dir() and any(Path(targ_pth).iterdir()):
        file_list = ['.sh', '.txt', '.elf', '.so.2', '.bin', '.o', '.so', '.prx', '.ko', '.exe', '.js']

        for f in targ_pth.iterdir():
            sha2_hash = hashlib.sha256(f.name.encode()).hexdigest()
            if f.suffix in file_list:
                print(f'File: {f.name} with hash: {sha2_hash} found!')
            send_files = str(input('Upload files to VirusTotal? (Y)es or (N)o \n'))
            if send_files == 'Y'.lower():
                send_files_vt(sha2_hash)
                time.sleep(16)
                continue
            elif send_files == 'N'.lower():
                continue
            else:
                sys.exit(1)


def last_mod(targ_pth):
    print('[*] Searching for most recently created/modified files...\n')
    try:
       
        daysago = time.time() - (60*60*24) * 1
        newfiles = [f for f in os.scandir(str(targ_pth)) if f.stat().st_mtime > daysago]
        for f in newfiles:
            print(f)
    except FileNotFoundError:
        print('[!] ERROR: Folder doesnt exist...')


def processes_run_from_dir(targ_pth):
    print(f'Finding processes running from {targ_pth}...\n')
    cmd = f'ls -alR /proc/*/cwd 2> /dev/null | grep {targ_pth}'
    os.system(cmd)
    
   
def find_execs_in_folder(targ_pth):
    print(f'Finding processes running from {targ_pth}...\n')
    
    cmd = " sudo find %s  -type f -exec file -p '{}' \; | grep ELF " % targ_pth
   
    os.system(cmd)


def list_hidden_dirs(targ_pth):
    cmd = f"sudo find {targ_pth} -type d -name '.*'"
    os.system(cmd)
    
def banner():
  
    return """
---------------------------------------------------------------
███╗   ██╗██╗██╗  ██╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗    
████╗  ██║██║╚██╗██╔╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║    
██╔██╗ ██║██║ ╚███╔╝ ██║ █╗ ██║███████║   ██║   ██║     ███████║    
██║╚██╗██║██║ ██╔██╗ ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║    
██║ ╚████║██║██╔╝ ██╗╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║    
╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝                                                                       
---------------------------------------------------------------                                                                 
    """


def main():

    parser = argparse.ArgumentParser(description=f'\nBy: {AUTHOR}\tLast_Seen: {LAST_SEEN}\n\nDescription: {DESCRIPTION}', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-c', '--ch', type=Path, help='Find executables/interesting files & hashes in /tmp folder')
    parser.add_argument('-m', '--mod', help='Find files modified or created within the last day')
    parser.add_argument('-p', '--proc', help='Display processes running from specified directory')
    parser.add_argument('-x', '--exec', help='find executables')
    parser.add_argument('-hd', '--hid', help='discover hidden files in a given folder')
   
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        print(banner())
        parser.print_help()

    elif args.ch:
        print(banner())
        check_folder_status(args.ch)
        hash_files_send_to_vt(args.ch)

    elif args.mod:
        print(banner())
        last_mod(args.mod)

    elif args.proc:
        print(banner())
        processes_run_from_dir(args.proc)
    
    elif args.exec:
        print(banner())
        find_execs_in_folder(args.exec)

    elif args.hid:
        print(banner())
        list_hidden_dirs(args.hid)
    

if __name__ == '__main__':
    main()
