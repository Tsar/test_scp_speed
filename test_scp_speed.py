#!/usr/bin/env python3

import os
import sys
import json
import time
from datetime import datetime
from random import randint
import hashlib

import paramiko
from scp import SCPClient

t = lambda: time.time()
ts = lambda: datetime.now().strftime('[%Y-%m-%d %H:%M:%S.%f]')
log = lambda text: print(f'{ts()} {text}', flush=True)

def create_ssh_client(hostname, port, username, password=None, key_filename=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if key_filename:
        ssh.connect(hostname, port=port, username=username, key_filename=key_filename)
    else:
        ssh.connect(hostname, port=port, username=username, password=password)
    return ssh

def calculate_md5(filename, chunk_size=65536):
    md5_hash = hashlib.md5()
    with open(filename, 'rb') as file:
        chunk = file.read(chunk_size)
        while chunk:
            md5_hash.update(chunk)
            chunk = file.read(chunk_size)
    return md5_hash.hexdigest()

if __name__ == '__main__':
    launch_datetime = datetime.now().strftime('%Y-%m-%d %H:%M')

    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <JSON config file>')
        sys.exit(0)

    with open(sys.argv[1], 'r') as configFile:
        config = json.load(configFile)
        remote_path = config['remote_path']    # file that will be downloaded
        expected_md5 = config['expected_md5']  # md5 of the file
        report_filename = config.get('report_filename')

    local_tmp_filename = f'/tmp/test_scp_speed_file_{randint(1000000, 9999999)}.bin'

    ssh_client = create_ssh_client(
        hostname=config['hostname'],
        port=int(config['port']),
        username=config['username'],
        password=config.get('password'),
        key_filename=config.get('key_filename'),
    )

    log(f'Connecting to server')
    with SCPClient(ssh_client.get_transport()) as scp:
        log(f'Downloading file "{remote_path}" to "{local_tmp_filename}"')
        download_start_time = t()
        scp.get(remote_path, local_tmp_filename)
        elapsed = t() - download_start_time

    file_size_mb = os.path.getsize(local_tmp_filename) / 1048576.0
    avg_speed = file_size_mb / elapsed
    log(
        'Download finished:\n' +
        f' * file size:     {file_size_mb:.1f} MB\n' +
        f' * elapsed:       {elapsed:.1f} sec\n' +
        f' * average speed: {avg_speed:.2f} MB/sec'
    )
    md5 = calculate_md5(local_tmp_filename)
    md5_matches = md5.lower() == expected_md5.lower()
    if md5_matches:
        log('MD5 hash matches expected')
    else:
        log(f'MD5 hashes do not match: got {md5}, expected {expected_md5}')
    os.remove(local_tmp_filename)

    if report_filename:
        report_file_existed = os.path.isfile(report_filename)
        with open(report_filename, 'a') as report:
            if not report_file_existed:
                report.write('Timestamp,File size (MB),Elapsed (sec),Average speed (MB/sec),MD5 matches\n')
            md5_ok = 'Yes' if md5_matches else f'"No: got {md5}, expected {expected_md5}"'
            report.write(f'{launch_datetime},{file_size_mb:.1f},{elapsed:.1f},{avg_speed:.2f},{md5_ok}\n')
