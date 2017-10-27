import paramiko
from scp import SCPClient
import os
import shutil
from datetime import datetime
import tempfile
import argparse

"""
This script is intended to work locally and test changes remotely.
It will create a zip file of your current work on the Yeti folder 
and copy it to the remote server via SCP. 
It will unzip it and restart the services for you so you can easily
deploy your code before making a git commit.

usage: local_upload.py [-h] -s SERVER -p PORT -c CERT [-u USER]
                       [-r REMOTELOCATION]

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        The ssh server to connect to
  -p PORT, --port PORT  The port to connect to
  -c CERT, --cert CERT  Private key path for auth
  -u USER, --user USER  The username to login
  -r REMOTELOCATION, --remotelocation REMOTELOCATION
                        Yeti's remote location
"""


def get_yeti_path():
    os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
    return os.path.abspath('..')


def compress_folder():
    yeti_path = get_yeti_path()
    filename = '{:%m-%d-%Y_%H-%M}'.format(datetime.now())
    temp_path = os.path.join(tempfile.gettempdir(), filename)
    print('Zipping folder')
    temp_path = shutil.make_archive(temp_path, 'zip', yeti_path)
    print('Created {} file'.format(temp_path))
    return temp_path


def delete_file(filename):
    print('Deleting {}'.format(filename))
    if os.remove(filename):
        return True
    return False


def get_ssh_client(server, port, username, cert_file):
    print('Getting client')
    client = paramiko.SSHClient()
    client.load_host_keys(cert_file)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(server, port=port, username=username)
    print('Connected to client')
    return client


def send_ssh_file(client, src, dst):
    scp = SCPClient(client.get_transport())
    print('Sending file')
    scp.put(src, dst)
    scp.close()


def uncompress_and_delete_from_server(client, filename, destination='/opt/yeti'):
    commands = [
        'unzip -o /tmp/{filename} -d {destination}'.format(filename=filename, destination=destination),
        'rm /tmp/{filename}'.format(filename=filename),
        'ls {}/extras/systemd/ | xargs systemctl restart'.format(destination)
    ]
    # Unzip and overwrite folder
    for command in commands:
        (stdin, stdout, stderr) = client.exec_command(command)
        if stdout.channel.recv_exit_status():
            print(stderr.read())


if __name__ == '__main__':
    print('Starting script')
    client = None
    temp_path = None
    deleted = False
    ap = argparse.ArgumentParser()
    ap.add_argument('-s', '--server', help='The ssh server to connect to', required=True)
    ap.add_argument('-p', '--port', help='The port to connect to', required=True, type=int)
    ap.add_argument('-c', '--cert', help='Private key path for auth', required=True)
    ap.add_argument('-u', '--user', help='The username to login')
    ap.add_argument('-r', '--remotelocation', help='Yeti\'s remote location')
    ag = ap.parse_args()
    try:
        temp_path = compress_folder()
        client = get_ssh_client(ag.server, port=ag.port, username=ag.user or 'root',
                                cert_file=ag.cert)
        send_ssh_file(client, temp_path, '/tmp')
        deleted = delete_file(temp_path)
        terminator = '\\' if os.name == 'nt' else '/'
        uncompress_and_delete_from_server(client, temp_path.split(terminator)[-1],
                                          destination=ag.remotelocation or '/opt/yeti/')
    except Exception:
        if temp_path and not deleted:
            delete_file(temp_path)
        raise
    finally:
        if client:
            client.close()
    print('Done')

