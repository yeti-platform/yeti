'''
Created on 13 mai 2015

@author: slarinier

Thanks to inliniac and Regit for ideas: 
https://github.com/inliniac/suricata/blob/master/scripts/suricatasc/src/suricatasc.py
'''
from ConfigParser import ConfigParser
import glob
import multiprocessing
import os
import re
from socket import socket, AF_UNIX, error
from subprocess import PIPE
import subprocess
import sys
from time import sleep

from Malcom.auxiliary.toolbox import debug_output
from Malcom.sniffer.modules.base_module import Module
import simplejson as json


classname = "Suricata"
SURICATASC_VERSION = "0.9"

VERSION = "0.1"
SIZE = 4096

class Suricata(Module):
    def __init__(self,session):
        self.session = session
        self.display_name = "Suricata"
        self.name = "suricata"
        self.pull_content = 'suricata'
        super(Suricata, self).__init__()
        interface,mode,conf_suricata,socket_unix=self.setup()
        
                
        self.actions=Actions(interface=interface, conf_sniffer=conf_suricata, mode=mode, socket_unix=socket_unix)
        if not os.path.isdir(os.path.join(self.session.engine.setup['MODULES_DIR'],self.name,str(self.session.id))):
            self.actions.start()
        
    def setup(self):
        interface=''
        mode=''
        conf_suricata=''
        socket_unix=''
        
        if 'suricata' in self.config:
            if 'interface' in self.config['suricata']:
                interface=self.config['suricata']['interface']
            if 'mode' in self.config['suricata']:
                mode=self.config['suricata']['mode']
            if 'conf_suricata' in self.config['suricata']:
                conf_suricata=self.config['suricata']['conf_suricata']
            if 'socket_unix' in self.config['suricata']:
                socket_unix=self.config['suricata']['socket_unix']
                
        return interface,mode,conf_suricata,socket_unix
    def content(self,path):
        content="<table class='table table-condensed'><tr><th>Timestamp</th><th>Event Type</th><th>Proto</th><th>Source</th><th>Destination</th><th>Signature ID</th><th>Signature</th><th>Category</th><th>md5</th></tr>"
        with open(path, 'r') as f_json:
            for l in f_json:
                entry=json.loads(l)
                timestamp=entry['timestamp']
                event_type=entry['event_type']
                src_ip=entry['src_ip']
                src_port=entry['src_port']
                dest_ip=entry['dest_ip']
                dest_port=entry['dest_port']
                proto=entry['proto']
                signature_id=''
                description=''  
                category=''
                md5file=''
                if event_type =="alert":
                    signature_id=entry['alert']['signature_id']
                    description=entry['alert']['signature']
                    category=entry['alert']['category']
                if event_type=='fileinfo':
                    description=entry['fileinfo']['filename']
                    category=entry['fileinfo']['magic']
                    if 'md5' in entry['fileinfo']:
                        md5file=entry['fileinfo']['md5']
                if (event_type =="alert" or event_type=='fileinfo') and (description not in  ['SURICATA TCPv4 invalid checksum','FILE store all']): 
                    content=content+'<tr><td>%s</td><td>%s</td><td>%s</td><td>%s %s</td><td>%s %s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' %(timestamp,event_type,proto,src_ip,src_port,dest_ip,dest_port,signature_id,description,category,md5file)
            content=content+"</table>"
            return content
    def files_meta(self,dir_to_write_logs):
        files_dir=os.path.join(dir_to_write_logs,'files')
        files_metas=glob.glob(files_dir+'*.meta')
        for file_metas in files_metas:
            pass
    def bootstrap(self):
        file_name=self.session.pcap_filename
        name_session=self.session.name
        if file_name and name_session:
            file_to_analyse=os.path.join(self.session.engine.setup['SNIFFER_DIR'],file_name)
            dir_to_write_logs=os.path.join(self.session.engine.setup['MODULES_DIR'],self.name,str(self.session.id))    
            if not os.path.isdir(dir_to_write_logs):
                self.actions.send_pcap(file_to_analyse, dir_to_write_logs)
                sleep(10)
                
        content=self.content(os.path.join(dir_to_write_logs,'eve.json'))
        if not os.path.isdir(dir_to_write_logs):
            self.actions.stop()
        return content
            
    def on_packet(self, pkt):
        pass



#Class to execute and launch command with Suricata
class Actions(object):
    '''
    classdocs
    '''


    def __init__(self,sniffer='suricata',interface='eth0',conf_sniffer="/etc/suricata/suricata.yaml",pid_rep="/run/",mode='--unix-socket',socket_unix="/var/run/suricata/suricata-command.socket"):
        '''
        Constructor
        '''
        self.sniffer=sniffer
        self.interface=interface
        self.conf_sniffer=conf_sniffer
        self.pip_rep=pid_rep
        self.mode=mode
        self.suricate_brocker=SuricataBroker(socket_unix)
    def start(self):
            pr=multiprocessing.Process(target=self.run)
            pr.start()
    def stop(self):
        ret=self.suricate_brocker.connect()
        
        if ret:
            self.suricate_brocker.stop()
        self.suricate_brocker.close()
        
    def run(self):
        cmd=[]
        if self.mode=="--unix-socket":
            cmd=[self.sniffer,'-c',self.conf_sniffer,'--unix-socket']
        if self.mode=='online':
            cmd=[self.sniffer,'-c',
                              self.conf_sniffer,'-i',self.interface,
                              '-D']
        try:
            result=subprocess.Popen(cmd,
                             stdout=PIPE)
            for ligne in result.stdout.read():
                #debug_output('toto'+ligne+'\r\n')
                pass
        except OSError:
            pass
    def send_pcap(self,pcap_file,directory='output'):
        ret=self.suricate_brocker.connect()
        if not os.path.isdir(directory):
            os.mkdir(directory)
        if ret:
            self.suricate_brocker.send_pcap(pcap_file, directory)
        self.suricate_brocker.close()
    
        


class SuricataBroker(object):
    def __init__(self,sck_path='', verbose=True):

        self.cmd_list=['shutdown','quit','pcap-file','pcap-file-number','pcap-file-list','iface-list','iface-stat']
        self.sck_path = sck_path
        self.verbose = verbose
        
    def json_recv(self):
        cmdret = None
        i = 0
        data = ""
        while i < 5:
            i += 1
            data += self.socket.recv(SIZE)
            try:
                cmdret = json.loads(data)
                break
            except json.decoder.JSONDecodeError:
                sleep(0.3)
        return cmdret

    def send_command(self, command, arguments = None):
        if command not in self.cmd_list and command != 'command-list':
            raise SuricataCommandException("No such command: %s", command)

        cmdmsg = {}
        cmdmsg['command'] = command
        if (arguments != None):
            cmdmsg['arguments'] = arguments
        if self.verbose:
            debug_output("SND: " + json.dumps(cmdmsg),'info')
        self.socket.send(json.dumps(cmdmsg))
        cmdret = self.json_recv()

        if cmdret == None:
            raise SuricataReturnException("Unable to get message from server")

        if self.verbose:
            debug_output("RCV: "+ json.dumps(cmdret),'info')

        return cmdret

    def connect(self):
        try:
            self.socket = socket(AF_UNIX)
            self.socket.connect(self.sck_path)
        except error, err:
            raise SuricataNetException(err)

        self.socket.settimeout(10)
        #send version
        if self.verbose:
            debug_output("SND: " + json.dumps({"version": VERSION}),'info')
        self.socket.send(json.dumps({"version": VERSION}))

        # get return
        cmdret = self.json_recv()

        if cmdret == None:
            raise SuricataReturnException("Unable to get message from server")

        if self.verbose:
            debug_output("RCV: "+ json.dumps(cmdret),'info')

        if cmdret["return"] == "NOK":
            raise SuricataReturnException("Error: %s" % (cmdret["message"]))

        cmdret = self.send_command("command-list")

        # we silently ignore NOK as this means server is old
        if cmdret["return"] == "OK":
            self.cmd_list = cmdret["message"]["commands"]
            self.cmd_list.append("quit")
            return True
    
    def stop(self):
        command='shutdown'
        arguments={}
        self.send_command(command, arguments)
    
    def close(self):
        self.socket.close()
    def send_pcap(self,pcap_file,directory):
        command='pcap-file'
        arguments={}
        if os.path.isfile(pcap_file) and os.path.isdir(directory):
            arguments["filename"] = pcap_file
            arguments["output-dir"] = directory
            cmdret=self.send_command(command, arguments)
            if cmdret["return"] == "NOK":
                    
                    debug_output(json.dumps(cmdret["message"], sort_keys=True, indent=4, separators=(',', ': ')),'error')
            else:
                    
                    debug_output(json.dumps(cmdret["message"], sort_keys=True, indent=4, separators=(',', ': ')),'info')

class SuricataException(Exception):
    """
    Generic class for suricatasc exception
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)

class SuricataNetException(SuricataException):
    """
    Exception raised when network error occur.
    """
    pass

class SuricataCommandException(SuricataException):
    """
    Exception raised when command is not correct.
    """
    pass

class SuricataReturnException(SuricataException):
    """
    Exception raised when return message is not correct.
    """
    pass


class SuricataCompleter:
    def __init__(self, words):
        self.words = words
        self.generator = None

    def complete(self, text):
        for word in self.words:
            if word.startswith(text):
                yield word

    def __call__(self, text, state):
        if state == 0:
            self.generator = self.complete(text)
        try:
            return self.generator.next()
        except StopIteration:
            return None
        return None

