#!/usr/local/bin/python3.4
'''
*****************************************************************************************
Copyright (c) 2017 Jorge Borreicho
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*****************************************************************************************
'''

import sys
import os
import socket
import socketserver
import signal
import multiprocessing
import threading
import configparser
import json
import hashlib
import binascii
from optparse import OptionParser

from jb_radius import *


class RadiusHandler(socketserver.BaseRequestHandler):

    def handle(self):
    
        global RADIUS_RULES, RADIUS_ACTIONS, RADIUS_SERVERS, RADIUS_USERS, RADIUS_CLIENTS, RADIUS_AUTH_PORT, RADIUS_ACCT_PORT
        
        listening_port = self.server.server_address[1]
        
        #Find out if it is an authentication or accounting request based on the server port
        if listening_port == RADIUS_AUTH_PORT:
            request_type = "authentication"
        elif listening_port == RADIUS_ACCT_PORT:
            request_type = "accounting"
        else:
            return
        
        #Check if the request comes from an authorized client
        radius_secret = ""
        for authorized_address in RADIUS_CLIENTS.keys():
            addr, dec_mask = authorized_address.split("/")
            mask = dec2mask(int(dec_mask))
            if subnet_address(self.client_address[0], mask) == addr:
                radius_secret = RADIUS_CLIENTS[authorized_address]["secret"]
                break
        
        if radius_secret == "": 
            log2file("Received from {0} port {1}: Unknown Client, Silently Discarding".format(self.client_address[0], self.client_address[1])) 
            return
        
        
        radius_packet = Radius_Packet(RADIUS_DICT, radius_secret)
        radius_packet.Radius_Decode(self.request[0])
        
        log2file("Received from {0} port {1}".format(self.client_address[0], self.client_address[1]) + str(radius_packet.Print()))
                
        rules_numbers = list(RADIUS_RULES.keys())
        rules_numbers = [int(i) for i in rules_numbers]
        rules_numbers.sort()

        next_rule = rules_numbers.pop(0) #first rule
        prev_rule = -1
        user_profile = "none" #init user profile
        
        log2file("Executing rules...")
        while next_rule > 0:
            
            if next_rule <= prev_rule:
                next_rule = int(rules_numbers.pop(0)) #pop next rule
                continue
                
            prev_rule = next_rule

            if request_type == "authentication" and RADIUS_RULES[str(next_rule)]["criteria"] == "user_authentication":
                username = radius_packet.Lookup_AVP_Value("User-Name")
                password_cyphered = radius_packet.Lookup_AVP_Value("User-Password")
                
                if password_cyphered is not None and username is not None:  #the required AVPs are present in the request packet
                
                    password_decyphered = Radius_User_Password_Decrypt(password_cyphered , radius_secret, radius_packet.Lookup_Authenticator())
                    
                    try:
                        password_format = RADIUS_USERS[username]["password_format"] 
                        user_password = RADIUS_USERS[username]["password"] #username found
                    except KeyError: #username not found
                        log2file("User Authentication: username not found or with missing parameters")
                        user_password = "\n"
                        password_format = "clear"
                    
                    if password_format == "md5":
                        h = hashlib.md5()
                        h.update(password_decyphered.encode("utf-8"))
                        password_decyphered = h.digest()
                        password_decyphered = binascii.hexlify(bytearray(password_decyphered)).decode()
                    
                    if user_password == password_decyphered: # password matches
                        try:
                            user_profile = RADIUS_USERS[username]["user_profile"]
                        except:
                            pass #user_profile = "none"
                            
                        log2file("User Authentication: success (user profile: {0})".format(user_profile))
                        try:
                            next_rule = int(RADIUS_RULES[str(next_rule)]["next_rule"])
                            next_action = 0
                        except KeyError:
                            try:
                                next_action = int(RADIUS_RULES[str(next_rule)]["action"])
                                next_rule = 0
                            except KeyError:
                                next_action = 0
                                next_rule = 0
                    else: # unknown user or bad password
                        log2file("User Authentication: failed")
                        next_rule = int(rules_numbers.pop(0)) #pop next rule
                        next_action = 0
                        
            elif request_type == "authentication" and RADIUS_RULES[str(next_rule)]["criteria"] == "user_profile_matches":
                             
                if user_profile == RADIUS_RULES[str(next_rule)]["profile_name"]: # profile matches
                    log2file("User Profile Matches {0}: yes".format(RADIUS_RULES[str(next_rule)]["profile_name"]))
                    try:
                        next_rule = int(RADIUS_RULES[str(next_rule)]["next_rule"])
                        next_action = 0
                    except KeyError:
                        try:
                            next_action = int(RADIUS_RULES[str(next_rule)]["action"])
                            next_rule = 0
                        except KeyError:
                            next_action = 0
                            next_rule = 0
                else: # unknown user or bad password
                    log2file("User Profile Matches {0}: no".format(RADIUS_RULES[str(next_rule)]["profile_name"]))
                    next_rule = int(rules_numbers.pop(0)) #pop next rule
                    next_action = 0  
                        
            elif RADIUS_RULES[str(next_rule)]["criteria"] == "attribute_matches":
                try:
                    attribute_name = RADIUS_RULES[str(next_rule)]["attribute_name"]
                    attribute_value = RADIUS_RULES[str(next_rule)]["attribute_value"]
                except KeyError:
                    attribute_name = "none"
                    attribute_value = "\n"
                    
                if attribute_name != "none":    
                    received_attribute_value = radius_packet.Lookup_AVP_Value(attribute_name)
                
                    if received_attribute_value == attribute_value: # attribute matches
                        log2file("Attribute {0} Matches {1}: yes".format(attribute_name, attribute_value))
                        try:
                            next_rule = int(RADIUS_RULES[str(next_rule)]["next_rule"])
                            next_action = 0
                        except KeyError:
                            try:
                                next_action = int(RADIUS_RULES[str(next_rule)]["action"])
                                next_rule = 0
                            except KeyError:
                                next_action = 0
                                next_rule = 0
                    else: # unknown user or bad password
                        log2file("Attribute {0} Matches {1}: no".format(attribute_name, attribute_value))
                        next_rule = int(rules_numbers.pop(0)) #pop next rule
                        next_action = 0      
                        
            elif RADIUS_RULES[str(next_rule)]["criteria"] == "is_authentication":
                if request_type == "authentication":
                    log2file("Is Authentication: yes")
                    try:
                        next_rule = int(RADIUS_RULES[str(next_rule)]["next_rule"])
                        next_action = 0
                    except KeyError:
                        try:
                            next_action = int(RADIUS_RULES[str(next_rule)]["action"])
                            next_rule = 0
                        except KeyError:
                            next_action = 0
                            next_rule = 0
                else:
                    log2file("Is Authentication: no")
                    next_rule = int(rules_numbers.pop(0)) #pop next rule
                    next_action = 0 
                    
            elif RADIUS_RULES[str(next_rule)]["criteria"] == "is_accounting":
                if request_type == "accounting":
                    log2file("Is Accounting: yes")
                    try:
                        next_rule = int(RADIUS_RULES[str(next_rule)]["next_rule"])
                        next_action = 0
                    except KeyError:
                        try:
                            next_action = int(RADIUS_RULES[str(next_rule)]["action"])
                            next_rule = 0
                        except KeyError:
                            next_action = 0
                            next_rule = 0
                else:
                    log2file("Is Accounting: no")
                    next_rule = int(rules_numbers.pop(0)) #pop next rule
                    next_action = 0 
                    
            elif RADIUS_RULES[str(next_rule)]["criteria"] == "none":
                log2file("Rule with no criteria")
                try:
                    next_rule = int(RADIUS_RULES[str(next_rule)]["next_rule"])
                    next_action = 0
                except KeyError:
                    try:
                        next_action = int(RADIUS_RULES[str(next_rule)]["action"])
                        next_rule = 0
                    except KeyError:
                        next_action = 0
                        next_rule = 0
            else:
                next_rule = 0
                next_action = 0
                
        action = "ignore" #init action  
        proxy_server = "none" #init proxy server
    
        log2file("Executing actions...")    
        while next_action > 0:

            if request_type == "authentication" and RADIUS_ACTIONS[str(next_action)]["action"] == "accept":
                action = "accept"
                log2file("Reply with Access-Accept") 
                try:
                    next_action = int(RADIUS_ACTIONS[str(next_action)]["next_action"])
                except KeyError:
                    next_action = 0
                    
            elif request_type == "authentication" and RADIUS_ACTIONS[str(next_action)]["action"] == "reject":        
                action = "reject"
                log2file("Reply with Access-Reject") 
                try:
                    next_action = int(RADIUS_ACTIONS[str(next_action)]["next_action"])
                except KeyError:
                    next_action = 0
                    
            elif request_type == "accounting" and RADIUS_ACTIONS[str(next_action)]["action"] == "accept":
                action = "accept"
                log2file("Reply with Accounting-Response") 
                try:
                    next_action = int(RADIUS_ACTIONS[str(next_action)]["next_action"])
                except KeyError:
                    next_action = 0                    
            elif RADIUS_ACTIONS[str(next_action)]["action"] == "proxy":        
                action = "proxy"
                try:
                    proxy_server = RADIUS_SERVERS[RADIUS_ACTIONS[str(next_action)]["server"]]
                    proxy_server_name = RADIUS_ACTIONS[str(next_action)]["server"]
                except KeyError:
                    proxy_server = "none" 
                    proxy_server_name = "none"
                    
                log2file("Proxy Request to {0}".format(proxy_server_name)) 
                proxy_radius_packet = Radius_Packet(RADIUS_DICT, proxy_server["secret"])
                proxy_radius_packet.Add_AVP_List(radius_packet.Lookup_AVP_List(), radius_secret, radius_packet.Lookup_Authenticator())
                try:
                    next_action = int(RADIUS_ACTIONS[str(next_action)]["next_action"])
                except KeyError:
                    next_action = 0  
                    
            elif RADIUS_ACTIONS[str(next_action)]["action"] == "add_attribute": 
                try:
                    attribute_name = RADIUS_ACTIONS[str(next_action)]["attribute_name"]
                    attribute_value = RADIUS_ACTIONS[str(next_action)]["attribute_value"]
                except KeyError:
                    log2file("Added attribute: error, missing parameters") 
                if action == "proxy" and attribute_name is not None and attribute_value is not None:
                    proxy_radius_packet.Add_AVP(attribute_name, attribute_value)
                    log2file("Added attribute: {0} = {1}".format(attribute_name, attribute_value))                   
                elif attribute_name is not None and attribute_value is not None:
                    radius_packet.Add_AVP(attribute_name, attribute_value)
                    log2file("Added attribute: {0} = {1}".format(attribute_name, attribute_value)) 
                try:
                    next_action = int(RADIUS_ACTIONS[str(next_action)]["next_action"])
                except KeyError:
                    next_action = 0
            else:
                next_action = 0

                    
        if request_type == "authentication" and action == "accept":
            radius_packet.Add_Header("Access-Accept")
            radius_packet.Radius_Decode(radius_packet.Packet())
            log2file("Sending to {0} port {1}".format(self.client_address[0], self.client_address[1]) + str(radius_packet.Print()))
            request_socket = self.request[1]
            request_socket.sendto(radius_packet.Packet(), self.client_address)
        elif request_type == "authentication" and action == "reject":
            radius_packet.Add_Header("Access-Reject")
            radius_packet.Radius_Decode(radius_packet.Packet())
            log2file("Sending to {0} port {1}".format(self.client_address[0], self.client_address[1]) + str(radius_packet.Print()))
            request_socket = self.request[1]
            request_socket.sendto(radius_packet.Packet(), self.client_address)        
        elif request_type == "accounting" and action == "accept":
            radius_packet.Add_Header("Accounting-Response")
            radius_packet.Radius_Decode(radius_packet.Packet())
            log2file("Sending to {0} port {1}".format(self.client_address[0], self.client_address[1]) + str(radius_packet.Print()))
            request_socket = self.request[1]
            request_socket.sendto(radius_packet.Packet(), self.client_address)
        elif action == "proxy" and proxy_server != "none":
            try:
                if request_type == "authentication":
                    proxy_radius_packet.Add_Header("Access-Request")
                    proxy_port = proxy_server["auth_port"]
                elif request_type == "accounting":
                    proxy_radius_packet.Add_Header("Accounting-Request")
                    proxy_port = proxy_server["acct_port"]
                    
                proxy_radius_packet.Radius_Decode(proxy_radius_packet.Packet())            
                log2file("Sending to {0} port {1} (proxy)".format(proxy_server["ip_address"], proxy_port) + str(proxy_radius_packet.Print()))
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                proxy_sock.settimeout(int(proxy_server["timeout"]))
                
                proxy_sock.sendto(proxy_radius_packet.Packet(), (proxy_server["ip_address"],  int(proxy_port)))
                
                received_data = proxy_sock.recvfrom(1500)
                proxy_radius_packet.Radius_Decode(received_data[0])
                log2file("Received from {0} port {1} (proxy)".format(proxy_server["ip_address"], proxy_port) + str(proxy_radius_packet.Print()))
                
                radius_packet.Add_AVP_List(proxy_radius_packet.Lookup_AVP_List(), proxy_server["secret"], proxy_radius_packet.Lookup_Authenticator())
                radius_packet.Add_Header(proxy_radius_packet.Lookup_Command_Name())
                
                #reply back with message reveived from proxy server (no modification is made to the AVPs)
                request_socket = self.request[1]
                request_socket.sendto(radius_packet.Packet(), self.client_address)
                
            except KeyError:
                log2file("Proxy Failed: missing parameters") 
            except socket.timeout:
                log2file("No Reply from {0} port {1}: Timeout")
            #except:
            #    log2file("Proxy Failed: server problem") 


        else:
            log2file("Ignoring Request from {0} port {1}".format(self.client_address[0], self.client_address[1]))


def log2file(msg):
    global LOG
    
    timestamp = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    LOG.write(timestamp + ": " + str(msg) + "\n")
    LOG.flush()
    return         
        
def New_Worker(server):
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
        
def SIGTERM_Handler(signal, frame):
    print("SIGTERM received, stopping wifi_stat_api")
    server.socket.close()
    #Send_Syslog_Msg(16, 6, 'main(): stopping wifi_stat_api on SIGTERM')
    sys.exit(0)   
        
if __name__ == '__main__': 
   
    #
    #Parse CLI Options
    #
    parser = OptionParser()
    parser.add_option("-c", "--config-file", dest="config_filename", help="Configuration File")
    (options, args) = parser.parse_args()
    if options.config_filename is None:
        CONFIG_FILENAME = "radius.conf"
    else:
        CONFIG_FILENAME = options.config_filename
    #    
    #Load configuration file
    #
    print('Loading config from: ' + CONFIG_FILENAME)
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_FILENAME)
        
        #
        # RADIUS SERVER
        #        
        RADIUS_AUTH_PORT = int(config['radius']["listen_auth_port"])
        RADIUS_ACCT_PORT = int(config['radius']["listen_acct_port"])
        RADIUS_IP = config['radius']["listen_ip"]
        #RADIUS_SECRET = config['radius']["secret"]
        RADIUS_WORKERS = int(config['radius']["workers"])
        RADIUS_DICTIONARY_FILENAME = config['radius']["dictionary_filename"]
        RADIUS_LOG_FILENAME = config['radius']["log_filename"]
        
        radius_rules = config['radius']["rules"]
        radius_actions = config['radius']["actions"]
        radius_servers = config['radius']["servers"]
        radius_clients = config['radius']["clients"]
        radius_users = config['radius']["users"]

        RADIUS_RULES = json.loads(radius_rules)
        RADIUS_ACTIONS = json.loads(radius_actions)   
        RADIUS_SERVERS = json.loads(radius_servers)
        RADIUS_CLIENTS = json.loads(radius_clients)         
        RADIUS_USERS = json.loads(radius_users)
        
        #Open Log File
        LOG = open(RADIUS_LOG_FILENAME, 'w')
        
        #Load Radius Dictionary
        RADIUS_DICT = Radius_Dict()
        RADIUS_DICT.Load(RADIUS_DICTIONARY_FILENAME)

    except Exception as error:
        #Send_Syslog_Msg(16, 2, 'main(): unexpected error occured, stopping stat_api: ' + str(error))
        print('Unexpected error occured while loading config file, stopping: ' + str(error))
        sys.exit(0)    
    
    #    
    #Start the working processes
    #
    try:
    
        # create a single server object -- children will each inherit a copy
        auth_server = socketserver.UDPServer((RADIUS_IP, RADIUS_AUTH_PORT), RadiusHandler)
        acct_server = socketserver.UDPServer((RADIUS_IP, RADIUS_ACCT_PORT), RadiusHandler)
        
        if RADIUS_WORKERS > 0 and os.name != "nt": #use multiprocessing - spawn multiple worker processes, not supported in Windows!
            multiprocessing.freeze_support()

            # create child processes to act as workers
            for i in range(RADIUS_WORKERS-1):
                multiprocessing.Process(target=New_Worker, args=(auth_server,)).start()
        
        if RADIUS_WORKERS > 0 and os.name != "nt": #use multiprocessing - spawn multiple worker processes, not supported in Windows!
            multiprocessing.freeze_support()

            # create child processes to act as workers
            for i in range(RADIUS_WORKERS):
                multiprocessing.Process(target=New_Worker, args=(acct_server,)).start()
        else:
            # Start a thread with the acct server - only used in Windows!
            acct_server_thread = threading.Thread(target=acct_server.serve_forever)
            acct_server_thread.daemon = True
            acct_server_thread.start()
        
        auth_server.serve_forever()
        
    except KeyboardInterrupt:
        print('<Ctrl-C> received, stopping')
        auth_server.socket.close()

        #Send_Syslog_Msg(16, 6, 'main(): stopping stat_api on user request')
        
    except Exception as error:
        #Send_Syslog_Msg(16, 2, 'main(): unexpected error occured, stopping stat_api: ' + str(error))
        print('Unexpected error occured, stopping: ' + str(error))
        sys.exit(0)
