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
import time
from jb_radius import *

    
if __name__ == '__main__': 

    DESTINATION_IP = "192.168.116.62" # <------- change this to match your radius server IP
    AUTH_PORT = 1812 # <------- change this to match your radius server authentication port
    
    DICTIONARY_FILE = "radius.dict"
    
    RADIUS_DICT = Radius_Dict()
    RADIUS_DICT.Load(DICTIONARY_FILE)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   
    
    #request 1
    radius_packet = Radius_Packet(RADIUS_DICT, "secret")
    radius_packet.Add_AVP("User-Name","jorge@test.pt")
    radius_packet.Add_AVP("User-Password","jorge_password123")
    radius_packet.Add_AVP("Calling-Station-Id","AA:BB:CC:00:00:01")
    radius_packet.Add_AVP("3GPP-IMSI","268090000000001")
    radius_packet.Add_Header("Access-Request")
    
    sock.sendto(radius_packet.Packet(), (DESTINATION_IP, AUTH_PORT))
    time.sleep(1)
    

    #request 2
    radius_packet = Radius_Packet(RADIUS_DICT, "secret")
    radius_packet.Add_AVP("User-Name","john@test.pt")
    radius_packet.Add_AVP("User-Password","john_password123")
    radius_packet.Add_AVP("Calling-Station-Id","AA:BB:CC:00:00:02")
    radius_packet.Add_AVP("3GPP-IMSI","268090000000002")
    radius_packet.Add_Header("Access-Request")
    
    sock.sendto(radius_packet.Packet(), (DESTINATION_IP, AUTH_PORT))
    time.sleep(1)
    
    #request 3
    radius_packet = Radius_Packet(RADIUS_DICT, "secret")
    radius_packet.Add_AVP("User-Name","eva@test.pt")
    radius_packet.Add_AVP("User-Password","eva_password123")
    radius_packet.Add_AVP("Calling-Station-Id","AA:BB:CC:00:00:03")
    radius_packet.Add_AVP("3GPP-IMSI","268090000000003")
    radius_packet.Add_Header("Access-Request")
    
    sock.sendto(radius_packet.Packet(), (DESTINATION_IP, AUTH_PORT))
    time.sleep(1)
    
    #request 4
    radius_packet = Radius_Packet(RADIUS_DICT, "secret")
    radius_packet.Add_AVP("User-Name","mary@test.pt")
    radius_packet.Add_AVP("User-Password","mary_password123")
    radius_packet.Add_AVP("Calling-Station-Id","AA:BB:CC:00:00:04")
    radius_packet.Add_AVP("3GPP-IMSI","268090000000004")
    radius_packet.Add_Header("Access-Request")
    
    sock.sendto(radius_packet.Packet(), (DESTINATION_IP, AUTH_PORT))
    time.sleep(1)
    
    #request 5
    radius_packet = Radius_Packet(RADIUS_DICT, "secret")
    radius_packet.Add_AVP("User-Name","henry@test.pt")
    radius_packet.Add_AVP("User-Password","henry_password123")
    radius_packet.Add_AVP("Calling-Station-Id","AA:BB:CC:00:00:05")
    radius_packet.Add_AVP("3GPP-IMSI","268090000000005")
    radius_packet.Add_Header("Access-Request")
    
    sock.sendto(radius_packet.Packet(), (DESTINATION_IP, AUTH_PORT))
    time.sleep(1)
    
    #request 6
    radius_packet = Radius_Packet(RADIUS_DICT, "secret")
    radius_packet.Add_AVP("User-Name","albert@test.pt")
    radius_packet.Add_AVP("User-Password","albert_password123")
    radius_packet.Add_AVP("Calling-Station-Id","AA:BB:CC:00:00:06")
    radius_packet.Add_AVP("3GPP-IMSI","268090000000006")
    radius_packet.Add_Header("Access-Request")
    
    sock.sendto(radius_packet.Packet(), (DESTINATION_IP, AUTH_PORT))
    
