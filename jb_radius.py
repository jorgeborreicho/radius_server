import struct
import binascii
import socket 
import hashlib
import random
import datetime


#--------------------------------------------------------
#   USEFUL FUNCTIONS
#--------------------------------------------------------

def mac2str(mac_bytes):
    mac_addr = struct.unpack("!BBBBBB",mac_bytes)
    return str(hex(mac_addr[0]))[2:] + ":" + str(hex(mac_addr[1]))[2:] + ":" + str(hex(mac_addr[2]))[2:] + ":" + str(hex(mac_addr[3])) [2:]+ ":" + str(hex(mac_addr[4]))[2:] + ":" + str(hex(mac_addr[5]))[2:]

def str2mac(mac_str):
    s_octet = mac_str.split(':')
    mac_addr = struct.pack('!BBBBBB',int(s_octet[0]),int(s_octet[1]),int(s_octet[2]),int(s_octet[3]),int(s_octet[4]),int(s_octet[5]))
    return mac_addr
    
def ip2str(ip_bytes):
    ip_addr = struct.unpack("!BBBB",ip_bytes)
    return str(int(ip_addr[0])) + "." + str(int(ip_addr[1])) + "." + str(int(ip_addr[2])) + "." + str(int(ip_addr[3]))

def str2ip(ip_str):
    s_octet = ip_str.split('.')
    ip_addr = struct.pack('!BBBB',int(s_octet[0]),int(s_octet[1]),int(s_octet[2]),int(s_octet[3]))
    return ip_addr
    
def dec2mask(dec):
    auxbit = 1
    mask = 0
    for i in range(dec):
        mask = mask | auxbit << (31 - i)

    return ip2str(struct.pack("!I",mask))

def subnet_address(ip_str, mask_str):
    ip_octet = ip_str.split('.')
    mask_octet = mask_str.split('.')
    
    subnet_addr = struct.pack('!BBBB',int(ip_octet[0]) & int(mask_octet[0]),int(ip_octet[1]) & int(mask_octet[1]),int(ip_octet[2]) & int(mask_octet[2]),int(ip_octet[3]) & int(mask_octet[3]))
    
    return ip2str(subnet_addr)


    
#--------------------------------------------------------
#   RADIUS PACKET FUNCTIONS
#--------------------------------------------------------

def Radius_User_Password(password, secret, authenticator):
    """
    RFC2865 - Chapter 5.2
    Call the shared secret S and the pseudo-random 128-bit Request
    Authenticator RA.  Break the password into 16-octet chunks p1, p2,
    etc.  with the last one padded at the end with nulls to a 16-octet
    boundary.  Call the ciphertext blocks c(1), c(2), etc.  We'll need
    intermediate values b1, b2, etc.

    b1 = MD5(S + RA)       c(1) = p1 xor b1
    b2 = MD5(S + c(1))     c(2) = p2 xor b2
    .                       .
    .                       .
    .                       .
    bi = MD5(S + c(i-1))   c(i) = pi xor bi

    The String will contain c(1)+c(2)+...+c(i) where + denotes
    concatenation.
    """
    password_length = struct.pack("!B",len(password))
    padd_size = 16 - (len(password) % 16)
    
    try:
        p = password.encode("utf-8")
    except AttributeError:
        p = password
    
    while padd_size > 0:
        p = p + b'\x00'
        padd_size = padd_size - 1
    
    S = secret.encode("utf-8")
    I = authenticator
  
    result = b'' 
    c = I
    while p:
        h = hashlib.md5()
        h.update(S)
        h.update(c)
        b = h.digest()

        for i in range(16):
            result += bytes((b[i] ^ p[i],))

        c = result[-16:]
        p = p[16:]
   
    return result
    
def Radius_User_Password_Decrypt(password, secret, authenticator):

    p = password
    S = secret.encode("utf-8")
    I = authenticator
  
    result = b'' 
    c = I
    while p:
        h = hashlib.md5()
        h.update(S)
        h.update(c)
        b = h.digest()

        for i in range(16):
            result += bytes((b[i] ^ p[i],))

        #c = result[-16:]
        c = p[:16]
        p = p[16:]
        
    try:
        result = (result.split(b'\0',1)[0]).decode("utf-8") #remove trailing \x00's
    except UnicodeDecodeError:
        result = "\n"
    return result


def Cisco_User_Password(password, secret):
    """
    http://www.cisco.com/c/en/us/td/docs/ios/12_2sb/isg/coa/guide/isg_ig/isgcoa3.html#wp1129967
    
    Password Example
    
    The following example shows how to create a valid account logon.
    
    Step 1 
    Construct a plain text version of the string field by concatenating the Data-Length and Password sub-fields:
    â€“If necessary, pad the resulting string until its length (in octets) is an even multiple of 16. We recommend using zero octets (0x00) for padding to obfuscate the password length.
    â€“Prefix the password with its length (raw, not ASCII) and pad to a multiple of 16 bytes; not to an even multiple of 16. In this example, the plain text string is P and the password is web:
    
    P = 0x03 + web (in hex bytes: 03 77 65 62 00 00 00 00 00 00 00 00 00 00 00 00)
    
    Step 2 
    Break the clear text string P into chunks of up to 16-octets each, for example, p1, p2. The last chunk can contain fewer than 16 octets if no padding is used.
    In this example, the shared secret is S, and the pseudo-random 128-bit initiator vector is I.
    S = cisco 
    I = IIIIIIIIIIIIIIII (in hex bytes: 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49) 
    The cipher text blocks are c(1), c(2), and so on. The intermediate values are b1, b2, and so on.
    b1 = MD5 (cisco + IIIIIIIIIIIIIIII) = b4 04 ba b5 24 cb 6d f6 60 5e 21 ae e9 37 9d 26
    
    b1 = MD5 (S + I) c(1) = p1 XOR b1
    
    b2 = MD5 (S + c(1)) c(2) = p2 XOR b2
    
    bi = MD5 (S + c(i-1)) c(i) = pi XOR bi
    
    Step 3 
    The resulting encrypted value will contain c(1)+c(2)+...+c(i) where + denotes concatenation.
    
    c(1) = p1 XOR b1
    p1 03 77 65 62 00 00 00 00 00 00 00 00 00 00 00 00
    XOR
    b1 b4 04 ba b5 24 cb 6d f6 60 5e 21 ae e9 37 9d 26
    -----------------------------------------------
    c(1) = b7 73 df d7 24 cb 6d f6 60 5e 21 ae e9 37 9d 26

    VSA 249 value = 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 b7 73 df d7 24 cb 6d f6 60 5e 21 ae e9 37 9d 26
    """
    password_length = struct.pack("!B",len(password))
    padd_size = 16 - ((len(password) + 1) % 16)

    p = password_length + password.encode("utf-8")
    while padd_size > 0:
        p = p + b'\x00'
        padd_size = padd_size - 1

    S = secret.encode("utf-8")
    I = Create_Radius_Authenticator()

    result = I
    c = I
    while p:
        h = hashlib.md5()
        h.update(S)
        h.update(c)
        b = h.digest()

        for i in range(16):
            result += bytes((b[i] ^ p[i],))

        c = result[-16:]
        p = p[16:]
    
    return result
    
#--------------------------------------------------------
#   RADIUS CLASSES
#--------------------------------------------------------    

class Radius_Dict():
    def Load(self, filename):
        
        self.command_by_name = dict()
        self.command_by_code = dict()
        self.avp_by_name = dict()
        self.avp_by_code = dict()
        
        #Open and parse Radius Dictionary File
        timestamp = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print(timestamp + " - Loading Radius Dictionary File: " + filename + "\n")
    
        with open(filename) as f:
            lines = f.readlines()
        
        for line in lines:
            aux = line.split('\n') # remove "\n"
            line = aux[0]
            #print(line)
            aux = line.split(" ")
            if aux[0] == 'P':
                self.command_by_name[aux[2]]=int(aux[1])
                self.command_by_code[int(aux[1])]=aux[2]
            elif aux[0] == 'A':
                self.avp_by_name[aux[3]]={"code":int(aux[2]),"vendor":int(aux[1]),"name":aux[3],"type":aux[4]}
                self.avp_by_code[str(aux[1]) + "-" + str(aux[2])]={"code":int(aux[2]),"vendor":int(aux[1]),"name":aux[3],"type":aux[4]}
               
    def Get_Command_Code(self, command_name):
        try:
            r = self.command_by_name[command_name]
        except KeyError:
            r = -1
        return r
    def Get_Command_Name(self, command_code):
        try:
            r = self.command_by_code[command_code]        
        except KeyError:
            r = "Unknown Command"
        return r
    def Get_AVP_Code(self, avp_name):
        try:
            r = self.avp_by_name[avp_name]["code"]
        except KeyError:
            r = -1
        return r
    def Get_AVP_Name(self, avp_code):
        try:
            r = self.avp_by_code[avp_code]["name"]
        except KeyError:
            r = "Unknown AVP"
        return r
    def Get_AVP_Vendor(self, avp_name):
        try:        
            r = self.avp_by_name[avp_name]["vendor"]
        except KeyError:
            r = -1
        return r
    def Get_AVP_Type(self, avp_name):
        try:
            r = self.avp_by_name[avp_name]["type"]
        except KeyError:
            r = -1
        return r

class Radius_Packet():
    def __init__(self, dictionary, secret):
        
        self.packet = bytearray() #the whole packet
        self.secret = secret
        self.id = random.randrange(0, 256)
        self.decoded_packet = [] #used on receiver end
        self.attributes = bytearray() #the atrributes part of packet
        self.dictionary = dictionary 
        
        #Generate an Authenticator
        auth = []
        for i in range(16):
            auth.append(random.randrange(0, 256))
        self.authenticator = bytes(auth)  

        
    def Add_AVP(self, name, content):
        avp = b""
        twobyte_dict = [8164]
        
        vendor_id = self.dictionary.Get_AVP_Vendor(name)
        code = self.dictionary.Get_AVP_Code(name)
        content_type = self.dictionary.Get_AVP_Type(name)
        
        if content_type == "integer":
            content = struct.pack('!I', int(content))
        elif content_type == "integer8":
            content = struct.pack('!B', int(content))
        elif content_type == "string" or content_type == "tagged-string":
            content = content.encode('utf-8')
        elif content_type == "ipaddr":
            content = str2ip(content)
        elif content_type == "password":
            content = Radius_User_Password(content, self.secret, self.authenticator)
        else:
            pass
            
        if vendor_id == 0 and type(content) ==  type(b""):
            length=len(content)+2
            avp += struct.pack('!B', code) #code
            avp += struct.pack('!B', length)#length
            avp += content
            
                  
        elif vendor_id in twobyte_dict and type(content) ==  type(b""):
            length=len(content)+2+4+4
            avp += struct.pack('!B', 26) #code
            avp += struct.pack('!B', length) #length
            length=len(content)+4
            avp += struct.pack('!I', vendor_id)
            avp += struct.pack('!H', code)
            avp += struct.pack('!H', length)
            avp +=  content
            
        elif type(content) ==  type(b""):
            length=len(content)+2+4+2
            avp += struct.pack('!B', 26) #code
            avp += struct.pack('!B', length) #length
            length=len(content)+2
            avp += struct.pack('!I', vendor_id)
            avp += struct.pack('!B', code)
            avp += struct.pack('!B', length)
            avp +=  content
            

        self.attributes += avp
            
        return
        
         
    def Add_Header(self, command):
    
        code = self.dictionary.Get_Command_Code(command)
        
        self.packet += struct.pack('!B', code)
        self.packet += struct.pack('!B', self.id)
        self.packet += struct.pack('!h', len(self.attributes) + 20)
        self.packet += struct.pack('!QQ', 0, 0)
        self.packet += self.attributes
        
        if code == 1:#Access-Request
            #Notice that in Access-Request the Authenticator is a random number used to encrypt password 
            struct.pack_into('!16s', self.packet, 4, self.authenticator)       
            
        elif code in [2, 3, 5, 11]:
            #Notice that in Access-Accept, Access-Reject, Accounting-Response, Access-Challenge
            #the request authenticator is used like so MD5(code+id+len+<request autenticator>+attributes+secret)
                  
            struct.pack_into('!16s', self.packet, 4, self.authenticator)
            hash = hashlib.md5()
            hash.update(self.packet+self.secret.encode("utf-8"))
            struct.pack_into('!16s', self.packet, 4, hash.digest())
            
        else:
            #Notice that in Accounting, CoA and Disconnect the Authenticator is calculated
            #using MD5(code+id+len+<autenticator with zeros>+attributes+secret)
            hash = hashlib.md5()
            hash.update(self.packet+self.secret.encode("utf-8"))
            struct.pack_into('!16s', self.packet, 4, hash.digest())
            
        return self.packet

    
    def Packet(self):
        return self.packet
            
    def Radius_Decode(self, packet_data):
        twobyte_dict = [8164]
        code, id, length = struct.unpack("!BBH", packet_data[0:4])
        authenticator = packet_data[4:20]
        pointer = 20
        
        avp_list = []


        while pointer < length:
            avp_code, avp_length = struct.unpack("!BB", packet_data[pointer:pointer+2])
            
            if avp_code == 26:
                avp_vendor_id = struct.unpack("!I", packet_data[pointer+2:pointer+6])[0]
                
                if avp_vendor_id in twobyte_dict:
                    avp_code, avp_length2 = struct.unpack("!HH", packet_data[pointer+6:pointer+10])
                    avp_value = packet_data[pointer+10:pointer+10+avp_length2-2]
                
                    avp_name = self.dictionary.Get_AVP_Name(str(avp_vendor_id) + "-" + str(avp_code))
                    avp_type = self.dictionary.Get_AVP_Type(avp_name)
                    avp_value = self.Radius_AVP_Value_Unpack(avp_value, avp_type)

                    avp_list.append({"name": avp_name, "vendor_id": avp_vendor_id, "code":avp_code, "length":avp_length, "value":avp_value})                
                else:    
                    avp_code, avp_length2 = struct.unpack("!BB", packet_data[pointer+6:pointer+8])
                    avp_value = packet_data[pointer+8:pointer+8+avp_length2-2]
                    
                    avp_name = self.dictionary.Get_AVP_Name(str(avp_vendor_id) + "-" + str(avp_code))
                    avp_type = self.dictionary.Get_AVP_Type(avp_name)
                    avp_value = self.Radius_AVP_Value_Unpack(avp_value, avp_type)
    
                    avp_list.append({"name": avp_name, "vendor_id": avp_vendor_id, "code":avp_code, "length":avp_length, "value":avp_value})
       
            else:
                avp_value = packet_data[pointer+2:pointer+avp_length]
                
                avp_name = self.dictionary.Get_AVP_Name("0-" + str(avp_code))
                avp_type = self.dictionary.Get_AVP_Type(avp_name)
                avp_value = self.Radius_AVP_Value_Unpack(avp_value, avp_type)
                avp_list.append({"name": avp_name, "vendor_id": 0, "code":avp_code, "length":avp_length, "value":avp_value})
    
            pointer = pointer + avp_length
        
        #overwrite id and authenticator to be used in the reply packet
        self.id = id
        self.authenticator = authenticator    
        self.decoded_packet = (length, code, self.dictionary.Get_Command_Name(code), id, authenticator, avp_list)

        return
    
    
    def Radius_AVP_Value_Unpack(self, value, value_type):
    
        if value_type == "integer":
            value = struct.unpack('!I', value)[0]
        elif value_type == "integer8":
            value = struct.unpack('!B', value)[0]
        elif value_type == "string" or value_type == "tagged-string":
            value = value.decode('utf-8')
        elif value_type == "ipaddr":
            value = ip2str(value)
        elif value_type == "password":
            pass
        else:
            pass
        
        return value
        
    def Radius_Authenticator_Generate(self):
        auth = []
        for i in range(4):
            auth.append(random.randrange(0, 256))
        self.authenticator = bytes(auth)
        return self.authenticator
        
        
    def Lookup_Command_Name(self):        
        return self.decoded_packet[2] #self.decoded_packet[2] is command_name
    
    def Lookup_Authenticator(self):        
        return self.decoded_packet[4] #self.decoded_packet[4] is the authenticator
        
    def Lookup_AVP(self, name):        
        for avp in self.decoded_packet[5]: #self.decoded_packet[5] is avp_list
            if avp["name"] == name:
                return avp
        return {}
        
    def Lookup_AVP_Value(self, name):
        avp_list = self.decoded_packet[5]      
        for avp in avp_list: 
            if avp["name"] == name:
                r = avp["value"]
                return r
        return None
    
    def Lookup_AVP_List(self):
        return self.decoded_packet[5]
        
    def Add_AVP_List(self, avp_list, original_secret, original_authenticator):
         
        for avp in avp_list:
            if avp["vendor_id"] == 0: 
                if avp["code"] == 2: #User-Password
                    decrypted = Radius_User_Password_Decrypt(avp["value"], original_secret, original_authenticator)  
                    self.Add_AVP(avp["name"], decrypted)
                else:
                    self.Add_AVP(avp["name"], avp["value"])
            else:
                self.Add_AVP(avp["name"], avp["value"])
       
        return 
        
    def Print(self):
        
        result = "\n"
        result +="    Code: {0} ({1})".format(self.decoded_packet[2],self.decoded_packet[1]) + "\n"
        result +="    Packet Identifier: {0}".format(self.decoded_packet[3])+ "\n"
        result +="    Length: {0}".format(self.decoded_packet[0])+ "\n"
        result +="    Authenticator: {0}".format(self.decoded_packet[4])+ "\n"
        result +="    Attribute Value Pairs:"+ "\n"
        
        avp_list = self.decoded_packet[5]

        for avp in avp_list:
            if avp["vendor_id"] == 0: 
                if avp["code"] == 2: #User-Password
                    decrypted = Radius_User_Password_Decrypt(avp["value"], self.secret, self.authenticator)
                    result +="        {0} ({1}) [Length = {2}] = {3} ({4})".format(avp["name"], avp["code"], avp["length"] , avp["value"], decrypted)+ "\n"
                else:
                    result +="        {0} ({1}) [Length = {2}] = {3}".format(avp["name"], avp["code"], avp["length"] , avp["value"])+ "\n"
            else:
                result +="        {0} (Vendor Id = {1}, {2}) [Length = {3}] = {4}".format(avp["name"], avp["vendor_id"], avp["code"], avp["length"] , avp["value"])+ "\n"
        
        result += "\n"
        return result


