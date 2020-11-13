# Packet unit V1.0
# (C) Christopher Weightman 2020. All rights reserved.

class ICMPPacket: # ICMP packet object with all header elements and data
    
    # get functions
    def getAddress(self):
        return self.address
    def getMessageType(self):
        return self.messageType
    def getCode(self):
        return self.code
    def getChecksum(self):
        return self.checksum
    def getPayload(self):
        return self.payload
    def getTime(self):
        return self.time
    def getPacketAsList(self):
        return [self.address, self.messageType, self.code, self.checksum, self.payload, self.time]

    def printPacket(self):
        return ('ICMP Packet ' + str(self.address) + ' - Message type: ' + str(self.messageType) + ' Code: ' + str(self.code)) # returns packet data in printable format

    def __init__(self, add, msgType, co, chksm, payld, ti): # take required elements for a ICMP packet as parameters
        
        global address, messageType, code, checksum, payload, time
        # load parameters into object
        self.address = add
        self.messageType = msgType 
        self.code = co
        self.checksum = chksm
        self.payload = payld
        self.time = ti

class TCPPacket: # TCP packet object with all header elements and data

    # get functions
    def getAddress(self):
        return self.address    
    def getSourcePort(self):
        return self.sourcePort   
    def getDestinationPort(self):
        return self.destinationPort
    def getSequenceNum(self):
        return self.sequenceNum  
    def getAcknowledgementNum(self):
        return self.acknowledgementNum  
    def getFlagURG(self):
        return self.flagURG   
    def getFlagACK(self):
        return self.flagACK   
    def getFlagPSH(self):
        return self.flagPSH
    def getFlagRST(self):
        return self.flagRST  
    def getFlagSYN(self):
        return self.flagSYN  
    def getFlagFIN(self):
        return self.flagFIN 
    def getPayload(self):
        return self.payload   
    def getTime(self):
        return self.time   
    def getPacketAsList(self):
        return [self.address, self.sourcePort, self.destinationPort, self.sequenceNum, self.acknowledgementNum, self.flagURG, self.flagACK, self.flagPSH, self.flagRST, self.flagSYN, self.flagFIN, self.payload, self.time]   
    
    def printPacket(self):
        return ('TCP Packet ' + str(self.address) + ' - Source port: ' + str(self.sourcePort) + ' Destination port: ' + str(self.destinationPort) + ' Sequence number: ' + str(self.sequenceNum) + ' Acknowledgement number: ' + str(self.acknowledgementNum) + ' Flags: ' + str(self.flagURG) + str(self.flagACK) + str(self.flagPSH) + str(self.flagRST) + str(self.flagSYN) + str(self.flagFIN)) # returns packet data in printable format
    
    def __init__(self, add, srcPort, destPort, seqNum, ackNum, flURG, flACK, flPSH, flRST, flSYN, flFIN, payld, ti): # take required elements for a TCP packet as parameters
        
        global address, sourcePort, destinationPort, sequenceNum, acknowledgementNum, flagURG, flagACK, flagPSH, flagRST, flagSYN, flagFIN, payload, time
        # load parameters into object
        self.address = add
        self.sourcePort = srcPort
        self.destinationPort = destPort
        self.sequenceNum = seqNum
        self.acknowledgementNum = ackNum
        self.flagURG = flURG
        self.flagACK = flACK
        self.flagPSH = flPSH
        self.flagRST = flRST
        self.flagSYN = flSYN
        self.flagFIN = flFIN
        self.payload = payld
        self.time = ti

class UDPPacket: # UDP packet object with all header elements and data

    def getAddress(self):
        return self.address    
    def getSourcePort(self):
        return self.sourcePort    
    def getDestinationPort(self):
        return self.destinationPort
    def getSize(self):
        return self.size
    def getPayload(self):
        return self.payload    
    def getTime(self):
        return self.time
    def getPacketAsList(self):
        return [self.address, self.sourcePort, self.destinationPort, self.size, self.payload, self.time]
        
    def printPacket(self):
        return ('UDP Packet from ' , self.address , ' - Source port: ' , self.sourcePort, ' Destination port: ' , self.destinationPort, ' Size:  ', self.size) # returns packet data in printable format
        
    def __init__(self, add, srcPort, destPort, sz, payld, ti): # take required elements for a UDP packet as parameters
        
        global address, sourcePort, destinationPort, size, payload, time
        # load parameters into object
        self.address = add
        self.sourcePort = srcPort
        self.destinationPort = destPort
        self.size = sz
        self.payload = payld
        self.time = ti