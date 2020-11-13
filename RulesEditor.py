# Rules Editor unit V1.0
# Christopher Weightman 2020. All rights reserved.

import pickle, socket

class RulesEditor:

    def addIPRule(self): # add forbidden IP rule to rules database
        inputValidated = False
        while (inputValidated == False):
            IPToAdd = input('Enter IP to add to forbidden IP list: ') # user inputs forbidden IP
            try: # validate that input IP is a valid IP
                socket.inet_aton(IPToAdd) # socket library employed for validation
                inputValidated = True
            except OSError:
                print ('Invalid input. Please input a valid IP')
        userRules[0].append(IPToAdd) # add to rules database
        waitInput = input('Added IP to blocklist. Press enter to continue...')
        
    def deleteIPRule(self): # delete forbidden IP rule from rules database
        inputValidated = False
        while (inputValidated == False):
            IPToDelete = input('Enter IP to remove from forbidden IP list: ')
            try:
                socket.inet_aton(IPToDelete)
                inputValidated = True
            except OSError:
                print ('Invalid input. Please input a valid IP')
        userRules[0].remove(IPToDelete)
        waitInput = input('Deleted IP from blocklist. Press enter to continue...')
    
    def addPortRule(self): # add forbidden port rule to rules database
        inputValidated = False
        while (inputValidated == False):
            portToAdd = input('Enter a port to add to forbidden ports list: ')
            try: # validation that value entered is an integer and can therefore be a port
                int(portToAdd)
                inputValidated = True
            except ValueError:
                print ('Invalid input. Please input a number')
        userRules[1].append(int(portToAdd))
        waitInput = input('Added port to blocklist. Press enter to continue...')
        
    def deletePortRule(self): # delete forbidden port rule from rules database
        inputValidated = False
        while (inputValidated == False):
            portToDelete = input('Enter a port to delete from forbidden ports list: ')
            try:
                int(portToDelete)
                inputValidated = True
            except ValueError:
                print ('Invalid input. Please input a number')
        userRules[1].remove(int(portToDelete))
        waitInput = input('Deleted port from forbidden ports list. Press enter to continue...')
    
    def addServicesRule(self): # add IP and associated ports rule to rules database
        inputValidated = False
        blockToAdd = [] # list holding IP and associated ports
        while (inputValidated == False):
            IPToAdd = input('Enter IP for service blocking: ')
            try: # validate input IP using socket library
                socket.inet_aton(IPToAdd)
                inputValidated = True
            except OSError:
                print ('Invalid input. Please input a valid IP')
        blockToAdd.append(IPToAdd)
        portsToAdd = None
        while portsToAdd != 'e':
            portInputValidated = False
            while (portInputValidated == False):
                portsToAdd = input('Enter a port to block for this IP (or "e" for exit): ')
                try: # validate input port numbers
                    int(portsToAdd)
                    portInputValidated = True
                except ValueError:
                    if portsToAdd !='e':
                        print ('Invalid input. Please input a number')
                    else:
                        portInputValidated = True    
            if portsToAdd != 'e':
                blockToAdd.append(int(portsToAdd))
        userRules[2].append(blockToAdd)
        waitInput = input('Added IP and ports to blocklist. Press enter to continue...')
                
    def deleteServicesRule(self): # delete IP and associated ports rule from rules database
        inputValidated = False
        IPToDelete = None
        blockToDelete = []
        while (inputValidated == False):
            IPToDelete = input('Enter IP for service blocking deletion: ')
            try:
                socket.inet_aton(IPToDelete)
                inputValidated = True
            except OSError:
                print ('Invalid input. Please input a valid IP')
        blockToDelete.append(IPToDelete)
        portsToDelete = None
        while portsToDelete != 'e':
            portInputValidated = False
            while (portInputValidated == False):
                portsToDelete = input('Enter a port to unblock for this IP (or "e" for exit): ')
                try:
                    int(portsToDelete)
                    portInputValidated = True
                except ValueError:
                    if portsToDelete !='e':
                        print ('Invalid input. Please input a number')
                    else:
                        portInputValidated = True    
            if portsToDelete != 'e':
                blockToDelete.append(int(portsToDelete))
        userRules[2].remove(blockToDelete)
        waitInput = input('Deleted IP and ports from blocklist. Press enter to continue...')
                   
    def addPacketTypeRule(self): # add packet types rule to rules database
        
        if (userRules[3][0] == 1) and  (userRules[3][1] == 1) and (userRules[3][2] == 1): # if all packet types are already set as forbidden
            waitInput = input('All packet types already forbidden! Press enter to continue...')
        else:
            print ('Which packet types should be forbidden?')
            packetTypeInput = '0'
            while packetTypeInput != 'e':
                packetTypeInput = input('Enter type (TCP, UDP, or ICMP) (or "e" for exit): ')
                if (packetTypeInput == 'TCP') or (packetTypeInput == 'UDP') or (packetTypeInput == 'ICMP'):
                    if packetTypeInput == 'TCP':
                        userRules[3][0] = 1 # mark TCP packets as forbidden
                    if packetTypeInput == 'UDP':
                        userRules[3][1] = 1 # mark UDP packets as forbidden
                    if packetTypeInput == 'ICMP':
                        userRules[3][2] = 1 # mark ICMP packets as forbidden
                    waitInput = input('Added packet type to blocklist. Press enter to continue...')
                else:
                    print('Invalid input. Please select from options TCP, UDP, or ICMP')
            
    def deletePacketTypeRule(self): # add packet types rule to rules database
        
        if (userRules[3][0] == 0) and  (userRules[3][1] == 0) and (userRules[3][2] == 0):
            waitInput = input('All packet types already unforbidden! Press enter to continue...')
        else:
            print ('Which packet types should be unforbidden?')
            packetTypeInput = '0'
            while packetTypeInput != 'e':
                packetTypeInput = input('Enter type (TCP, UDP, or ICMP) (or "e" for exit): ')
                if (packetTypeInput == 'TCP') or (packetTypeInput == 'UDP') or (packetTypeInput == 'ICMP'):
                    if packetTypeInput == 'TCP':
                        userRules[3][0] = 0   
                    if packetTypeInput == 'UDP':
                        userRules[3][1] = 0
                    if packetTypeInput == 'ICMP':
                        userRules[3][2] = 0   
                    waitInput = input('Deleted packet type from blocklist. Press enter to continue...')
                else:
                    print('Invalid input. Please select from options TCP, UDP, or ICMP')
    
    def viewRules(self):
                       
        # create readable string of all forbidden IPs
        forbiddenIPsString = 'Forbidden IPs: '
        for i in userRules[0]:
            if (i != None) and (userRules[0].index(i) > 1):
                if userRules[0].index(i) == 0:
                    forbiddenIPsString = forbiddenIPsString + str(i)
                else:
                    forbiddenIPsString = forbiddenIPsString + ', ' + str(i)
         
        # create readable string of all forbidden ports 
        forbiddenPortsString = 'Forbidden ports: '
        for i in userRules[1]:
            if (i != None) and (userRules[1].index(i) > 2):
                if userRules[1].index(i) == 0:
                    forbiddenPortsString = forbiddenPortsString + str(i)
                else:
                    forbiddenPortsString = forbiddenPortsString + ', ' + str(i)
        
        # create readable string of all forbidden IP and port combinations
        forbiddenSpecificServicesString = 'Forbidden IPs and services: '
        for i in userRules[2]:
            if (i != None) and (userRules[2].index(i) > 1):
                if userRules[2].index(i) == 0:
                    forbiddenSpecificServicesString = forbiddenSpecificServicesString + str(i)
                else:
                    forbiddenSpecificServicesString = forbiddenSpecificServicesString +  ', ' + str(i)
        
        # create readable string of all forbidden packet types
        forbiddenPacketTypesString = 'Forbidden packet types: '
        if userRules[3][0] == 1:
            forbiddenPacketTypesString = forbiddenPacketTypesString + 'TCP' + ' '
        if userRules[3][1] == 1:
            forbiddenPacketTypesString = forbiddenPacketTypesString + 'UDP' + ' '
        if userRules[3][2] == 1:
            forbiddenPacketTypesString = forbiddenPacketTypesString + 'ICMP' + ' '
         
        # print all strings displaying rules from custom rules database 
        print(forbiddenIPsString)
        print(forbiddenPortsString)
        print(forbiddenSpecificServicesString)
        print(forbiddenPacketTypesString)
        print()
        waitInput = input('Press enter to continue...')


    def main(self):
    
        userInput = None
        while userInput != 'e':
            
            print () # print main menu
            print('Intrustion Detection System Rule Editing Platform')
            print('---------------------------')
            print('Please select from the following options:')
            print('1. View Rules')
            print('2. Add Rule')
            print('3. Delete Rule')
            print('e. Exit program')
            print()
            
            userInput = input('Option number: ')
               
            if userInput == '1':
                self.viewRules()
            
            elif (userInput == '2') or (userInput == '3'):

                print ('Please select the type of rule:')
                print ('1. IP Rule')
                print ('2. Port Rule')
                print ('3. IP and Port Rule')
                print ('4. Packet Type Rule')
                userRuleInput = input('Option number: ')
                print ()

                if userInput == '2':
                    if userRuleInput == '1':
                        self.addIPRule()
                    if userRuleInput == '2':
                        self.addPortRule()
                    if userRuleInput == '3':
                        self.addServicesRule()
                    if userRuleInput == '4':
                        self.addPacketTypeRule()
                    
                elif userInput == '3':
                    if userRuleInput == '1':
                        self.deleteIPRule()
                    if userRuleInput == '2':
                        self.deletePortRule()
                    if userRuleInput == '3':
                        self.deleteServicesRule()
                    if userRuleInput == '4':
                        self.deletePacketTypeRule()
                                     
                rulesFile = open('rules.data', 'wb')
                pickle.dump(userRules, rulesFile)
                rulesFile.close()
                        
            elif userInput == 'e':
                pass
                
            else:
                print('Invalid input. Please select from options 1, 2, 3, or 4')
               
    def __init__(self):
            
        global userRules
        rulesFile = open('rules.data', 'rb') # load rules database file
        userRules = pickle.load(rulesFile) # load rules database into userRules list
        rulesFile.close()