# Main Menu unit V1.0
# Christopher Weightman 2020. All rights reserved.

from IntrusionDetectionSystem import *
from UserInterface import *
from TestingUnit import *
from RulesEditor import *
from Packet import *

def runMainProgram(): # run main IDS
    
    idsOptions = [False, None] # start IDS in non-testing mode
    gui = UserInterface()
    ids = IntrusionDetectionSystem()
     
    gui.populateInterface(ids.mainFunction(idsOptions)) # run one loop of program functions to initialise interface
    
    while not gui.checkIfClosedInterface():
        gui.populateInterface(ids.mainFunction(idsOptions)) # perform main IDS functions in loop
    
def runRulesEditor(): # run rules editor unit
    
    rulesEditor = RulesEditor() # run rules editing subprogram
    rulesEditor.main()
    
def runTestingMode():
    
    testing = TestingUnit() # run testing unit
    testing.main()
    
print () # print out options menu
print ()
print('Intrustion Detection System')
print('---------------------------')
print('Please select from the following options:')
print('1. Start Intrusion Detection System')
print('2. Launch Testing Mode')
print('3. Launch Rules Editor')
print('e. Quit program')

userInput = None

while (userInput != '1') and (userInput != '2') and (userInput != '3') and (userInput != 'e'): # accepts correct input from user
    userInput = input('Option: ')

if userInput == '1':
    runMainProgram()
elif userInput == '2':
    runTestingMode()
elif userInput == '3':
    runRulesEditor()