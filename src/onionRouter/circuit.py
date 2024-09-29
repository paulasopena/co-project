class Circuit:
    # An entry wil look something like:
    # {"circID": {"addr": outgoingAddr, "outgoingCircID": outgoingCircID}}
    entries = {}
    def __init__(self, circID):
        self.entries = {circID: {}} # Initialize the 1st circID without an outgoing connection

    # Add an outgoing connection to a circID
    def addOutgoingConnection(self, addr, incomingCircID, outgoingCircID):
        if incomingCircID not in entries:
            return False
        entries[incomingCircID]={"addr":addr,"outgoingCircID":outgoingCircID}
        return True

    # Finds the smallest circID available
    def findAvailableCircID(self):
        # 2 bytes -> 16bits -> 2**16 numbers
        for i in range(0,2**16):
            if i not in entries:
                return i
        # In case all circID's are taken
        return -1
    
    # Create new entry
    def addNewEntry(self,circID):
        if int(circID)>=2**16 or circID in self.entries:
            return False
        self.entries[circID] = {} 
        return True

