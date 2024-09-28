class Circuit:
    entries = {}
    def __init__(self, circID):
        # if the OR doesn't have a connection with the other node, the circID must be 0
        if circID!=0:
            return False
        entries = {"0": {}} # Initialize the 1st circID without an outgoing connection

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

