import hashlib
import time
import rsa


def SHA256(cnt):
    return hashlib.sha256(str(cnt).encode('utf-8')).hexdigest()


class Transaction:
    def __init__(self, fromAddress, toAddress, amount):
        self.fromAddress = fromAddress
        self.toAddress = toAddress
        self.amount = amount
        self.signature = ''

    def txnForHash(self):
        return (str(self.fromAddress) + str(self.toAddress) + str(self.amount))

    def signTransaction(self, signingKeyPair):
        if signingKeyPair[1] != self.fromAddress:
            return 'You cannot sign transactions for other wallet'
        self.signature = rsa.sign(
            self.txnForHash(), signingKeyPair[0], 'SHA-256')

    def isValid(self):
        if self.fromAddress == None:
            return True
        if len(self.signature) == 0:
            return 'No signature in this transaction'
        try:
            rsa.verify(self.txnForHash().encode('utf-8'), signature, pubkey)
            return True
        except:
            return False


class Block:
    def __init__(self, timestamp, transactions, prevhash='', nonce=0):
        self.timestamp = timestamp
        self.transactions = transactions
        self.prevhash = prevhash
        self.nonce = nonce
        self.hash = self.calculateHash()

    def calculateHash(self):
        return str(SHA256(str(self.prevhash) + str(self.timestamp) + str(self.transactions) + str(self.nonce)))

    def __str__(self):
        attr = 'timestamp:' + str(self.timestamp) + ' | ' +\
               'transactions:' + str(self.transactions) + ' | ' +\
               'prevhash:' + str(self.prevhash) + ' | ' +\
               'hash:' + str(self.hash) + ' | ' +\
               'nonce:' + str(self.nonce)
        return attr

    def mineBlock(self, difficulty):
        wanted = '0' * difficulty
        while not self.calculateHash().startswith(wanted):
            self.nonce += 1
            self.hash = self.calculateHash()
        print('Block mined:', self.hash)

    def hasValidTransactions(self):
        for item in self.transactions:
            if not item.isValid():
                return False
        return True


class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = [self.initialBlock()]
        self.difficulty = difficulty
        self.pendingTransactions = []
        self.miningReward = 50

    def initialBlock(self):
        return Block('05/28/2020', [Transaction(None, myWalletAddress, 100)], '')

    def getLength(self):
        return len(self.chain)

    def getLatestBlock(self):
        return self.chain[self.getLength()-1]

    def minePendingTransactions(self, miningRewardAddress):
        block = Block(time.localtime(), self.pendingTransactions,
                      self.getLatestBlock().hash)
        block.mineBlock(self.difficulty)
        print('Block successfully mined!')
        self.chain.append(block)
        self.pendingTransactions = [Transaction(
            None, miningRewardAddress, self.miningReward)]

    def addTransaction(self, txn):
        if not (txn.fromAddress and txn.toAddress and txn.isValid()):
            return False
        self.pendingTransactions.append(txn)

    def getBalanceOfAddress(self, address):
        balance = 0
        for item in self.chain:
            for txn in item.transactions:
                if txn.fromAddress == address:
                    balance -= txn.amount
                if txn.toAddress == address:
                    balance += txn.amount
        return balance

    def isChainValid(self):
        for i in range(1, self.getLength()):
            currentBlock = self.chain[i]
            previousBlock = self.chain[i-1]
            if not currentBlock.hasValidTransactions():
                return False
            if currentBlock.hash != currentBlock.calculateHash():
                return False
            if currentBlock.prevhash != previousBlock.hash:
                return False
        return True
