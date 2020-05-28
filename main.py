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
        self.signature = rsa.sign(self.txnForHash(), signingKeyPair[0], 'SHA-256')

    def isValid(self):
        if self.fromAddress == None:
            return True
        if len(self.signature) == 0:
            return 'No signature in this transaction'
        try:
            rsa.verify(self.txnForHash().encode('utf-8'), signature, self.fromAddress)
            return True
        except:
            return False

    def reveal(self):
        attr = str(self.fromAddress) + '->' + str(self.toAddress) + ':' + str(self.amount)
        return attr


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
        reveal = ''
        for item in self.transactions:
            reveal += item.reveal() + '  '
        attr = 'timestamp:' + str(self.timestamp) + ' | ' +\
               'transactions:' + reveal + ' | ' +\
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
        block = Block(time.localtime(), self.pendingTransactions, self.getLatestBlock().hash)
        block.mineBlock(self.difficulty)
        print('Block successfully mined!')
        self.chain.append(block)
        self.pendingTransactions = [Transaction(None, miningRewardAddress, self.miningReward)]

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




# Create my keys
keyPair = rsa.newkeys(512)
myKey = keyPair[1]
myWalletAddress = keyPair[0]

# Create the Blockchain platform
Platform = Blockchain()

# Prompt user to enter transactions or start the miner
work = True
while work:
    dowhat = input('Please enter the things you want to do: enter "mine" for mining, enter "esc" for exit, others for adding transactions> ')
    if dowhat == 'esc':
        work = False
    elif dowhat == 'mine':
        miner = input('Please choose the miner, enter nothing for default (myWallet)> ')
        print('Starting the miner...')
        if not miner:
            miner = myWalletAddress
        Platform.minePendingTransactions(miner)
        print('Is the current chain valid?', Platform.isChainValid())
        print('Balance of myWallet is:', Platform.getBalanceOfAddress(myWalletAddress))
        print('Balance of address0 is:', Platform.getBalanceOfAddress('address0'))
    else:
        print('Then add a transaction to the pool...')
        fAd = input('Please enter the fromAddress, enter nothing for default (myWallet)> ')
        if not fAd:
            fAd = myWalletAddress
        tAd = input('Please enter the toAddress, enter nothing for default (myWallet)> ')
        if not tAd:
            tAd = myWalletAddress
        while True:
            amount = input('Please enter the amount of transaction> ')
            try:
                amount = float(amount)
                break
            except:
                pass
        pubKey = input('Please enter your public key, enter nothing for default (myKey)> ')
        if not pubKey:
            pubKey = myKey
        privKey = input('Please enter your private key, enter nothing for default (myWallet)> ')
        if not privKey:
            privKey = myWalletAddress
        txn = Transaction(fAd, tAd, amount)
        txn.signTransaction((privKey, pubKey))
        Platform.addTransaction(txn)

for block in Platform.chain:
    print(block.__str__())
