import hashlib, time
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

class transaction:
    def __init__(self, fromAddress, toAddress, amount):
        self.fromAddress = fromAddress
        self.toAddress = toAddress
        self.amount = amount
        self.signature = None
         
    def calculateHash(self):
        return SHA256.new((str(self.fromAddress) + str(self.toAddress) + self.amount).encode())
    
    def signTransaction(self, signingkey):
        if signingkey.public_key() != self.fromAddress:
            raise Exception('You can not sign transactions for other wallet.')

        hasher = self.calculateHash()
        signer = DSS.new(signingkey, 'fips-186-3')
        self.signature = signer.sign(hasher)
    
    def isValid(self):
        if isinstance(self.fromAddress, str):  #系统发放的矿工奖励跳过验证
            return True
        
        if self.signature == None:
            raise Exception('No signature for this transaction.')
        
        try:
            verifer = DSS.new(self.fromAddress, 'fips-186-3')   #使用公钥创建校验对象
            hasher = self.calculateHash()
            verifer.verify(hasher, self.signature)
            # The signnature is valid.
            return True
        except(ValueError, TypeError):
            print('The signature is not valid.')
            return False
     
class Block:
    def __init__(self, timestamp, transaction, previousHash = ''):
        self.timestamp = timestamp
        self.transaction = transaction
        self.previousHash = previousHash
        self.nonce = 0
        self.hash = self.calculateHash()
    
    def calculateHash(self):
        if isinstance(self.transaction, str):
            transaction = self.transaction
        else:
            transaction = [str(i.fromAddress) + str(i.toAddress) + i.amount for i in self.transaction]
        return hashlib.sha256((self.previousHash + self.timestamp + ''.join(transaction) + str(self.nonce)).encode()).hexdigest()
    
    def validateTransactions(self):
        if isinstance(self.transaction, str):
            return True
        for transaction in self.transaction:
            if not transaction.isValid():
                print('invalid transaction found in transactions(发现异常交易)')
                return False
        return True

    def mineBlock(self, difficulty):
        while self.hash[0: difficulty] != '0' * difficulty:
            self.nonce = self.nonce + 1
            self.hash = self.calculateHash()
        
        print('Block mined:', self.hash)

class Blockchain:
    def __init__(self):
        self.chain = [self.createGenesisBlock()]
        self.difficulty = 2
        self.transactionPool = []
        self.miningReward = 50

    def createGenesisBlock(self):
        return Block( '25/5/2020', 'Genesis Block', '0')
    
    def getLatestBlock(self):
        return self.chain[len(self.chain)-1]
    
    def mineTransactionPool(self, miningRewardAddress):  #发放奖励
        miningRewardTransaction = transaction('system', miningRewardAddress, str(self.miningReward))
        self.transactionPool.append(miningRewardTransaction)
        newblock = Block(str(time.time()), self.transactionPool)
        newblock.previousHash = self.getLatestBlock().hash
        newblock.mineBlock(self.difficulty)
        self.chain.append(newblock)
        self.transactionPool = []
    
    def addtransaction(self, transaction):
        if not transaction.isValid():
            raise Exception('The transaction is invalid')
        self.transactionPool.append(transaction)
        #print('The transaction is valid')
    
    def getBalanceOfAddress(self, address):
        balance = 0
        for index in range(1, len(self.chain)):
            for transaction in self.chain[index].transaction :
                if not isinstance(transaction.fromAddress, str) and transaction.fromAddress == address:
                    balance = balance - float(transaction.amount)
                
                if transaction.toAddress == address:
                    balance = balance + float(transaction.amount)
        return balance
    
    def isChainvalid(self):
        for i in range(1, len(self.chain)):
            currentBlock = self.chain[i]
            previousBlock = self.chain[i - 1]

            for index in range(1, len(self.chain)):
                if not self.chain[index].validateTransactions():
                    return False 

            if currentBlock.hash != currentBlock.calculateHash():
                print('transaction has been modified(数据篡改)')
                return False
            if currentBlock.previousHash != previousBlock.hash:
                print('The blockchain is broken（区块链断裂）')
                return False
        return True
    
CTcoin = Blockchain()

privatekeysender = ECC.generate(curve = 'P-256')  #转账者私钥
publickeysender = privatekeysender.public_key()   #转账者公钥
privatekeyreceiver = ECC.generate(curve = 'P-256')  #收钱人私钥
publickeyreceiver = privatekeyreceiver.public_key() #收钱人公钥

t1 = transaction(publickeysender, publickeyreceiver, '100')
#t2 = transaction(publickeysender, publickeyreceiver, '100')  #尝试不签名
#CTcoin.addtransaction(t2)
t1.signTransaction(privatekeysender)
#t1.signature = bin(10) #尝试篡改签名内容---签名和交易不合法
#t1.amount = '10'   #尝试篡改交易金额----交易不合法

CTcoin.addtransaction(t1)

CTcoin.mineTransactionPool(publickeysender)

print(CTcoin.getBalanceOfAddress(publickeyreceiver))   #收钱人余额
#CTcoin.chain[1].timestamp = '5'  #尝试篡改区块上的时间戳---区块链发现数据篡改
#CTcoin.isChainvalid()

#CTcoin.chain[1].timestamp = '5'
#CTcoin.chain[1].hash = CTcoin.chain[1].calculateHash() #尝试篡改区块的时间戳和哈希值----区块链断裂
#CTcoin.isChainvalid()

#for block in CTcoin.chain:    #打印出blockchain里的参数
#    print(block.timestamp)
#    print(block.transaction)
#    print(block.previousHash)
#    print(block.hash)
#    print()





