import time
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def generate_key():
    key = ECC.generate(curve='p-256')
    return key


class transaction:
    def __init__(self, from_address, to_address, amount):
        self.from_address = from_address
        self.to_address = to_address
        self.amount = amount
        self.timestamp = time.time()

    # Calculate the hash of the transaction.
    def calculate_hash(self):
        message = str(self.from_address) + str(self.to_address) + \
            str(self.amount) + str(self.timestamp)
        return hashlib.sha256(message.encode('utf8')).hexdigest()

    # Sign on the transaction.
    def sign_transaction(self, signing_key):
        # Owners can only trade with their money.
        if signing_key.public_key() != self.from_address:
            return 'You can only trade with your money.'
        signer = DSS.new(signing_key, 'fips-186-3')
        hasher = self.calculate_hash()
        self.sign_obj = signer.sign(hasher)

    # Check whether the transaction is valid.
    def is_valid(self):
        # The transaction is about mining.
        if self.from_address == None:
            return True
        # There is no signature.
        if len(self.sign_obj) == 0:
            return 'Your signature is empty.'
        # Regard the from address as the public key.
        verifer = self.from_address
        hasher = self.calculate_hash()
        # Verify the signature.
        try:
            verifer.verify(hasher, self.sign_obj)
            return True
        except:
            return False


class Block:
    def __init__(self, timestamp, transactions, pre_hash=''):
        self.timestamp = timestamp
        self.transactions = transactions
        self.pre_hash = pre_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    # Calculate the hash
    def calculate_hash(self):
        message = str(self.timestamp) + str(self.transactions) + \
            str(self.pre_hash) + str(nonce)
        return hashlib.sha256(message.encode('utf8')).hexdigest()

    # Get the nonce which makes hash start with several 0 bits.
    def mine(self, difficulty):
        while self.hash[:difficulty] != '0'*difficulty:
            self.nonce += 1

    # Check whether all transactions are valid.
    def valid_transactions(self):
        for tx in self.transactions:
            if not tx.isvalid():
                return False
        return True


class Blockchain:
    def __init__(self):
        self.chain = [self.create_block()]
        self.difficulty = 2
        self.pending_txs = []
        self.reward = 100

    # Create an empty block.
    def create_block(self):
        return Block('2008-11-1', [], '0')

    # Get the last block of the chain.
    def get_latest_block(self):
        length = len(self.chain)
        return self.chain[length-1]

    # Get the block after mining.
    def mine_pending_txs(self, miner_address):
        mine_tx = transaction(None, miner_address, self.reward)
        self.pending_txs.append(mine_tx)
        # Add transactions into the block.
        block = Block(time.time(), self.pending_txs,
                      hash(self.get_latest_block()))
        block.mine(self.difficulty)
        self.chain.append(block)
        self.pending_txs = []

    # Add new transactions into pending_txs.
    def add_transaction(self, transaction):
        if not transaction.is_valid():
            return 'This transaction is invalid.'
        if transaction.amount <= 0:
            return 'The amount of money should be positive.'
        if self.get_balance(transaction.from_address) < transaction.amount:
            return 'You do not have enough money.'
        self.pending_txs.append(transaction)

    # Get the balance of specific address.
    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block:
                # The address of the transaction is the payer.
                if tx.from_adress == address:
                    balance -= tx.amount
                # The address of the transaction is the receiver.
                elif tx.to_adress == address:
                    balance += tx.amount

    # Get all transactions for one address.
    def get_all_transactions(self, address):
        txs = []
        for block in self.chain:
            for tx in block:
                # Append the transaction either the payer or the receiver.
                if tx.from_address == address:
                    txs.append(tx)
                elif tx.to_address == address:
                    txs.append(tx)
