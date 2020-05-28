import time
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256


def generate_key():
    key = ECC.generate(curve='P-256')
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
        return SHA256.new(message.encode())

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
        if self.from_address is None:
            return True
        # There is no signature.
        if self.sign_obj == None:
            return 'Your signature is empty.'
        # Regard the from address as the public key.
        verifer = DSS.new(self.from_address, 'fips-186-3')
        hasher = self.calculate_hash()
        # Verify the signature.
        try:
            verifer.verify(hasher, self.sign_obj)
            return True
        except:
            print('Someone tampers the signature.')
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
        transactions = [str(tx.from_address)+str(tx.to_address) +
                        str(tx.amount)+str(tx.timestamp) for tx in self.transactions]
        message = str(self.timestamp) + str(transactions) + \
            str(self.pre_hash) + str(self.nonce)
        return hashlib.sha256(message.encode()).hexdigest()

    # Get the nonce which makes hash start with several 0 bits.
    def mine(self, difficulty):
        while self.hash[:difficulty] != '0'*difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

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
        self.reward = 50

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
                      self.get_latest_block().hash)
        block.mine(self.difficulty)
        self.chain.append(block)
        self.pending_txs = []

    # Add new transactions into pending_txs.
    def add_transaction(self, transaction):
        if not transaction.is_valid():
            return 'This transaction is invalid.'
        if transaction.amount <= 0:
            return 'The amount of money should be positive.'
        # if self.get_balance(transaction.from_address) < transaction.amount:
        #     return 'You do not have enough money.'
        self.pending_txs.append(transaction)

    # Get the balance of specific address.
    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                # The address of the transaction is the payer.
                if tx.from_address is address:
                    balance -= tx.amount
                # The address of the transaction is the receiver.
                elif tx.to_address is address:
                    balance += tx.amount
        return balance

    # Get all transactions for one address.
    def get_all_transactions(self, address):
        txs = []
        for block in self.chain:
            for tx in block.transactions:
                # Append the transaction either the payer or the receiver.
                if tx.from_address is address:
                    txs.append(tx)
                elif tx.to_address is address:
                    txs.append(tx)


def main():
    # Generate keys for payer and receiver.
    payer_prikey = generate_key()
    payer_pubkey = payer_prikey.public_key()
    receiver_prikey = generate_key()
    receiver_pubkey = receiver_prikey.public_key()
    # Simulate the transaction.
    bitCoin = Blockchain()
    tx = transaction(payer_pubkey, receiver_pubkey, 10)
    tx.sign_transaction(payer_prikey)
    bitCoin.add_transaction(tx)
    # Mine transactions.
    bitCoin.mine_pending_txs(payer_pubkey)
    payer_balance = bitCoin.get_balance(payer_pubkey)
    print('The payer has:',payer_balance)
    receiver_balance = bitCoin.get_balance(receiver_pubkey)
    print('The receiver has:',receiver_balance)


main()
    