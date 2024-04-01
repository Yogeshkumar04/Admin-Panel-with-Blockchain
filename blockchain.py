import hashlib
import json
from time import time
from ecdsa import SigningKey, NIST384p, VerifyingKey

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        """
        A function that returns the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()  # Load the existing blockchain
        if not self.chain:  # If loading failed, create the genesis block
            self.create_genesis_block()
        self.pending_transactions = []
        
    def to_dict(self):
        """
        Convert the entire blockchain into a list of dictionaries.
        Useful for JSON serialization and for viewing the blockchain in a readable format.
        """
        chain_data = []
        for block in self.chain:
            chain_dict = {
                'index': block.index,
                'transactions': block.transactions,
                'timestamp': block.timestamp,
                'previous_hash': block.previous_hash,
                'hash': block.hash
            }
            chain_data.append(chain_dict)
        return chain_data

    def last_block(self):
        """
        Returns the last block in the chain. Useful for quickly accessing the most recent block.
        """
        return self.chain[-1]
    
    def create_genesis_block(self):
        """
        A function to generate the genesis block and append it to the chain.
        The block has index 0, previous_hash as 0, and a valid hash.
        """
        genesis_block = Block(0, [], time(), "0")
        self.chain.append(genesis_block)
        
      
    def add_block(self, block):
        """
        A function that adds the block to the chain after verification.
        Verification includes checking that the previous_hash referred in the block matches the hash of the latest block.
        """
        if self.chain[-1].hash == block.previous_hash:
            self.chain.append(block)
            self.save_chain()  # Save the blockchain every time a new block is added
            return True
        return False
    
    def save_chain(self):
        """
        Serializes the entire blockchain into JSON and saves it to a file.
        """
        chain_data = self.to_dict()  # Convert blockchain to a dictionary
        with open('blockchain_data.json', 'w') as f:
            json.dump(chain_data, f, indent=4)
            
            
    def load_chain(self):
        """
        Loads the blockchain from a file and deserializes it.
        """
        try:
            with open('blockchain_data.json', 'r') as f:
                chain_data = json.load(f)
                self.chain = [Block(block['index'],
                                    block['transactions'],
                                    block['timestamp'],
                                    block['previous_hash']) for block in chain_data]
        except (IOError, json.JSONDecodeError) as e:
            print(f"Unable to load blockchain from file: {e}")
            
            

    def add_new_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine(self):
        """
        A function that acts as a mining simulator.
        Here, for simplicity, we'll assume that mining simply involves creating a new block with pending transactions.
        """
        if not self.pending_transactions:
            return False

        last_block = self.chain[-1]
        new_block = Block(index=last_block.index + 1,
                          transactions=self.pending_transactions,
                          timestamp=time(),
                          previous_hash=last_block.hash)
        self.add_block(new_block)
        self.pending_transactions = []  # Reset the list of transactions
        return new_block

blockchain = Blockchain()

def generate_keys():
    """
    Generates a private and a public key pair.
    """
    private_key = SigningKey.generate(curve=NIST384p)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

def log_transaction(sender_private_key, sender_public_key, receiver, amount):
    """
    Logs a transaction with a signature.
    """
    transaction = {
        'sender': sender_public_key.to_string().hex(),
        'receiver': receiver,
        'amount': amount,
        'timestamp': time()
    }
    transaction_string = json.dumps(transaction, sort_keys=True)
    signature = sender_private_key.sign(transaction_string.encode())
    transaction['signature'] = signature.hex()  # Store the signature in hex format
    blockchain.add_new_transaction(transaction)
    return blockchain.mine()

def verify_transaction(transaction):
    """
    Verifies the transaction signature.
    """
    signature = bytes.fromhex(transaction['signature'])
    public_key_string = transaction['sender']
    public_key = VerifyingKey.from_string(bytes.fromhex(public_key_string), curve=NIST384p)
    transaction_data = {key: transaction[key] for key in transaction if key != 'signature'}
    transaction_string = json.dumps(transaction_data, sort_keys=True)
    return public_key.verify(signature, transaction_string.encode())
