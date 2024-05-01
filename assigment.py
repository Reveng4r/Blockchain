from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

class SmartContractServer:
    def __init__(self):
        self.smart_contract_data = {}

    def initiate_smart_contract(self, node_a_public_key):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.smart_contract_data[node_a_public_key] = {
            'timestamp': timestamp,
            'encrypted_data': None
        }
        return node_a_public_key + "(Sign, " + timestamp + ")"

    def upload_encrypted_data(self, node_a_public_key, encrypted_data):
        self.smart_contract_data[node_a_public_key]['encrypted_data'] = encrypted_data

    def get_encrypted_data(self, node_a_public_key):
        return self.smart_contract_data[node_a_public_key]['encrypted_data']

class Node:
    def __init__(self, name):
        self.name = name
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        return self.public_key

    def encrypt_data(self, data, public_key):
        return public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_data(self, encrypted_data):
        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

# Scenario
if __name__ == "__main__":
    smart_contract_server = SmartContractServer()
    node_a = Node("Node A")
    node_b = Node("Node B")

    # Node A initiates a smart contract
    contract_data = smart_contract_server.initiate_smart_contract(node_a.get_public_key())

    # Node A sends contract data to Node B
    public_key_data = contract_data  # This would be sent to Node B

    # Node B receives public key data from the contract server
    # and uses it to encrypt the private data
    encrypted_data = node_b.encrypt_data("Private Data", node_a.get_public_key())

    # Node B uploads encrypted data to the contract server
    smart_contract_server.upload_encrypted_data(node_a.get_public_key(), encrypted_data)

    # Node A retrieves encrypted data from the contract server
    encrypted_data_from_server = smart_contract_server.get_encrypted_data(node_a.get_public_key())

    # Node A decrypts the encrypted data
    decrypted_data = node_a.decrypt_data(encrypted_data_from_server)
    print("Decrypted Data by Node A:", decrypted_data.decode())
