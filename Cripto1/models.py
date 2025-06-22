from django.db import models
from django.contrib.auth.models import User
import hashlib
import time
import json
from encrypted_model_fields.fields import EncryptedTextField
from django.core.validators import FileExtensionValidator

# Import for cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.exceptions import InvalidSignature

class Block(models.Model):
    index = models.IntegerField(unique=True)
    timestamp = models.FloatField()
    proof = models.CharField(max_length=255)
    previous_hash = models.CharField(max_length=255)
    hash = models.CharField(max_length=255)
    nonce = models.CharField(max_length=255)
    merkle_root = models.CharField(max_length=255)
    difficulty = models.FloatField(default=4.0, null=True, blank=True)

    def __str__(self):
        return f"Block #{self.index}"

    class Meta:
        ordering = ['index']

class Transaction(models.Model):
    TRANSACTION_TYPES = [
        ('text', 'Text Message'),
        ('file', 'File Upload'),
    ]

    block = models.ForeignKey(Block, on_delete=models.CASCADE, related_name='transactions', null=True, blank=True)
    type = models.CharField(max_length=50, choices=TRANSACTION_TYPES)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_transactions')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_transactions')
    sender_public_key = models.TextField(null=True, blank=True)  # Nuovo campo
    content = models.TextField(blank=True)  # For text messages
    file = models.FileField(upload_to='transaction_files/', null=True, blank=True,
                          validators=[FileExtensionValidator(allowed_extensions=['pdf', 'csv', 'xlsx', 'xls', 'doc', 'docx', 'txt'])])
    timestamp = models.FloatField()
    transaction_hash = models.CharField(max_length=255, unique=True)
    signature = models.TextField(null=True, blank=True)
    is_encrypted = models.BooleanField(default=False)
    original_filename = models.CharField(max_length=255, blank=True, null=True) # Per salvare il nome originale del file cifrato
    encrypted_symmetric_key = models.BinaryField(null=True, blank=True) # Per la chiave simmetrica cifrata del file
    receiver_public_key_at_encryption = models.TextField(null=True, blank=True) # Public key of receiver at the time of encryption
    max_downloads = models.IntegerField(null=True, blank=True, default=None) # Numero massimo di download consentiti
    current_downloads = models.IntegerField(default=0) # Contatore dei download effettuati
    is_viewed = models.BooleanField(default=False) # Indica se la transazione è stata visualizzata dal destinatario

    def __str__(self):
        return f"Transaction {self.transaction_hash[:10]}..."

    def to_dict(self):
        """Returns a dictionary representation of the transaction for signing/hashing."""
        return {
            'type': self.type,
            'sender': self.sender.id,
            'receiver': self.receiver.id,
            'sender_public_key': self.sender_public_key or '',
            'content': self.content,
            'file': str(self.file) if self.file else '',
            'timestamp': self.timestamp,
            'is_encrypted': self.is_encrypted,
            'original_filename': self.original_filename or '', # Include original filename
            'encrypted_symmetric_key': self.encrypted_symmetric_key.hex() if self.encrypted_symmetric_key else '',
            'receiver_public_key_at_encryption': self.receiver_public_key_at_encryption or '',
        }

    def calculate_hash(self):
        """Calculates the SHA-256 hash of the transaction data."""
        transaction_string = json.dumps(self.to_dict(), sort_keys=True).encode()
        print(f"[DEBUG VERIFYING] transaction_dict: {self.to_dict()}")
        print(f"[DEBUG VERIFYING] transaction_string: {transaction_string}")
        return hashlib.sha256(transaction_string).hexdigest()

    def verify_signature(self):
        """Verifies the digital signature of the transaction."""
        if not self.signature:
            print(f"[DEBUG] No signature for transaction {self.transaction_hash}")
            return False

        try:
            # Usa la chiave pubblica salvata nella transazione
            if not self.sender_public_key:
                print(f"[DEBUG] No sender_public_key saved in transaction {self.transaction_hash}")
                return False
            public_key = serialization.load_pem_public_key(
                self.sender_public_key.encode(),
                backend=default_backend()
            )
            
            # Calculate the hash of the transaction data
            tx_dict = self.to_dict()
            print(f"[DEBUG] Transaction dict for verification: {tx_dict}")
            data_to_verify = self.calculate_hash().encode()
            print(f"[DEBUG] Data to verify (hash): {self.calculate_hash()}")
            print(f"[DEBUG] Signature (hex): {self.signature}")
            
            # Verify the signature
            public_key.verify(
                bytes.fromhex(self.signature),
                data_to_verify,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"[DEBUG] Signature valid for transaction {self.transaction_hash}")
            return True
        except Exception as e:
            print(f"Error verifying signature for transaction {self.transaction_hash}: {type(e).__name__}: {e}")
            print(f"[DEBUG] Transaction dict: {self.to_dict()}")
            print(f"[DEBUG] Data to verify (hash): {self.calculate_hash()}")
            print(f"[DEBUG] Signature (hex): {self.signature}")
            return False

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_key = models.CharField(max_length=255, unique=True) # Keep as a unique identifier (can be hash of public key)
    public_key = models.TextField(null=True, blank=True) # Allow null for existing rows
    private_key = EncryptedTextField(null=True, blank=True) # Allow null for existing rows
    balance = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"

    def generate_key_pair(self, password: bytes = b'securepassword'):
        """Genera una nuova coppia di chiavi RSA per l'utente, cifrando la privata con la password fornita."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        )
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key = pem_public_key.decode()
        self.private_key = pem_private_key.decode()
        self.user_key = hashlib.sha256(self.public_key.encode()).hexdigest()
        self.save()

    def decrypt_private_key(self, password=b'securepassword'):
        """Decrypts and returns the user's private key."""
        try:
            private_key = serialization.load_pem_private_key(
                self.private_key.encode(),
                password=password, # Use the password for decryption
                backend=default_backend()
            )
            print(f"DEBUG: Private key decrypted successfully with provided password.")
            return private_key
        except Exception as e:
            print(f"DEBUG: Error decrypting private key with provided password: {e}")
            return None

    @property
    def private_key_hash(self):
        if self.private_key:
            return hashlib.sha256(self.private_key.encode()).hexdigest()
        return None

    def decrypt_message(self, encrypted_hex, password=b'securepassword'):
        """Decripta un messaggio cifrato in hex usando la chiave privata dell'utente."""
        try:
            if not encrypted_hex:
                return ''
            private_key = self.decrypt_private_key(password=password)
            if not private_key:
                return 'Errore: chiave privata non disponibile.'
            
            print(f"DEBUG: Encrypted hex received for decryption: {encrypted_hex}")
            print(f"DEBUG: Length of encrypted hex: {len(encrypted_hex)}")

            from cryptography.hazmat.primitives.asymmetric import padding
            decrypted = private_key.decrypt(
                bytes.fromhex(encrypted_hex),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            return f'Errore nella decriptazione: {str(e)}'

    def decrypt_file_content(self, encrypted_bytes: bytes, password: bytes):
        """Decripta il contenuto di un file (in bytes) usando la chiave privata dell'utente."""
        try:
            private_key = self.decrypt_private_key(password=password)
            if not private_key:
                return None # Or raise an exception

            from cryptography.hazmat.primitives.asymmetric import padding
            decrypted_content = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_content
        except Exception as e:
            print(f"Error decrypting file content: {e}")
            return None

class SmartContract(models.Model):
    name = models.CharField(max_length=255, unique=True)
    code = models.TextField()
    deployer = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    block = models.ForeignKey(Block, on_delete=models.CASCADE, null=True, blank=True) # Allow null for pending contracts
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class BlockchainState(models.Model):
    current_supply = models.FloatField(default=0.0)
    max_supply = models.FloatField(default=210000000.0)
    current_reward = models.FloatField(default=0.05)
    halving_count = models.IntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)
    difficulty = models.FloatField(default=4.0)

    class Meta:
        verbose_name = "Blockchain State"
        verbose_name_plural = "Blockchain States"

    def __str__(self):
        return f"Blockchain State - Supply: {self.current_supply}"
