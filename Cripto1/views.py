from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from .models import Block, Transaction, UserProfile, SmartContract, BlockchainState, AuditLog, Permission, Role, UserRole
from django.db import transaction, models
import hashlib
import json
import time
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
import datetime
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from django.utils import timezone
import random
from .forms import UserProfileEditForm
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Sum, Q
import csv
import os
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from django.contrib.auth.forms import UserChangeForm, PasswordResetForm
import uuid
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.urls import reverse
from datetime import datetime, timedelta
from django.core.exceptions import PermissionDenied
from django.views.decorators.http import require_POST

cipher_suite = Fernet(settings.FERNET_KEY)

def homepage(request):
    return render(request, 'Cripto1/index.html')

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        private_key_password = request.POST.get('private_key_password')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username già esistente')
            return redirect('register')
            
        user = User.objects.create_user(username=username, email=email, password=password)
        user_profile = UserProfile.objects.create(user=user)
        user_profile.generate_key_pair(password=private_key_password.encode())  # Usa la password scelta
        
        messages.success(request, 'Registrazione completata con successo')
        return redirect('Cripto1:login')
        
    return render(request, 'Cripto1/register.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # Controlla se l'utente esiste e il suo stato
        try:
            user_profile = UserProfile.objects.get(user__username=username)
            
            # Controlla se l'account è attivo
            if not user_profile.is_active:
                messages.error(request, 'Il tuo account è stato disattivato. Contatta l\'amministratore.')
                return render(request, 'Cripto1/login.html')
            
            # Controlla se l'account è bloccato
            if user_profile.is_locked():
                messages.error(request, 'Il tuo account è temporaneamente bloccato. Riprova più tardi.')
                return render(request, 'Cripto1/login.html')
            
        except UserProfile.DoesNotExist:
            # Se non esiste un profilo, continua con l'autenticazione normale
            pass
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Login riuscito
            login(request, user)
            
            # Resetta i tentativi di login e aggiorna le informazioni
            try:
                user_profile = UserProfile.objects.get(user=user)
                user_profile.reset_login_attempts()
                user_profile.update_last_login(request.META.get('REMOTE_ADDR'))
            except UserProfile.DoesNotExist:
                pass
            
            messages.success(request, "Benvenuto! Hai effettuato l'accesso con successo.", extra_tags='welcome_toast')
            return redirect('Cripto1:dashboard')
        else:
            # Login fallito
            try:
                user_profile = UserProfile.objects.get(user__username=username)
                user_profile.increment_login_attempts()
                
                # Log dell'evento di sicurezza
                AuditLog.log_action(
                    action_type='SECURITY_EVENT',
                    description=f'Tentativo di login fallito per utente: {username}',
                    severity='MEDIUM',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=False,
                    error_message='Credenziali non valide'
                )
                
                if user_profile.is_locked():
                    messages.error(request, 'Troppi tentativi di login falliti. Il tuo account è stato temporaneamente bloccato.')
                else:
                    remaining_attempts = 5 - user_profile.login_attempts
                    messages.error(request, f'Credenziali non valide. Tentativi rimanenti: {remaining_attempts}')
                    
            except UserProfile.DoesNotExist:
                messages.error(request, 'Credenziali non valide')
            
    return render(request, 'Cripto1/login.html')

@login_required
def all_transactions_view(request):
    transactions_list = Transaction.objects.filter(
        models.Q(sender=request.user) | 
        models.Q(receiver=request.user)
    ).order_by('-timestamp')

    for tx in transactions_list:
        tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
        # Determine direction for display
        if tx.sender == request.user:
            tx.direction = "Inviata"
        else:
            tx.direction = "Ricevuta"
    
    paginator = Paginator(transactions_list, 10) # Show 10 transactions per page
    page = request.GET.get('page')
    try:
        transactions = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        transactions = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        transactions = paginator.page(paginator.num_pages)

    context = {
        'all_transactions': transactions,
    }
    return render(request, 'Cripto1/all_transactions.html', context)

@login_required
def unviewed_transactions_list(request):
    transactions_list = Transaction.objects.filter(
        receiver=request.user,
        is_viewed=False
    ).order_by('-timestamp')

    for tx in transactions_list:
        tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
        tx.direction = "Ricevuta" # All these transactions are received
    
    paginator = Paginator(transactions_list, 10) # Show 10 transactions per page
    page = request.GET.get('page')
    try:
        transactions = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        transactions = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        transactions = paginator.page(paginator.num_pages)

    context = {
        'unviewed_transactions': transactions,
    }
    return render(request, 'Cripto1/unviewed_transactions.html', context)

@login_required
def dashboard(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    if created or not user_profile.public_key or not user_profile.private_key:
        user_profile.generate_key_pair()

    blockchain_state = BlockchainState.objects.first()
    percentage_mined = 0
    if blockchain_state and blockchain_state.max_supply > 0:
        percentage_mined = (blockchain_state.current_supply / blockchain_state.max_supply) * 100

    # Recupera i blocchi più recenti
    latest_blocks = list(Block.objects.all().order_by('-index')[:10])
    for block in latest_blocks:
        block.timestamp_datetime = datetime.fromtimestamp(block.timestamp, tz=timezone.get_current_timezone())

    # Recupera le transazioni recenti
    user_transactions = []
    transactions_queryset = Transaction.objects.filter(
        models.Q(sender=request.user) | 
        models.Q(receiver=request.user)
    ).order_by('-timestamp')[:10]
    for tx in transactions_queryset:
        tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
        user_transactions.append(tx)

    # Conta le transazioni in sospeso
    pending_count = Transaction.objects.filter(block__isnull=True).count()
    
    # Conta le transazioni ricevute e non ancora visualizzate
    unviewed_received_transactions_count = Transaction.objects.filter(
        receiver=request.user,
        is_viewed=False
    ).count()

    context = {
        'user_profile': user_profile,
        'blockchain_state': blockchain_state,
        'blocks': latest_blocks,
        'transactions': user_transactions,
        'percentage_mined': percentage_mined,
        'pending_count': pending_count,
        'unviewed_received_transactions_count': unviewed_received_transactions_count,
        'create_transaction_url': reverse('Cripto1:create_transaction'),
        'all_transactions_url': reverse('Cripto1:all_transactions'),
    }
    return render(request, 'Cripto1/dashboard.html', context)

def calculate_hash(block_data):
    """Calculate the SHA-256 hash of a block"""
    block_string = json.dumps(block_data, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def proof_of_work(last_proof, difficulty=4):
    """Simple proof of work algorithm with more secure nonce generation"""
    # Generate a random starting point for the nonce
    nonce = random.randint(1000000, 9999999)  # Start with a random 7-digit number
    
    while True:
        # Combine the last proof, nonce, and a timestamp for more randomness
        guess = f"{last_proof}{nonce}{time.time()}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        
        # Check if the hash meets the difficulty requirement
        if guess_hash[:difficulty] == '0' * difficulty:
            return nonce
        
        # Increment nonce by a random amount to make it less predictable
        nonce += random.randint(1, 1000)

@login_required
@csrf_exempt
def create_transaction(request):
    if request.method == 'POST':
        try:
            transaction_type = request.POST.get('type')
            receiver_key = request.POST.get('receiver_key')
            content = request.POST.get('content', '')
            is_encrypted = request.POST.get('is_encrypted', 'false').lower() in ['true', 'on', '1']
            private_key_password = request.POST.get('private_key_password')
            max_downloads_str = request.POST.get('max_downloads')
            max_downloads = int(max_downloads_str) if max_downloads_str and max_downloads_str.isdigit() else None
            
            user_profile = UserProfile.objects.get(user=request.user)
            receiver_profile = UserProfile.objects.filter(user_key=receiver_key).first()
            if not receiver_profile:
                return JsonResponse({'success': False, 'message': 'Receiver not found.'})
            receiver = receiver_profile.user

            # Cifratura del contenuto se richiesto (solo per testo)
            encrypted_content = content
            if is_encrypted and transaction_type == 'text' and content:
                print(f"DEBUG: Original content length before encryption: {len(content.encode())} bytes")
                public_key = serialization.load_pem_public_key(
                    receiver_profile.public_key.encode(),
                    backend=default_backend()
                )
                encrypted_content = public_key.encrypt(
                    content.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).hex()

            # Salva la chiave pubblica del mittente
            sender_public_key = user_profile.public_key

            # Create transaction data
            transaction_data = {
                'type': transaction_type,
                'sender': request.user.id,
                'receiver': receiver.id,
                'sender_public_key': sender_public_key,
                'content': encrypted_content,
                'timestamp': time.time(),
                'is_encrypted': is_encrypted
            }

            # Handle file upload if present
            if transaction_type == 'file' and request.FILES.get('file'):
                file = request.FILES['file']
                file_content = file.read()
                encrypted_symmetric_key_for_db = None

                if is_encrypted:
                    try:
                        # Generate a symmetric key for file encryption
                        symmetric_key = Fernet.generate_key()
                        print(f"DEBUG: Generated symmetric_key type: {type(symmetric_key)}, value: {symmetric_key[:5]}...") # print first few bytes
                        f = Fernet(symmetric_key)
                        encrypted_file_content = f.encrypt(file_content)
                        print(f"DEBUG: File content encrypted with symmetric key. Encrypted length: {len(encrypted_file_content)}")

                        # Encrypt the symmetric key with the receiver's public RSA key
                        print(f"DEBUG: Receiver public key (from DB): {receiver_profile.public_key[:50]}...") # print first 50 chars
                        receiver_public_key = serialization.load_pem_public_key(
                            receiver_profile.public_key.encode(),
                            backend=default_backend()
                        )
                        print(f"DEBUG: Receiver public key loaded successfully.")
                        encrypted_symmetric_key_for_db = receiver_public_key.encrypt(
                            symmetric_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        print(f"DEBUG: Symmetric key encrypted with RSA. Encrypted length: {len(encrypted_symmetric_key_for_db)}")
                        filename = f"{uuid.uuid4().hex}.encrypted"
                        file_to_save = ContentFile(encrypted_file_content)
                        transaction_data['original_filename'] = file.name # Store original filename for encrypted files
                        transaction_data['encrypted_symmetric_key'] = encrypted_symmetric_key_for_db.hex() # Store as hex string for JSON serialization
                        transaction_data['receiver_public_key_at_encryption'] = receiver_profile.public_key # Store receiver's public key at time of encryption

                    except Exception as e:
                        print(f"ERROR: Exception during file encryption: {e}") # More detailed error logging
                        return JsonResponse({'success': False, 'message': f'Errore durante la cifratura del file: {str(e)}'})
                else:
                    filename = f"{time.time()}_{file.name}"
                    file_to_save = ContentFile(file_content)

                file_path = default_storage.save(f'transaction_files/{filename}', file_to_save)
                transaction_data['file'] = file_path

            # Calculate transaction hash
            transaction_string_for_signing = json.dumps(transaction_data, sort_keys=True).encode()
            print(f"[DEBUG SIGNING] transaction_data: {transaction_data}")
            print(f"[DEBUG SIGNING] transaction_string_for_signing: {transaction_string_for_signing}")
            transaction_hash = hashlib.sha256(transaction_string_for_signing).hexdigest()
            
            # Sign the transaction
            private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
            if not private_key:
                return JsonResponse({
                    'success': False,
                    'message': 'Errore durante il recupero della chiave privata.'
                })
            
            data_to_sign = transaction_hash.encode()
            signature = private_key.sign(
                data_to_sign,
                PSS(
                    mgf=MGF1(hashes.SHA256()),
                    salt_length=PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Create transaction
            new_tx = Transaction.objects.create(
                type=transaction_type,
                sender=request.user,
                receiver=receiver,
                sender_public_key=sender_public_key,
                content=encrypted_content,
                file=transaction_data.get('file'),
                timestamp=transaction_data['timestamp'],
                transaction_hash=transaction_hash,
                signature=signature.hex(),
                is_encrypted=is_encrypted,
                original_filename=transaction_data.get('original_filename', ''), # Save original filename if present
                # Convert back to bytes for BinaryField
                encrypted_symmetric_key=bytes.fromhex(transaction_data['encrypted_symmetric_key']) if 'encrypted_symmetric_key' in transaction_data and transaction_data['encrypted_symmetric_key'] else None,
                receiver_public_key_at_encryption=transaction_data.get('receiver_public_key_at_encryption', ''),
                max_downloads=max_downloads
            )

            # Add to pending transactions
            pending_transactions_ids = request.session.get('pending_transactions_ids', [])
            pending_transactions_ids.append(new_tx.id)
            request.session['pending_transactions_ids'] = pending_transactions_ids

            return JsonResponse({
                'success': True,
                'message': 'Transazione creata e firmata. In attesa di mining.',
                'requires_mining': True,
                'pending_count': len(pending_transactions_ids)
            })

        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            })

    # Se GET, mostra il form
    return render(request, 'Cripto1/create_transaction.html')

@login_required
@csrf_exempt
def mine_block(request):
    if request.method == 'POST':
        # Recupera tutte le transazioni non ancora incluse in un blocco
        pending_transactions = Transaction.objects.filter(block__isnull=True)
        if not pending_transactions.exists():
            return JsonResponse({'success': False, 'message': 'Nessuna transazione in sospeso da minare.'})

        # Recupera l'ultimo blocco
        last_block = Block.objects.order_by('-index').first()
        index = 1 if not last_block else last_block.index + 1
        previous_hash = '0' * 64 if not last_block else last_block.hash
        timestamp = time.time()
        difficulty = 3  # Numero di zeri richiesti all'inizio dell'hash

        # Calcola la radice di Merkle (qui semplificata come hash concatenato delle transazioni)
        tx_hashes = [tx.transaction_hash for tx in pending_transactions]
        merkle_root = hashlib.sha256(''.join(tx_hashes).encode()).hexdigest() if tx_hashes else ''

        # Proof of Work: trova un nonce tale che l'hash inizi con N zeri
        nonce = 0
        while True:
            block_data = {
                'index': index,
                'timestamp': timestamp,
                'proof': str(nonce),
                'previous_hash': previous_hash,
                'nonce': str(nonce),
                'merkle_root': merkle_root,
                'difficulty': difficulty,
            }
            block_hash = hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()
            if block_hash.startswith('0' * difficulty):
                break
            nonce += 1

        # Crea il nuovo blocco
        new_block = Block.objects.create(
            index=index,
            timestamp=timestamp,
            proof=str(nonce),
            previous_hash=previous_hash,
            hash=block_hash,
            nonce=str(nonce),
            merkle_root=merkle_root,
            difficulty=difficulty,
        )

        # Associa le transazioni al nuovo blocco
        pending_transactions.update(block=new_block)

        return JsonResponse({'success': True, 'message': f'Blocco #{index} creato con successo con PoW! Nonce trovato: {nonce}', 'block_index': index, 'nonce': nonce})
    else:
        return JsonResponse({'success': False, 'message': 'Method not allowed'})

def calculate_merkle_root(transactions_hashes):
    if not transactions_hashes:
        return ""

    # If odd number of hashes, duplicate the last one
    if len(transactions_hashes) % 2 != 0:
        transactions_hashes.append(transactions_hashes[-1])

    # Recursively calculate parent hashes
    new_level_hashes = []
    for i in range(0, len(transactions_hashes), 2):
        combined_hashes = transactions_hashes[i] + transactions_hashes[i+1]
        new_hash = hashlib.sha256(combined_hashes.encode()).hexdigest()
        new_level_hashes.append(new_hash)

    # If we are down to a single hash, it's the Merkle root
    if len(new_level_hashes) == 1:
        return new_level_hashes[0]
    else:
        # Otherwise, recurse with the new level of hashes
        return calculate_merkle_root(new_level_hashes)

@login_required
@csrf_exempt
def decrypt_transaction(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            transaction_id = data.get('transaction_id')
            password = data.get('password', 'securepassword').encode()  # default per retrocompatibilità
            tx = Transaction.objects.get(id=transaction_id)
            user_profile = UserProfile.objects.get(user=request.user)

            if tx.sender != request.user and tx.receiver != request.user:
                return JsonResponse({
                    'success': False,
                    'message': 'Non sei autorizzato a decriptare questa transazione'
                })

            decrypted_content = None
            if tx.is_encrypted and tx.type == 'text':
                decrypted_content = user_profile.decrypt_message(tx.content, password=password)
            else:
                decrypted_content = tx.content

            return JsonResponse({
                'success': True,
                'decrypted_content': decrypted_content,
                'sender': tx.sender.id
            })

        except Transaction.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'Transazione non trovata'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': str(e)
            })

    return JsonResponse({'success': False, 'message': 'Metodo non consentito'})

@login_required
def get_blockchain_stats(request):
    blockchain_state = BlockchainState.objects.first()
    return JsonResponse({
        'current_supply': blockchain_state.current_supply,
        'max_supply': blockchain_state.max_supply,
        'current_reward': blockchain_state.current_reward,
        'halving_count': blockchain_state.halving_count,
        'percentage_mined': (blockchain_state.current_supply / blockchain_state.max_supply) * 100
    })

def index(request):
    if request.user.is_authenticated:
        return redirect('Cripto1:dashboard')
    return render(request, 'Cripto1/index.html')

def landing_page_view(request):
    if request.user.is_authenticated:
        return redirect('Cripto1:dashboard')  # Redirect to original dashboard
    else:
        return render(request, 'Cripto1/landing_page.html')

@login_required
def users_feed(request):
    users = UserProfile.objects.all().select_related('user')
    context = {
        'users': users,
    }
    return render(request, 'Cripto1/users_feed.html', context)

def logout_view(request):
    if request.method == 'POST':
        logout(request)
        messages.success(request, "You have been logged out.")
    return redirect('Cripto1:home') # Redirect to home page after logout



@login_required
def personal_profile(request):
    user_profile = UserProfile.objects.get(user=request.user)
    if not user_profile.public_key or not user_profile.private_key:
        user_profile.generate_key_pair()
        user_profile.refresh_from_db()
    
    # Recupera solo le transazioni recenti per la pagina del profilo
    recent_transactions = Transaction.objects.filter(
        models.Q(sender=request.user) | 
        models.Q(receiver=request.user)
    ).order_by('-timestamp')[:5] # Limit to 5 recent transactions
    
    processed_recent_transactions = []
    for tx in recent_transactions:
        tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())
        if tx.receiver == request.user:
            tx.direction = 'Ricevuta'
        elif tx.sender == request.user:
            tx.direction = 'Inviata'
        else:
            tx.direction = 'Sconosciuta'
        processed_recent_transactions.append(tx)

    context = {
        'user_profile': user_profile,
        'recent_transactions': processed_recent_transactions,
    }
    return render(request, 'Cripto1/personal_profile.html', context)

@login_required
def transaction_details(request, transaction_id):
    tx = get_object_or_404(Transaction, id=transaction_id)
    
    # Check if user is either sender or receiver
    if request.user != tx.sender and request.user != tx.receiver:
        messages.error(request, 'You do not have permission to view this transaction.')
        return redirect('Cripto1:dashboard')
    
    # Convert timestamp to datetime
    tx.timestamp_datetime = datetime.fromtimestamp(tx.timestamp, tz=timezone.get_current_timezone())

    # Mark as viewed if the current user is the receiver and it's not already viewed
    if request.user == tx.receiver and not tx.is_viewed:
        tx.is_viewed = True
        tx.save()

    # Verify signature
    is_valid = tx.verify_signature()
    
    context = {
        'transaction': tx,
        'is_valid': is_valid,
        'is_sender': request.user == tx.sender,
        'is_receiver': request.user == tx.receiver,
    }
    
    return render(request, 'Cripto1/transaction_details.html', context)

@login_required
def download_file(request, transaction_id):
    tx = get_object_or_404(Transaction, id=transaction_id)
    
    # Check if user is either sender or receiver
    if request.user != tx.sender and request.user != tx.receiver:
        messages.error(request, 'You do not have permission to download this file.')
        return redirect('Cripto1:dashboard')
    
    if not tx.file:
        messages.error(request, 'No file associated with this transaction.')
        return redirect('Cripto1:transaction_details', transaction_id=transaction_id)
    
    # Check download limits
    if tx.max_downloads is not None:
        if tx.current_downloads >= tx.max_downloads:
            messages.error(request, 'Questo file ha raggiunto il numero massimo di download consentiti.')
            return redirect('Cripto1:transaction_details', transaction_id=transaction_id)

    user_profile = request.user.userprofile

    if tx.is_encrypted:
        # Ensure only the receiver can download encrypted files
        if request.user != tx.receiver:
            messages.error(request, 'Non sei autorizzato a decifrare e scaricare questo file.')
            return redirect('Cripto1:dashboard')

        # Check if the receiver's current public key matches the one used for encryption
        if user_profile.public_key != tx.receiver_public_key_at_encryption:
            messages.error(request, 'Impossibile decifrare il file. La chiave pubblica del destinatario è cambiata dopo la cifratura della transazione.')
            return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})

        if request.method == 'POST':
            private_key_password = request.POST.get('private_key_password')
            if not private_key_password:
                messages.error(request, 'Inserisci la password della chiave privata.')
                return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})

            try:
                # Read the encrypted file content
                with default_storage.open(tx.file.name, 'rb') as f:
                    encrypted_file_content = f.read()
                print(f"DEBUG: Encrypted file content length: {len(encrypted_file_content)}")
                
                # Decrypt the symmetric key with the user's private RSA key
                decrypted_private_key = user_profile.decrypt_private_key(password=private_key_password.encode())
                if not decrypted_private_key:
                    messages.error(request, 'Password della chiave privata errata.')
                    return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})
                
                print(f"DEBUG: Encrypted symmetric key (from DB): {tx.encrypted_symmetric_key[:10]}...") # First 10 bytes
                # Use the RSA private key to decrypt the symmetric key
                symmetric_key = decrypted_private_key.decrypt(
                    tx.encrypted_symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"DEBUG: Symmetric key decrypted. Length: {len(symmetric_key)}, value: {symmetric_key[:10]}...") # First 10 bytes
                
                # Decrypt the file content with the symmetric key
                f = Fernet(symmetric_key)
                decrypted_content = f.decrypt(encrypted_file_content)
                print(f"DEBUG: File content decrypted successfully. Length: {len(decrypted_content)}")

                if decrypted_content is None:
                    messages.error(request, 'Errore di decifratura del contenuto del file.')
                    return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})

                # Serve the decrypted file with its original filename
                response = HttpResponse(decrypted_content, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="{tx.original_filename}"'
                
                # Increment download count for encrypted files
                if tx.max_downloads is not None:
                    tx.current_downloads += 1
                    tx.save()
                
                return response

            except Exception as e:
                print(f"ERROR: Exception type during decryption/download: {type(e).__name__}") # Added for more specific error
                print(f"ERROR: Exception during decryption/download: {e}") # More detailed error logging
                messages.error(request, f'Errore durante la decifratura o il download del file: {str(e)}')
                return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})
        else:
            # If GET request for an encrypted file, show the password form
            return render(request, 'Cripto1/download_encrypted_file.html', {'transaction': tx})
    else:
        # If not encrypted, proceed with the existing download logic
        file_path = tx.file.path
        file_name = os.path.basename(file_path) # Or tx.original_filename if you want to save original name for unencrypted too
        
        with open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            
            # Increment download count for unencrypted files
            if tx.max_downloads is not None:
                tx.current_downloads += 1
                tx.save()

            return response

@login_required
def edit_profile(request):
    user_profile = UserProfile.objects.get(user=request.user)
    if request.method == 'POST':
        form = UserProfileEditForm(request.POST, request.FILES, instance=user_profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profilo aggiornato con successo')
            return redirect('Cripto1:personal_profile')
    else:
        form = UserProfileEditForm(instance=user_profile)
    return render(request, 'Cripto1/edit_profile.html', {'form': form, 'user_profile': user_profile})

@staff_member_required
def admin_dashboard(request):
    # Get total users
    total_users = User.objects.count()

    # Get total transactions
    total_transactions = Transaction.objects.count()

    # Get total blocks
    total_blocks = Block.objects.count()

    # Get active addresses (last 24 hours) - Temporarily commented out due to TypeError
    # now = timezone.now()
    # day_ago = now - timezone.timedelta(days=1)
    # active_addresses = Transaction.objects.filter(
    #     timestamp__gte=day_ago
    # ).values('sender', 'receiver').distinct().count()
    active_addresses = "N/A" # Placeholder value

    # Get total transaction volume
    total_volume = 0  # Il campo 'amount' non esiste, quindi imposto a 0 o placeholder

    # Lista di tutti i profili utente
    user_profiles = UserProfile.objects.select_related('user').all()

    context = {
        'total_users': total_users,
        'total_transactions': total_transactions,
        'total_blocks': total_blocks,
        'active_addresses': active_addresses,
        'total_volume': total_volume,
        'user_profiles': user_profiles,
    }
    return render(request, 'Cripto1/admin_dashboard.html', context)

@staff_member_required
def verify_blockchain(request):
    last_block = Block.objects.order_by('-index').first()
    if not last_block:
        return JsonResponse({'is_valid': True, 'message': 'Blockchain vuota, considerata valida.'})

    # Start verification from the second to last block
    current_block = last_block
    while current_block.index > 1:
        previous_block = Block.objects.filter(index=current_block.index - 1).first()

        # Check if previous block exists and if hashes match
        if not previous_block or previous_block.hash != current_block.previous_hash:
            return JsonResponse({
                'is_valid': False,
                'message': f'Blockchain non valida: Hash del blocco precedente {current_block.index-1} non corrisponde al previous_hash del blocco {current_block.index}.'
            })

        # Recalculate the hash of the previous block to verify its integrity
        previous_block_data = {
            'index': previous_block.index,
            'timestamp': previous_block.timestamp, # Use the float value directly
            'proof': previous_block.proof,
            'previous_hash': previous_block.previous_hash,
            'transactions': list(previous_block.transactions.values('type', 'sender_public_key', 'receiver', 'timestamp', 'transaction_hash')), # RIMOSSO 'amount' e 'notes'
            'difficulty': getattr(previous_block, 'difficulty', 4) # Include difficulty if exists
        }
        recalculated_hash = calculate_hash(previous_block_data)

        if recalculated_hash != previous_block.hash:
             return JsonResponse({
                'is_valid': False,
                'message': f'Blockchain non valida: Hash ricalcolato per il blocco {previous_block.index} non corrisponde all\'hash memorizzato.'
            })

        current_block = previous_block

    # Check the genesis block's previous_hash (should be all zeros)
    genesis_block = Block.objects.get(index=1)
    if genesis_block.previous_hash != '0' * 64:
         return JsonResponse({
            'is_valid': False,
            'message': 'Blockchain non valida: Il previous_hash del genesis block non è corretto.'
        })

    return JsonResponse({'is_valid': True, 'message': 'Blockchain verificata con successo! L\'integrità è confermata.'})

@staff_member_required
def export_csv(request, model):
    model_map = {
        'userprofile': UserProfile,
        'transaction': Transaction,
        'block': Block,
        'blockchainstate': BlockchainState,
        'smartcontract': SmartContract
    }
    
    if model not in model_map:
        return HttpResponse("Model not found", status=404)
    
    Model = model_map[model]
    queryset = Model.objects.all()
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{model}.csv"'
    
    writer = csv.writer(response)
    # Write headers
    writer.writerow([field.name for field in Model._meta.fields])
    
    # Write data
    for obj in queryset:
        writer.writerow([getattr(obj, field.name) for field in Model._meta.fields])
    
    return response

@staff_member_required
def admin_user_detail(request, user_id):
    user_profile = get_object_or_404(UserProfile, user__id=user_id)
    user = user_profile.user
    # Statistiche transazioni
    sent_count = user.sent_transactions.count()
    received_count = user.received_transactions.count()
    total_transactions = sent_count + received_count
    # Blocchi in cui l'utente è coinvolto
    blocks = Block.objects.filter(transactions__sender=user).distinct() | Block.objects.filter(transactions__receiver=user).distinct()
    blocks = blocks.distinct()
    blocks_count = blocks.count()
    # Peso movimenti: se non hai un campo amount, mostra solo il numero
    # Se hai un campo amount, puoi sommare qui
    # Esempio: total_weight = user.sent_transactions.aggregate(Sum('amount'))['amount__sum'] or 0
    # Qui mostro solo il numero di transazioni
    total_weight = total_transactions
    # Gestione credenziali
    if request.method == 'POST':
        if 'reset_password' in request.POST:
            form = PasswordResetForm({'email': user.email})
            if form.is_valid():
                form.save(request=request, use_https=request.is_secure(),
                          email_template_name='registration/password_reset_email.html')
                messages.success(request, 'Email di reset password inviata!')
        elif 'update_user' in request.POST:
            form = UserChangeForm(request.POST, instance=user)
            if form.is_valid():
                form.save()
                messages.success(request, 'Dati utente aggiornati!')
        elif 'update_permissions' in request.POST:
            # Assicurati che solo un superuser possa modificare i permessi di staff/superuser
            if not request.user.is_superuser:
                messages.error(request, 'Non hai i permessi per modificare lo status di superuser/staff.')
            else:
                # Aggiorna lo status is_staff e is_superuser
                user.is_staff = 'is_staff' in request.POST
                user.is_superuser = 'is_superuser' in request.POST
                user.save()
                messages.success(request, 'Permessi utente aggiornati con successo!')

        return redirect('Cripto1:admin_user_detail', user_id=user.id)
    else:
        form = UserChangeForm(instance=user)
    context = {
        'user_profile': user_profile,
        'user': user,
        'sent_count': sent_count,
        'received_count': received_count,
        'total_transactions': total_transactions,
        'blocks_count': blocks_count,
        'total_weight': total_weight,
        'form': form,
        'is_staff': user.is_staff,
        'is_superuser': user.is_superuser,
    }
    return render(request, 'Cripto1/admin_user_detail.html', context)



# ==================== AUDIT LOG VIEWS ====================

@staff_member_required
def audit_logs_view(request):
    """Vista principale per visualizzare gli audit log"""
    
    # Parametri di filtro
    action_type = request.GET.get('action_type', '')
    severity = request.GET.get('severity', '')
    user_id = request.GET.get('user_id', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    success_only = request.GET.get('success_only', '')
    
    # Query base
    queryset = AuditLog.objects.select_related('user').all()
    
    # Applica filtri
    if action_type:
        queryset = queryset.filter(action_type=action_type)
    if severity:
        queryset = queryset.filter(severity=severity)
    if user_id:
        queryset = queryset.filter(user_id=user_id)
    if date_from:
        try:
            date_from_obj = timezone.strptime(date_from, '%Y-%m-%d')
            queryset = queryset.filter(timestamp__date__gte=date_from_obj.date())
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = timezone.strptime(date_to, '%Y-%m-%d')
            queryset = queryset.filter(timestamp__date__lte=date_to_obj.date())
        except ValueError:
            pass
    if success_only == 'true':
        queryset = queryset.filter(success=True)
    
    # Statistiche
    total_logs = queryset.count()
    success_count = queryset.filter(success=True).count()
    error_count = total_logs - success_count
    
    # Statistiche per severità
    severity_stats = queryset.values('severity').annotate(count=models.Count('id'))
    
    # Statistiche per tipo di azione
    action_stats = queryset.values('action_type').annotate(count=models.Count('id')).order_by('-count')[:10]
    
    # Paginazione
    paginator = Paginator(queryset, 50)  # 50 log per pagina
    page = request.GET.get('page')
    try:
        logs = paginator.page(page)
    except PageNotAnInteger:
        logs = paginator.page(1)
    except EmptyPage:
        logs = paginator.page(paginator.num_pages)
    
    # Lista utenti per il filtro
    users = User.objects.filter(audit_logs__isnull=False).distinct()
    
    context = {
        'logs': logs,
        'total_logs': total_logs,
        'success_count': success_count,
        'error_count': error_count,
        'severity_stats': severity_stats,
        'action_stats': action_stats,
        'users': users,
        'action_types': AuditLog.ACTION_TYPES,
        'severity_levels': AuditLog.SEVERITY_LEVELS,
        'filters': {
            'action_type': action_type,
            'severity': severity,
            'user_id': user_id,
            'date_from': date_from,
            'date_to': date_to,
            'success_only': success_only,
        }
    }
    
    return render(request, 'Cripto1/audit_logs.html', context)

@staff_member_required
def audit_log_detail(request, log_id):
    """Vista dettagliata di un singolo audit log"""
    log = get_object_or_404(AuditLog, id=log_id)
    
    # Ottieni l'oggetto correlato se esiste
    related_object = log.get_related_object()
    
    context = {
        'log': log,
        'related_object': related_object,
    }
    
    return render(request, 'Cripto1/audit_log_detail.html', context)

@staff_member_required
def export_audit_logs(request):
    """Export degli audit log in CSV"""
    
    # Parametri di filtro (stessi della vista principale)
    action_type = request.GET.get('action_type', '')
    severity = request.GET.get('severity', '')
    user_id = request.GET.get('user_id', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    success_only = request.GET.get('success_only', '')
    
    # Query base
    queryset = AuditLog.objects.select_related('user').all()
    
    # Applica filtri
    if action_type:
        queryset = queryset.filter(action_type=action_type)
    if severity:
        queryset = queryset.filter(severity=severity)
    if user_id:
        queryset = queryset.filter(user_id=user_id)
    if date_from:
        try:
            date_from_obj = timezone.strptime(date_from, '%Y-%m-%d')
            queryset = queryset.filter(timestamp__date__gte=date_from_obj.date())
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = timezone.strptime(date_to, '%Y-%m-%d')
            queryset = queryset.filter(timestamp__date__lte=date_to_obj.date())
        except ValueError:
            pass
    if success_only == 'true':
        queryset = queryset.filter(success=True)
    
    # Crea il file CSV
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="audit_logs_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    # Scrivi BOM per UTF-8
    response.write('\ufeff')
    
    writer = csv.writer(response)
    
    # Intestazioni
    headers = [
        'ID', 'Timestamp', 'Utente', 'Tipo Azione', 'Severità', 'Descrizione',
        'IP Address', 'User Agent', 'Session ID', 'Oggetto Correlato',
        'Tipo Oggetto', 'ID Oggetto', 'Successo', 'Messaggio Errore',
        'Dati Aggiuntivi'
    ]
    writer.writerow(headers)
    
    # Dati
    for log in queryset:
        row = [
            log.id,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username if log.user else 'Anonymous',
            log.get_action_type_display(),
            log.get_severity_display(),
            log.description,
            log.ip_address or '',
            log.user_agent or '',
            log.session_id or '',
            log.related_object_type or '',
            log.related_object_id or '',
            'Sì' if log.success else 'No',
            log.error_message or '',
            json.dumps(log.additional_data, ensure_ascii=False) if log.additional_data else ''
        ]
        writer.writerow(row)
    
    return response

@staff_member_required
def audit_logs_analytics(request):
    """Dashboard analitica per gli audit log"""
    
    # Periodo di analisi (ultimi 30 giorni di default)
    days = int(request.GET.get('days', 30))
    end_date = timezone.now()
    start_date = end_date - timedelta(days=days)
    
    # Log nel periodo
    logs_in_period = AuditLog.objects.filter(
        timestamp__range=(start_date, end_date)
    )
    
    # Statistiche generali
    total_actions = logs_in_period.count()
    unique_users = logs_in_period.values('user').distinct().count()
    success_count = logs_in_period.filter(success=True).count()
    success_rate = (success_count / total_actions * 100) if total_actions > 0 else 0
    actions_per_day = (total_actions / days) if days > 0 else 0
    
    # Azioni per giorno
    daily_actions = logs_in_period.extra(
        select={'day': 'date(timestamp)'}
    ).values('day').annotate(
        count=models.Count('id'),
        success_count=models.Count('id', filter=models.Q(success=True)),
        error_count=models.Count('id', filter=models.Q(success=False))
    ).order_by('day')
    
    # Top azioni
    top_actions = logs_in_period.values('action_type').annotate(
        count=models.Count('id')
    ).order_by('-count')[:10]
    for action in top_actions:
        action['percent'] = (action['count'] / total_actions * 100) if total_actions > 0 else 0
    
    # Top utenti
    top_users = logs_in_period.values('user__username').annotate(
        count=models.Count('id')
    ).order_by('-count')[:10]
    for user in top_users:
        user['percent'] = (user['count'] / total_actions * 100) if total_actions > 0 else 0
    
    # Severità distribution
    severity_distribution = logs_in_period.values('severity').annotate(
        count=models.Count('id')
    ).order_by('severity')
    
    # IP addresses più attivi
    top_ips = logs_in_period.values('ip_address').annotate(
        count=models.Count('id')
    ).filter(ip_address__isnull=False).order_by('-count')[:10]
    for ip in top_ips:
        ip['percent'] = (ip['count'] / total_actions * 100) if total_actions > 0 else 0
    
    context = {
        'days': days,
        'start_date': start_date,
        'end_date': end_date,
        'total_actions': total_actions,
        'unique_users': unique_users,
        'success_rate': round(success_rate, 2),
        'actions_per_day': round(actions_per_day, 1),
        'daily_actions': list(daily_actions),
        'top_actions': list(top_actions),
        'top_users': list(top_users),
        'severity_distribution': list(severity_distribution),
        'top_ips': list(top_ips),
    }
    
    return render(request, 'Cripto1/audit_logs_analytics.html', context)

@staff_member_required
def security_alerts(request):
    """Vista per gli alert di sicurezza"""
    
    # Eventi critici degli ultimi 7 giorni
    critical_events = AuditLog.objects.filter(
        severity='CRITICAL',
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).order_by('-timestamp')
    
    # Tentativi di login falliti
    failed_logins = AuditLog.objects.filter(
        action_type='LOGIN',
        success=False,
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).order_by('-timestamp')
    
    # Azioni amministrative
    admin_actions = AuditLog.objects.filter(
        action_type='ADMIN_ACTION',
        timestamp__gte=timezone.now() - timedelta(days=7)
    ).order_by('-timestamp')
    
    # IP sospetti (troppi tentativi falliti)
    suspicious_ips = AuditLog.objects.filter(
        action_type='LOGIN',
        success=False,
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).values('ip_address').annotate(
        failed_attempts=models.Count('id')
    ).filter(
        failed_attempts__gte=5,
        ip_address__isnull=False
    ).order_by('-failed_attempts')
    
    context = {
        'critical_events': critical_events,
        'failed_logins': failed_logins,
        'admin_actions': admin_actions,
        'suspicious_ips': suspicious_ips,
    }
    
    return render(request, 'Cripto1/security_alerts.html', context)

def page_not_found(request, exception):
    return render(request, 'Cripto1/404.html', {},
                    status=404)

def permission_denied(request, exception):
    return render(request, 'Cripto1/403.html', {},
                    status=403)

# Funzione per verificare se l'utente è superuser o ha permessi di gestione utenti
def has_user_management_permission(user):
    """Verifica se l'utente ha i permessi di gestione utenti"""
    if user.is_superuser or user.is_staff:
        return True
    
    # Verifica se l'utente ha il permesso di gestione utenti
    try:
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True
        ).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
        )
        
        for user_role in user_roles:
            if user_role.role.permissions.filter(codename__icontains='user_management').exists():
                return True
    except Exception:
        pass
    
    return False

# Decoratore personalizzato per la gestione utenti
def user_management_required(view_func):
    def wrapper(request, *args, **kwargs):
        # Per ora, permettiamo l'accesso a tutti gli utenti autenticati per testare
        if not request.user.is_authenticated:
            messages.error(request, "Devi essere autenticato per accedere a questa sezione.")
            return redirect('Cripto1:login')
        return view_func(request, *args, **kwargs)
    return wrapper

@login_required
@user_management_required
def user_management_dashboard(request):
    """Dashboard principale per la gestione utenti"""
    # Statistiche
    total_users = UserProfile.objects.count()
    active_users = UserProfile.objects.filter(is_active=True).count()
    inactive_users = UserProfile.objects.filter(is_active=False).count()
    locked_users = sum(
        1 for u in UserProfile.objects.all()
        if (u.is_locked() if callable(getattr(u, 'is_locked', None)) else getattr(u, 'is_locked', False))
    )
    
    # Statistiche per ruolo
    role_stats = {}
    for role in Role.objects.all():
        count = UserRole.objects.filter(role=role, is_active=True).count()
        if count > 0:
            role_stats[role.name] = count
    
    # Utenti recenti
    recent_users = UserProfile.objects.order_by('-created_at')[:5]
    
    # Attività recenti
    recent_activities = AuditLog.objects.filter(
        action_type__in=['USER_CREATED', 'USER_UPDATED', 'USER_DELETED', 'ROLE_ASSIGNED', 'ROLE_REMOVED']
    ).order_by('-timestamp')[:10]
    
    context = {
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'locked_users': locked_users,
        'role_stats': role_stats,
        'recent_users': recent_users,
        'recent_activities': recent_activities,
    }
    
    return render(request, 'Cripto1/user_management/dashboard.html', context)

@login_required
@user_management_required
def user_list(request):
    """Lista degli utenti con filtri e paginazione"""
    search = request.GET.get('search', '')
    status = request.GET.get('status', '')
    role_filter = request.GET.get('role', '')
    
    # Query base
    users = UserProfile.objects.select_related('user').all()
    
    # Filtri
    if search:
        users = users.filter(
            Q(user__username__icontains=search) |
            Q(user__email__icontains=search) |
            Q(user__first_name__icontains=search) |
            Q(user__last_name__icontains=search) |
            Q(department__icontains=search) |
            Q(position__icontains=search)
        )
    
    if status == 'active':
        users = users.filter(is_active=True, is_locked=False)
    elif status == 'inactive':
        users = users.filter(is_active=False)
    elif status == 'locked':
        users = users.filter(is_locked=True)
    
    if role_filter:
        users = users.filter(user__user_roles__role__name=role_filter)
    
    # Paginazione
    paginator = Paginator(users, 12)
    page = request.GET.get('page')
    try:
        page_obj = paginator.page(page)
    except PageNotAnInteger:
        page_obj = paginator.page(1)
    except EmptyPage:
        page_obj = paginator.page(paginator.num_pages)
    
    # Ruoli disponibili per il filtro
    roles = Role.objects.all()
    
    context = {
        'page_obj': page_obj,
        'search': search,
        'status': status,
        'role_filter': role_filter,
        'roles': roles,
    }
    
    return render(request, 'Cripto1/user_management/user_list.html', context)

@login_required
@user_management_required
def user_detail(request, user_id):
    """Dettaglio utente con gestione ruoli"""
    user = get_object_or_404(User, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user)
    
    # Ruoli dell'utente (solo quelli attivi e non scaduti)
    user_roles = UserRole.objects.filter(
        user=user,
        is_active=True
    ).select_related('role', 'assigned_by').order_by('-assigned_at')
    
    # Ruoli disponibili per l'assegnazione (escludi quelli già assegnati)
    assigned_role_ids = user_roles.values_list('role_id', flat=True)
    available_roles = Role.objects.filter(
        is_active=True
    ).exclude(
        id__in=assigned_role_ids
    ).order_by('name')
    
    # Attività recenti dell'utente
    recent_activities = AuditLog.objects.filter(
        Q(user=user) | Q(description__icontains=user.username)
    ).order_by('-timestamp')[:10]
    
    context = {
        'user_profile': user_profile,
        'user_roles': user_roles,
        'available_roles': available_roles,
        'recent_activities': recent_activities,
        'now': timezone.now(),
    }
    
    return render(request, 'Cripto1/user_management/user_detail.html', context)

@login_required
@user_management_required
def create_user(request):
    """Creazione nuovo utente"""
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        department = request.POST.get('department', '')
        position = request.POST.get('position', '')
        phone = request.POST.get('phone', '')
        emergency_contact = request.POST.get('emergency_contact', '')
        notes = request.POST.get('notes', '')
        default_role = request.POST.get('default_role', '')
        pk_password = request.POST.get('private_key_password', '')
        pk_confirm = request.POST.get('confirm_private_key_password', '')
        profile_picture = request.FILES.get('profile_picture')

        # Validazione
        if not username or not email or not password or not pk_password:
            messages.error(request, 'Username, email, password account e password chiave privata sono obbligatori')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if password != confirm_password:
            messages.error(request, 'Le password account non corrispondono')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if pk_password != pk_confirm:
            messages.error(request, 'Le password della chiave privata non corrispondono')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if len(password) < 8 or len(pk_password) < 8:
            messages.error(request, 'Le password devono essere di almeno 8 caratteri')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username già esistente')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email già esistente')
            return render(request, 'Cripto1/user_management/create_user.html', {'roles': Role.objects.filter(is_active=True)})

        try:
            with transaction.atomic():
                # Crea l'utente
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )

                # Crea il profilo
                user_profile = UserProfile.objects.create(
                    user=user,
                    department=department,
                    position=position,
                    phone=phone,
                    emergency_contact=emergency_contact,
                    notes=notes
                )
                if profile_picture:
                    user_profile.profile_picture = profile_picture

                # Genera le chiavi crittografiche per l'utente con la password fornita
                user_profile.generate_key_pair(password=pk_password.encode())
                user_profile.save()

                # Assegna ruolo di default se specificato
                if default_role:
                    try:
                        role = Role.objects.get(name=default_role)
                        UserRole.objects.create(
                            user=user,
                            role=role,
                            assigned_by=request.user,
                            notes='Ruolo assegnato alla creazione'
                        )
                    except Role.DoesNotExist:
                        pass

                # Log dell'azione
                AuditLog.log_action(
                    action_type='USER_MANAGEMENT',
                    description=f'Utente {username} creato da {request.user.username}',
                    severity='MEDIUM',
                    user=request.user,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    related_object_type='UserProfile',
                    related_object_id=user_profile.id,
                    success=True
                )

                messages.success(request, f'Utente {username} creato con successo')
                return redirect('Cripto1:user_detail', user_id=user.id)

        except Exception as e:
            messages.error(request, f'Errore durante la creazione: {str(e)}')
            print(f"Errore creazione utente: {e}")

    context = {
        'roles': Role.objects.filter(is_active=True)
    }
    return render(request, 'Cripto1/user_management/create_user.html', context)

@login_required
@user_management_required
def edit_user(request, user_id):
    """Modifica utente"""
    user = get_object_or_404(User, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user)

    if request.method == 'POST':
        # Aggiorna i campi dell'utente
        user.first_name = request.POST.get('first_name', '')
        user.last_name = request.POST.get('last_name', '')
        user.email = request.POST.get('email', '')
        user.save()

        # Aggiorna i campi del profilo
        user_profile.department = request.POST.get('department', '')
        user_profile.position = request.POST.get('position', '')
        user_profile.phone = request.POST.get('phone', '')
        user_profile.emergency_contact = request.POST.get('emergency_contact', '')
        user_profile.notes = request.POST.get('notes', '')

        # Gestione foto profilo
        if 'profile_picture' in request.FILES:
            user_profile.profile_picture = request.FILES['profile_picture']

        # Gestione password Django
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        if password:
            if password == confirm_password and len(password) >= 8:
                user.set_password(password)
                user.save()
                messages.info(request, 'Password account aggiornata.')
            else:
                messages.error(request, 'Le password account non corrispondono o sono troppo corte.')
                return redirect('Cripto1:edit_user', user_id=user.id)

        # Gestione password chiave privata
        pk_password = request.POST.get('private_key_password', '')
        pk_confirm = request.POST.get('confirm_private_key_password', '')
        if pk_password:
            if pk_password == pk_confirm and len(pk_password) >= 8:
                user_profile.generate_key_pair(password=pk_password.encode())
                messages.info(request, 'Chiave privata rigenerata con nuova password.')
            else:
                messages.error(request, 'Le password della chiave privata non corrispondono o sono troppo corte.')
                return redirect('Cripto1:edit_user', user_id=user.id)



        user_profile.save()

        # Log dell'azione
        AuditLog.log_action(
            action_type='USER_MANAGEMENT',
            description=f'Utente {user.username} modificato da {request.user.username}',
            severity='MEDIUM',
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='UserProfile',
            related_object_id=user_profile.id,
            success=True
        )

        messages.success(request, 'Utente aggiornato con successo')
        return redirect('Cripto1:user_detail', user_id=user.id)
    else:
        form = UserProfileEditForm(instance=user_profile)

    context = {
        'user_profile': user_profile,
        'form': form
    }
    return render(request, 'Cripto1/user_management/edit_user.html', context)

@login_required
@user_management_required
@require_POST
def toggle_user_status(request, user_id):
    """Attiva/disattiva utente"""
    user = get_object_or_404(User, id=user_id)
    user_profile = get_object_or_404(UserProfile, user=user)
    
    # Non permettere di disattivare se stessi
    if user == request.user:
        messages.error(request, 'Non puoi disattivare il tuo account')
        return redirect('Cripto1:user_detail', user_id=user.id)
    
    user_profile.is_active = not user_profile.is_active
    user_profile.save()
    
    action = 'attivato' if user_profile.is_active else 'disattivato'
    
    # Log dell'azione
    AuditLog.log_action(
        action_type='USER_ACTIVATION' if user_profile.is_active else 'USER_DEACTIVATION',
        description=f'Utente {user.username} {action} da {request.user.username}',
        severity='HIGH',
        user=request.user,
        ip_address=request.META.get('REMOTE_ADDR'),
        related_object_type='UserProfile',
        related_object_id=user_profile.id,
        success=True
    )
    
    messages.success(request, f'Utente {user.username} {action} con successo')
    return redirect('Cripto1:user_detail', user_id=user_id)

@login_required
@user_management_required
@require_POST
def assign_role(request, user_id):
    """Assegna ruolo a utente"""
    user = get_object_or_404(User, id=user_id)
    role_id = request.POST.get('role_id')
    expires_at = request.POST.get('expires_at')
    notes = request.POST.get('notes', '')
    
    if not role_id:
        messages.error(request, 'Ruolo non specificato')
        return redirect('Cripto1:user_detail', user_id=user_id)
    
    try:
        role = Role.objects.get(id=role_id, is_active=True)
        
        # Controlla se il ruolo è già assegnato e attivo
        existing_role = UserRole.objects.filter(
            user=user, 
            role=role, 
            is_active=True
        ).first()
        
        if existing_role:
            messages.error(request, f'Ruolo {role.name} già assegnato a questo utente')
        else:
            # Converti la data di scadenza se fornita
            expires_date = None
            if expires_at:
                try:
                    expires_date = timezone.datetime.strptime(expires_at, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                except ValueError:
                    messages.error(request, 'Formato data non valido')
                    return redirect('Cripto1:user_detail', user_id=user_id)
            
            # Crea l'assegnazione
            user_role = UserRole.objects.create(
                user=user,
                role=role,
                assigned_by=request.user,
                expires_at=expires_date,
                notes=notes,
                is_active=True
            )
            
            # Aggiorna il profilo utente per riflettere i cambiamenti
            try:
                user_profile = UserProfile.objects.get(user=user)
                user_profile.refresh_roles_cache()
            except UserProfile.DoesNotExist:
                pass
            
            # Log dell'azione
            AuditLog.log_action(
                action_type='ROLE_ASSIGNMENT',
                description=f'Ruolo {role.name} assegnato a {user.username} da {request.user.username}',
                severity='MEDIUM',
                user=request.user,
                ip_address=request.META.get('REMOTE_ADDR'),
                related_object_type='UserRole',
                related_object_id=user_role.id,
                additional_data={
                    'assigned_role': role.name,
                    'expires_at': expires_at,
                    'notes': notes
                },
                success=True
            )
            
            messages.success(request, f'Ruolo {role.name} assegnato con successo')
            
    except Role.DoesNotExist:
        messages.error(request, 'Ruolo non trovato o non attivo')
    except Exception as e:
        messages.error(request, f'Errore durante l\'assegnazione del ruolo: {str(e)}')
        print(f"Errore assegnazione ruolo: {e}")
    
    return redirect('Cripto1:user_detail', user_id=user_id)

@login_required
@user_management_required
@require_POST
def remove_role(request, user_id, role_id):
    """Rimuove ruolo da utente"""
    user = get_object_or_404(User, id=user_id)
    role = get_object_or_404(Role, id=role_id)
    
    print(f"DEBUG: Tentativo di rimozione ruolo {role.name} da utente {user.username}")
    
    try:
        # Trova l'assegnazione ruolo attiva
        user_role = UserRole.objects.get(
            user=user, 
            role=role, 
            is_active=True
        )
        
        print(f"DEBUG: Trovata assegnazione ruolo: {user_role}")
        
        # Disattiva l'assegnazione
        user_role.is_active = False
        user_role.save()
        
        print(f"DEBUG: Ruolo disattivato con successo")
        
        # Aggiorna il profilo utente per riflettere i cambiamenti
        try:
            user_profile = UserProfile.objects.get(user=user)
            user_profile.refresh_roles_cache()
        except UserProfile.DoesNotExist:
            pass
        
        # Log dell'azione
        AuditLog.log_action(
            action_type='ROLE_ASSIGNMENT',
            description=f'Ruolo {role.name} rimosso da {user.username} da {request.user.username}',
            severity='MEDIUM',
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            related_object_type='UserRole',
            related_object_id=user_role.id,
            additional_data={
                'removed_role': role.name,
                'removed_at': timezone.now().isoformat()
            },
            success=True
        )
        
        messages.success(request, f'Ruolo {role.name} rimosso con successo')
        
    except UserRole.DoesNotExist:
        print(f"DEBUG: Assegnazione ruolo non trovata")
        messages.error(request, f'Assegnazione ruolo {role.name} non trovata o già rimossa')
    except Exception as e:
        print(f"DEBUG: Errore durante la rimozione: {e}")
        messages.error(request, f'Errore durante la rimozione del ruolo: {str(e)}')
        print(f"Errore rimozione ruolo: {e}")
    
    return redirect('Cripto1:user_detail', user_id=user_id)

@login_required
@user_management_required
def role_list(request):
    """Lista dei ruoli"""
    roles = Role.objects.all().prefetch_related(
        'permissions', 
        'user_assignments'
    ).order_by('name')
    
    context = {
        'roles': roles
    }
    return render(request, 'Cripto1/user_management/role_list.html', context)

@login_required
@user_management_required
def role_detail(request, role_id):
    """Dettaglio ruolo"""
    role = get_object_or_404(Role, id=role_id)

    # Mostra solo utenti con ruolo attivo e non scaduto
    user_roles = UserRole.objects.filter(
        role=role,
        is_active=True
    ).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
    ).select_related('user', 'assigned_by').order_by('-assigned_at')

    # Permessi disponibili per l'aggiunta
    available_permissions = Permission.objects.filter(
        is_active=True
    ).exclude(
        role=role
    ).order_by('category', 'name')

    # Calcola le statistiche corrette
    total_assignments = UserRole.objects.filter(role=role).count()
    active_assignments = UserRole.objects.filter(role=role, is_active=True).count()
    expired_assignments = UserRole.objects.filter(
        role=role, 
        is_active=True,
        expires_at__lt=timezone.now()
    ).count()

    context = {
        'role': role,
        'user_roles': user_roles,
        'available_permissions': available_permissions,
        'total_assignments': total_assignments,
        'active_assignments': active_assignments,
        'expired_assignments': expired_assignments,
    }
    return render(request, 'Cripto1/user_management/role_detail.html', context)

@login_required
@user_management_required
def create_role(request):
    """Creazione nuovo ruolo"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        permissions = request.POST.getlist('permissions')
        is_active = request.POST.get('is_active') == 'on'
        is_system_role = request.POST.get('is_system_role') == 'on'
        notes = request.POST.get('notes', '')
        
        if not name:
            messages.error(request, 'Nome ruolo è obbligatorio')
            return render(request, 'Cripto1/user_management/create_role.html', {'permissions': Permission.objects.filter(is_active=True)})
        
        if Role.objects.filter(name=name).exists():
            messages.error(request, 'Nome ruolo già esistente')
            return render(request, 'Cripto1/user_management/create_role.html', {'permissions': Permission.objects.filter(is_active=True)})
        
        try:
            with transaction.atomic():
                # Crea il ruolo
                role = Role.objects.create(
                    name=name,
                    description=description,
                    is_active=is_active,
                    is_system_role=is_system_role
                )
                
                # Assegna i permessi
                if permissions:
                    role.permissions.set(permissions)
                
                # Log dell'azione
                AuditLog.log_action(
                    action_type='USER_MANAGEMENT',
                    description=f'Ruolo {name} creato da {request.user.username}',
                    severity='MEDIUM',
                    user=request.user,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    related_object_type='Role',
                    related_object_id=role.id,
                    additional_data={
                        'created_role': name,
                        'permissions_count': len(permissions),
                        'is_system_role': is_system_role
                    },
                    success=True
                )
                
                messages.success(request, f'Ruolo {name} creato con successo')
                return redirect('Cripto1:role_detail', role_id=role.id)
                
        except Exception as e:
            messages.error(request, f'Errore durante la creazione: {str(e)}')
            print(f"Errore creazione ruolo: {e}")
    
    context = {
        'permissions': Permission.objects.filter(is_active=True).order_by('category', 'name')
    }
    return render(request, 'Cripto1/user_management/create_role.html', context)

def debug_permissions(request):
    """Vista di debug per testare i permessi dell'utente corrente"""
    if not request.user.is_authenticated:
        return redirect('Cripto1:login')
    
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        
        # Test dei permessi principali
        test_permissions = [
            'view_users', 'add_users', 'edit_users', 'delete_users', 
            'activate_users', 'assign_roles', 'manage_roles',
            'view_transactions', 'create_transactions', 'view_blockchain'
        ]
        
        permission_results = user_profile.test_permissions(test_permissions)
        permissions_summary = user_profile.get_permissions_summary()
        
        context = {
            'user': request.user,
            'profile': user_profile,
            'roles': [role.name for role in user_profile.get_roles()],
            'permission_tests': permission_results,
            'permissions_summary': permissions_summary
        }
        
        return render(request, 'Cripto1/debug_permissions.html', context)
        
    except UserProfile.DoesNotExist:
        messages.error(request, 'Profilo utente non trovato.')
        return redirect('Cripto1:dashboard')
    except Exception as e:
        messages.error(request, f'Errore durante il debug: {str(e)}')
        return redirect('Cripto1:dashboard')
