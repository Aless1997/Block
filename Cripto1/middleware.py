from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect
from django.contrib import messages
from django.utils import timezone
from .models import AuditLog, UserProfile
import json
print("=== AuditLogMiddleware caricato ===")

class AuditLogMiddleware(MiddlewareMixin):
    """
    Middleware per tracciare automaticamente le azioni degli utenti
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        # Lista delle azioni da tracciare automaticamente
        self.tracked_actions = {
            'login_view': 'LOGIN',
            'logout_view': 'LOGOUT',
            'register': 'REGISTER',
            'create_transaction': 'CREATE_TRANSACTION',
            'transaction_details': 'VIEW_TRANSACTION',
            'download_file': 'DOWNLOAD_FILE',
            'decrypt_transaction': 'DECRYPT_MESSAGE',
            'mine_block': 'MINE_BLOCK',
            'edit_profile': 'EDIT_PROFILE',
            'reset_private_key_password': 'RESET_PRIVATE_KEY',
            'admin_dashboard': 'ADMIN_ACTION',
            'verify_blockchain': 'VERIFY_BLOCKCHAIN',
            'export_csv': 'EXPORT_DATA',
            'admin_user_detail': 'USER_MANAGEMENT',
            'regenerate_user_private_key': 'USER_MANAGEMENT',
        }

    def process_request(self, request):
        # Salva informazioni della richiesta per uso successivo
        request.audit_info = {
            'ip_address': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'session_id': request.session.session_key or '',
        }
        return None

    def process_response(self, request, response):
        print(f"[DEBUG] process_response chiamato per path: {request.path}")
        if hasattr(request, 'resolver_match'):
            view_name = getattr(request.resolver_match, 'view_name', None)
            print(f"[DEBUG] view_name: {view_name}")
        else:
            view_name = None
            print("[DEBUG] Nessun resolver_match su request")
        # Loggo tutte le view per test
        self.log_action(request, view_name, response)
        return response

    def get_client_ip(self, request):
        """Ottiene l'IP reale del client anche dietro proxy"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def log_action(self, request, view_name, response):
        try:
            action_type = view_name or 'SYSTEM_EVENT'
            print(f"[AUDIT DEBUG] user={getattr(request, 'user', None)}, action_type={action_type}, path={request.path}")
            # Determina la severità basata sul tipo di azione
            severity = self.get_severity(action_type)
            # Crea la descrizione
            description = self.create_description(request, view_name, response)
            # Dati aggiuntivi
            additional_data = self.get_additional_data(request, view_name)
            # Determina se l'azione è stata completata con successo
            success = response.status_code < 400
            # Messaggio di errore se presente
            error_message = ""
            if not success:
                error_message = f"HTTP {response.status_code}"
            # Crea l'audit log
            from Cripto1.models import AuditLog
            AuditLog.log_action(
                user=request.user if hasattr(request, 'user') and getattr(request, 'user', None) and request.user.is_authenticated else None,
                action_type=action_type,
                description=description,
                severity=severity,
                ip_address=getattr(request, 'audit_info', {}).get('ip_address'),
                user_agent=getattr(request, 'audit_info', {}).get('user_agent'),
                session_id=getattr(request, 'audit_info', {}).get('session_id'),
                additional_data=additional_data,
                success=success,
                error_message=error_message
            )
        except Exception as e:
            import traceback
            print(f"ERROR: Failed to create audit log: {e}")
            traceback.print_exc()

    def get_severity(self, action_type):
        """Determina la severità dell'azione"""
        high_severity = ['LOGIN', 'LOGOUT', 'REGISTER', 'RESET_PRIVATE_KEY', 'ADMIN_ACTION']
        critical_severity = ['SECURITY_EVENT']
        
        if action_type in critical_severity:
            return 'CRITICAL'
        elif action_type in high_severity:
            return 'HIGH'
        else:
            return 'MEDIUM'

    def create_description(self, request, view_name, response):
        """Crea una descrizione dettagliata dell'azione"""
        descriptions = {
            'login_view': f"Tentativo di login per utente",
            'logout_view': f"Logout utente",
            'register': f"Registrazione nuovo utente",
            'create_transaction': f"Creazione nuova transazione",
            'transaction_details': f"Visualizzazione dettagli transazione",
            'download_file': f"Download file da transazione",
            'decrypt_transaction': f"Decifratura messaggio",
            'mine_block': f"Mining nuovo blocco",
            'edit_profile': f"Modifica profilo utente",
            'reset_private_key_password': f"Reset password chiave privata",
            'admin_dashboard': f"Accesso dashboard amministrativa",
            'verify_blockchain': f"Verifica integrità blockchain",
            'export_csv': f"Export dati in CSV",
            'admin_user_detail': f"Visualizzazione dettagli utente",
            'regenerate_user_private_key': f"Rigenerazione chiave privata utente",
        }
        
        base_description = descriptions.get(view_name, f"Azione: {view_name}")
        
        # Aggiungi dettagli specifici
        if view_name == 'create_transaction':
            transaction_type = request.POST.get('type', 'unknown')
            base_description += f" (Tipo: {transaction_type})"
        elif view_name == 'transaction_details':
            transaction_id = request.resolver_match.kwargs.get('transaction_id', 'unknown')
            base_description += f" (ID: {transaction_id})"
        elif view_name == 'download_file':
            transaction_id = request.resolver_match.kwargs.get('transaction_id', 'unknown')
            base_description += f" (ID: {transaction_id})"
        elif view_name == 'admin_user_detail':
            user_id = request.resolver_match.kwargs.get('user_id', 'unknown')
            base_description += f" (User ID: {user_id})"
        
        return base_description

    def get_additional_data(self, request, view_name):
        """Raccoglie dati aggiuntivi per l'audit log"""
        data = {
            'method': request.method,
            'path': request.path,
            'view_name': view_name,
        }
        
        # Aggiungi parametri specifici per alcune azioni
        if view_name == 'create_transaction':
            data['transaction_type'] = request.POST.get('type', '')
            data['is_encrypted'] = request.POST.get('is_encrypted', 'false')
        elif view_name == 'transaction_details':
            data['transaction_id'] = request.resolver_match.kwargs.get('transaction_id')
        elif view_name == 'download_file':
            data['transaction_id'] = request.resolver_match.kwargs.get('transaction_id')
        elif view_name == 'admin_user_detail':
            data['target_user_id'] = request.resolver_match.kwargs.get('user_id')
        
        return data


class SecurityMiddleware(MiddlewareMixin):
    """
    Middleware per la gestione della sicurezza e dei tentativi di login
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        # Percorsi esenti dal controllo di sicurezza
        self.exempt_paths = [
            '/admin/',
            '/static/',
            '/media/',
            '/favicon.ico',
        ]
    
    def process_request(self, request):
        # Controlla se il percorso è esente
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return None
        
        # Gestione tentativi di login falliti
        if request.path == '/login/' and request.method == 'POST':
            self.handle_login_attempt(request)
        
        # Controllo account bloccati per utenti autenticati
        if hasattr(request, 'user') and request.user.is_authenticated:
            self.check_user_status(request)
        
        return None
    
    def handle_login_attempt(self, request):
        """Gestisce i tentativi di login e il blocco account"""
        username = request.POST.get('username')
        if not username:
            return
        
        try:
            user = UserProfile.objects.get(user__username=username)
            
            # Se l'account è bloccato, incrementa i tentativi e logga
            if user.is_locked():
                user.increment_login_attempts()
                
                # Log dell'evento di sicurezza
                AuditLog.log_action(
                    action_type='SECURITY_EVENT',
                    description=f'Tentativo di login su account bloccato: {username}',
                    severity='HIGH',
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=False,
                    error_message='Account temporaneamente bloccato'
                )
                
                messages.error(request, 'Account temporaneamente bloccato. Riprova più tardi.')
                return
            
            # Se il login fallisce, incrementa i tentativi
            if request.method == 'POST' and hasattr(request, 'resolver_match') and request.resolver_match and 'login_view' in request.resolver_match.view_name:
                # Il controllo del successo del login viene fatto nella view
                # Qui gestiamo solo il fallimento
                pass
                
        except UserProfile.DoesNotExist:
            # Log del tentativo di login con username inesistente
            AuditLog.log_action(
                action_type='SECURITY_EVENT',
                description=f'Tentativo di login con username inesistente: {username}',
                severity='MEDIUM',
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                error_message='Username non trovato'
            )
    
    def check_user_status(self, request):
        """Controlla lo stato dell'utente autenticato"""
        try:
            user_profile = UserProfile.objects.get(user=request.user)
            
            # Controlla se l'account è attivo
            if not user_profile.is_active:
                messages.error(request, 'Il tuo account è stato disattivato.')
                from django.contrib.auth import logout
                logout(request)
                return redirect('Cripto1:login')
            
            # Controlla se l'account è bloccato
            if user_profile.is_locked():
                messages.error(request, 'Il tuo account è temporaneamente bloccato.')
                from django.contrib.auth import logout
                logout(request)
                return redirect('Cripto1:login')
            
            # Aggiorna le informazioni dell'ultimo login
            if not hasattr(request, '_last_login_updated'):
                user_profile.update_last_login(self.get_client_ip(request))
                request._last_login_updated = True
                
        except UserProfile.DoesNotExist:
            # Se non esiste un profilo, creane uno
            UserProfile.objects.create(user=request.user)
    
    def get_client_ip(self, request):
        """Ottiene l'IP reale del client anche dietro proxy"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip 