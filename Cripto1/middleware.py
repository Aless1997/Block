from django.utils.deprecation import MiddlewareMixin
from .models import AuditLog
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