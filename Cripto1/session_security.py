from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib import messages
from django.core.cache import caches
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import hashlib
import json

class AdvancedSessionSecurityMiddleware(MiddlewareMixin):
    # Attributo richiesto da Django per la compatibilità async/sync
    async_mode = False
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.session_cache = caches['sessions'] if 'sessions' in settings.CACHES else caches['default']
        super().__init__(get_response)
        
    def process_request(self, request):
        if not getattr(settings, 'SESSION_SECURITY_ENABLED', False):
            return None
            
        # Controllo se request.user è disponibile
        if not hasattr(request, 'user'):
            return None
            
        if not request.user.is_authenticated:
            return None
            
        # Verifica validità sessione
        if not self.validate_session(request):
            logout(request)
            messages.error(request, 'Sessione scaduta o non valida. Effettua nuovamente il login.')
            return redirect('Cripto1:login')
            
        # Aggiorna attività sessione
        self.update_session_activity(request)
        
        # Verifica timeout personalizzato
        if self.is_session_expired(request):
            logout(request)
            messages.warning(request, 'Sessione scaduta per inattività.')
            return redirect('Cripto1:login')
            
        return None
        
    def validate_session(self, request):
        """Valida integrità della sessione"""
        session_key = request.session.session_key
        if not session_key:
            return False
            
        # Verifica IP se abilitata
        if getattr(settings, 'SESSION_IP_VALIDATION', False):
            stored_ip = request.session.get('_session_ip')
            current_ip = self.get_client_ip(request)
            if stored_ip and stored_ip != current_ip:
                return False
            request.session['_session_ip'] = current_ip
            
        # Verifica User-Agent se abilitata
        if getattr(settings, 'SESSION_USER_AGENT_VALIDATION', False):
            stored_ua = request.session.get('_session_user_agent')
            current_ua = request.META.get('HTTP_USER_AGENT', '')
            ua_hash = hashlib.sha256(current_ua.encode()).hexdigest()
            if stored_ua and stored_ua != ua_hash:
                return False
            request.session['_session_user_agent'] = ua_hash
            
        # Verifica sessioni concorrenti
        if not self.check_concurrent_sessions(request):
            return False
            
        return True
        
    def check_concurrent_sessions(self, request):
        """Controlla il numero di sessioni concorrenti"""
        max_concurrent = getattr(settings, 'SESSION_MAX_CONCURRENT', 3)
        user_id = request.user.id
        session_key = request.session.session_key
        
        # Chiave cache per le sessioni dell'utente
        cache_key = f'user_sessions_{user_id}'
        user_sessions = self.session_cache.get(cache_key, [])
        
        # Rimuovi sessioni scadute
        current_time = timezone.now().timestamp()
        active_sessions = []
        for session_data in user_sessions:
            if session_data['expires'] > current_time:
                active_sessions.append(session_data)
                
        # Aggiungi/aggiorna sessione corrente
        session_found = False
        for i, session_data in enumerate(active_sessions):
            if session_data['session_key'] == session_key:
                active_sessions[i]['last_activity'] = current_time
                active_sessions[i]['expires'] = current_time + self.get_session_timeout(request)
                session_found = True
                break
                
        if not session_found:
            if len(active_sessions) >= max_concurrent:
                # Rimuovi la sessione più vecchia
                active_sessions.sort(key=lambda x: x['last_activity'])
                active_sessions.pop(0)
                
            active_sessions.append({
                'session_key': session_key,
                'last_activity': current_time,
                'expires': current_time + self.get_session_timeout(request),
                'ip_address': self.get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:100]
            })
            
        # Salva in cache
        self.session_cache.set(cache_key, active_sessions, 3600)
        return True
        
    def get_session_timeout(self, request):
        """Ottiene il timeout della sessione basato sul ruolo utente"""
        user = request.user
        
        # Controlla se è admin
        if user.is_superuser or user.is_staff:
            return getattr(settings, 'SESSION_TIMEOUT_ADMIN', 3600)
            
        # Controlla ruolo utente
        try:
            user_profile = user.userprofile
            if hasattr(user_profile, 'role') and user_profile.role:
                if 'external' in user_profile.role.lower():
                    return getattr(settings, 'SESSION_TIMEOUT_EXTERNAL', 900)
        except:
            pass
            
        return getattr(settings, 'SESSION_TIMEOUT_USER', 1800)
        
    def is_session_expired(self, request):
        """Verifica se la sessione è scaduta per inattività"""
        last_activity = request.session.get('_last_activity')
        if not last_activity:
            return False
            
        inactivity_timeout = getattr(settings, 'SESSION_INACTIVITY_TIMEOUT', 900)
        current_time = timezone.now().timestamp()
        
        return (current_time - last_activity) > inactivity_timeout
        
    def update_session_activity(self, request):
        """Aggiorna timestamp ultima attività"""
        request.session['_last_activity'] = timezone.now().timestamp()
        
    def get_client_ip(self, request):
        """Ottiene IP del client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')