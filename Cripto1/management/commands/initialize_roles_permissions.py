from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from Cripto1.models import Permission, Role, UserProfile, AuditLog


class Command(BaseCommand):
    help = 'Inizializza i ruoli e permessi di default del sistema'

    def handle(self, *args, **options):
        self.stdout.write('Inizializzazione ruoli e permessi...')
        
        # Creazione permessi
        permissions_data = [
            # Gestione Utenti
            ('view_users', 'Visualizza Utenti', 'Visualizzare la lista degli utenti', 'USER_MANAGEMENT'),
            ('add_users', 'Aggiungi Utenti', 'Creare nuovi utenti', 'USER_MANAGEMENT'),
            ('edit_users', 'Modifica Utenti', 'Modificare i dati degli utenti', 'USER_MANAGEMENT'),
            ('delete_users', 'Elimina Utenti', 'Eliminare utenti', 'USER_MANAGEMENT'),
            ('assign_roles', 'Assegna Ruoli', 'Assegnare ruoli agli utenti', 'USER_MANAGEMENT'),
            ('manage_roles', 'Gestisci Ruoli', 'Creare e modificare ruoli', 'USER_MANAGEMENT'),
            ('activate_users', 'Attiva Utenti', 'Attivare/disattivare utenti', 'USER_MANAGEMENT'),
            
            # Gestione Transazioni
            ('view_transactions', 'Visualizza Transazioni', 'Visualizzare le transazioni', 'TRANSACTION_MANAGEMENT'),
            ('create_transactions', 'Crea Transazioni', 'Creare nuove transazioni', 'TRANSACTION_MANAGEMENT'),
            ('edit_transactions', 'Modifica Transazioni', 'Modificare le transazioni', 'TRANSACTION_MANAGEMENT'),
            ('delete_transactions', 'Elimina Transazioni', 'Eliminare transazioni', 'TRANSACTION_MANAGEMENT'),
            ('decrypt_transactions', 'Decripta Transazioni', 'Decriptare contenuti delle transazioni', 'TRANSACTION_MANAGEMENT'),
            ('download_files', 'Download File', 'Scaricare file dalle transazioni', 'TRANSACTION_MANAGEMENT'),
            
            # Gestione Blockchain
            ('view_blockchain', 'Visualizza Blockchain', 'Visualizzare lo stato della blockchain', 'BLOCKCHAIN_MANAGEMENT'),
            ('mine_blocks', 'Mina Blocchi', 'Eseguire il mining di nuovi blocchi', 'BLOCKCHAIN_MANAGEMENT'),
            ('verify_blockchain', 'Verifica Blockchain', 'Verificare l\'integrità della blockchain', 'BLOCKCHAIN_MANAGEMENT'),
            ('manage_smart_contracts', 'Gestisci Smart Contract', 'Creare e gestire smart contract', 'BLOCKCHAIN_MANAGEMENT'),
            
            # Amministrazione Sistema
            ('system_config', 'Configurazione Sistema', 'Modificare le configurazioni di sistema', 'SYSTEM_ADMIN'),
            ('database_management', 'Gestione Database', 'Gestire il database', 'SYSTEM_ADMIN'),
            ('backup_restore', 'Backup e Ripristino', 'Eseguire backup e ripristini', 'SYSTEM_ADMIN'),
            ('system_monitoring', 'Monitoraggio Sistema', 'Monitorare le performance del sistema', 'SYSTEM_ADMIN'),
            
            # Log di Audit
            ('view_audit_logs', 'Visualizza Log Audit', 'Visualizzare i log di audit', 'AUDIT_LOGS'),
            ('export_audit_logs', 'Esporta Log Audit', 'Esportare i log di audit', 'AUDIT_LOGS'),
            ('audit_analytics', 'Analytics Audit', 'Visualizzare analytics dei log', 'AUDIT_LOGS'),
            ('security_alerts', 'Allerte Sicurezza', 'Gestire le allerte di sicurezza', 'AUDIT_LOGS'),
            
            # Sicurezza
            ('security_settings', 'Impostazioni Sicurezza', 'Modificare le impostazioni di sicurezza', 'SECURITY'),
            ('password_policies', 'Politiche Password', 'Gestire le politiche delle password', 'SECURITY'),
            ('access_control', 'Controllo Accessi', 'Gestire il controllo degli accessi', 'SECURITY'),
            ('encryption_management', 'Gestione Cifratura', 'Gestire le chiavi di cifratura', 'SECURITY'),
            
            # Report e Analytics
            ('view_reports', 'Visualizza Report', 'Visualizzare i report del sistema', 'REPORTS'),
            ('generate_reports', 'Genera Report', 'Generare nuovi report', 'REPORTS'),
            ('export_data', 'Esporta Dati', 'Esportare dati del sistema', 'REPORTS'),
            ('analytics_dashboard', 'Dashboard Analytics', 'Accesso al dashboard analytics', 'REPORTS'),
        ]
        
        created_permissions = []
        for codename, name, description, category in permissions_data:
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                defaults={
                    'name': name,
                    'description': description,
                    'category': category,
                }
            )
            if created:
                created_permissions.append(permission)
                self.stdout.write(f'  Creato permesso: {name}')
        
        # Creazione ruoli
        roles_data = [
            {
                'name': 'Super Admin',
                'description': 'Amministratore completo del sistema con tutti i permessi',
                'is_system_role': True,
                'permissions': [p.codename for p in Permission.objects.all()]
            },
            {
                'name': 'Admin',
                'description': 'Amministratore del sistema con permessi elevati',
                'is_system_role': True,
                'permissions': [
                    'view_users', 'add_users', 'edit_users', 'assign_roles', 'activate_users',
                    'view_transactions', 'create_transactions', 'edit_transactions', 'decrypt_transactions', 'download_files',
                    'view_blockchain', 'mine_blocks', 'verify_blockchain', 'manage_smart_contracts',
                    'view_audit_logs', 'export_audit_logs', 'audit_analytics', 'security_alerts',
                    'view_reports', 'generate_reports', 'export_data', 'analytics_dashboard'
                ]
            },
            {
                'name': 'Manager',
                'description': 'Manager con permessi di supervisione',
                'is_system_role': False,
                'permissions': [
                    'view_users', 'edit_users', 'assign_roles',
                    'view_transactions', 'create_transactions', 'edit_transactions', 'decrypt_transactions', 'download_files',
                    'view_blockchain', 'mine_blocks', 'verify_blockchain',
                    'view_audit_logs', 'export_audit_logs',
                    'view_reports', 'generate_reports', 'export_data'
                ]
            },
            {
                'name': 'Dipendente',
                'description': 'Dipendente con permessi base',
                'is_system_role': False,
                'permissions': [
                    'view_transactions', 'create_transactions', 'decrypt_transactions', 'download_files',
                    'view_blockchain', 'mine_blocks',
                    'view_reports'
                ]
            },
            {
                'name': 'Utente Base',
                'description': 'Utente con permessi minimi',
                'is_system_role': False,
                'permissions': [
                    'view_transactions', 'create_transactions', 'decrypt_transactions', 'download_files',
                    'view_blockchain'
                ]
            },
            {
                'name': 'Solo Lettura',
                'description': 'Utente con permessi di sola lettura',
                'is_system_role': False,
                'permissions': [
                    'view_transactions', 'view_blockchain', 'view_reports'
                ]
            }
        ]
        
        created_roles = []
        for role_data in roles_data:
            role, created = Role.objects.get_or_create(
                name=role_data['name'],
                defaults={
                    'description': role_data['description'],
                    'is_system_role': role_data['is_system_role']
                }
            )
            
            # Assegna i permessi al ruolo
            for permission_codename in role_data['permissions']:
                try:
                    permission = Permission.objects.get(codename=permission_codename)
                    role.permissions.add(permission)
                except Permission.DoesNotExist:
                    self.stdout.write(f'  Permesso non trovato: {permission_codename}')
            
            if created:
                created_roles.append(role)
                self.stdout.write(f'  Creato ruolo: {role.name}')
        
        # Assegna il ruolo Super Admin al primo superuser
        try:
            superuser = User.objects.filter(is_superuser=True).first()
            if superuser:
                user_profile, created = UserProfile.objects.get_or_create(user=superuser)
                super_admin_role = Role.objects.get(name='Super Admin')
                user_profile.assign_role(super_admin_role, assigned_by=superuser)
                self.stdout.write(f'  Assegnato ruolo Super Admin a: {superuser.username}')
        except Exception as e:
            self.stdout.write(f'  Errore nell\'assegnazione del ruolo Super Admin: {e}')
        
        # Log dell'inizializzazione
        AuditLog.log_action(
            action_type='SYSTEM_EVENT',
            description='Inizializzazione ruoli e permessi di sistema completata',
            severity='MEDIUM',
            additional_data={
                'permissions_created': len(created_permissions),
                'roles_created': len(created_roles)
            }
        )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Inizializzazione completata! Creati {len(created_permissions)} permessi e {len(created_roles)} ruoli.'
            )
        ) 