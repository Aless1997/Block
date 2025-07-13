from django.contrib import admin
from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy
from django.urls import path

app_name = 'Cripto1'

urlpatterns = [
    path('', views.homepage, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # User dashboard and profile
    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.personal_profile, name='personal_profile'),
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('users/', views.users_feed, name='users_feed'),
    path('all-transactions/', views.all_transactions_view, name='all_transactions'),
    path('unviewed-transactions/', views.unviewed_transactions_list, name='unviewed_transactions_list'),


    # Transaction URLs
    path('transaction/create/', views.create_transaction, name='create_transaction'),
    path('transaction/<int:transaction_id>/', views.transaction_details, name='transaction_details'),
    path('transaction/<int:transaction_id>/download/', views.download_file, name='download_file'),
    path('transaction/decrypt/', views.decrypt_transaction, name='decrypt_transaction'),

    # Custom Admin URLs (NON devono iniziare solo con 'admin/', per evitare conflitti)
    path('admdashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admdashboard/verify-blockchain/', views.verify_blockchain, name='verify_blockchain'),
    path('admdashboard/export/<str:model>/', views.export_csv, name='export_csv'),
    path('admdashboard/user/<int:user_id>/', views.admin_user_detail, name='admin_user_detail'),


    # Audit Log URLs
    path('audit-logs/', views.audit_logs_view, name='audit_logs'),
    path('audit-logs/<int:log_id>/', views.audit_log_detail, name='audit_log_detail'),
    path('audit-logs/export/', views.export_audit_logs, name='export_audit_logs'),
    path('audit-logs/analytics/', views.audit_logs_analytics, name='audit_logs_analytics'),
    path('security-alerts/', views.security_alerts, name='security_alerts'),

    # User Management URLs
    path('user-management/', views.user_management_dashboard, name='user_management_dashboard'),
    path('user-management/users/', views.user_list, name='user_list'),
    path('user-management/users/create/', views.create_user, name='create_user'),
    path('user-management/users/<int:user_id>/', views.user_detail, name='user_detail'),
    path('user-management/users/<int:user_id>/edit/', views.edit_user, name='edit_user'),
    path('user-management/users/<int:user_id>/toggle-status/', views.toggle_user_status, name='toggle_user_status'),
    path('user-management/users/<int:user_id>/assign-role/', views.assign_role, name='assign_role'),
    path('user-management/users/<int:user_id>/remove-role/<int:role_id>/', views.remove_role, name='remove_role'),

    
    # Role Management URLs
    path('user-management/roles/', views.role_list, name='role_list'),
    path('user-management/roles/create/', views.create_role, name='create_role'),
    path('user-management/roles/<int:role_id>/', views.role_detail, name='role_detail'),

    # Debug URLs
    path('debug/permissions/', views.debug_permissions, name='debug_permissions'),

    # Blockchain mining
    path('mine-block/', views.mine_block, name='mine_block'),

    # Password change
    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='registration/password_change_form.html', success_url=reverse_lazy('Cripto1:password_change_done')), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='registration/password_change_done.html'), name='password_change_done'),

    # Django admin (deve essere l'ULTIMA e fuori dal blocco app)
    path('admin/', admin.site.urls),
    # Aggiungi questa riga per il pattern backup_management
    path('admdashboard/backup/', views.backup_management, name='backup_management'),
    # Aggiungi questa riga alle URL esistenti
    path('admdashboard/backup/upload/', views.upload_backup, name='upload_backup'),
    path('admdashboard/backup/download/<str:filename>/', views.download_backup, name='download_backup'),
]