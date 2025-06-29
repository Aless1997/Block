from django.contrib import admin
from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy
from django.urls import path
from . import views

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
    path('profile/reset-private-key-password/', views.reset_private_key_password, name='reset_private_key_password'),

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
    path('admdashboard/user/<int:user_id>/regenerate-key/', views.regenerate_user_private_key, name='regenerate_user_private_key'),

    # Audit Log URLs
    path('audit-logs/', views.audit_logs_view, name='audit_logs'),
    path('audit-logs/<int:log_id>/', views.audit_log_detail, name='audit_log_detail'),
    path('audit-logs/export/', views.export_audit_logs, name='export_audit_logs'),
    path('audit-logs/analytics/', views.audit_logs_analytics, name='audit_logs_analytics'),
    path('security-alerts/', views.security_alerts, name='security_alerts'),

    # Blockchain mining
    path('mine-block/', views.mine_block, name='mine_block'),

    # Password change
    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='registration/password_change_form.html', success_url=reverse_lazy('Cripto1:password_change_done')), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='registration/password_change_done.html'), name='password_change_done'),

    # Django admin (deve essere l'ULTIMA e fuori dal blocco app)
    path('admin/', admin.site.urls),
]