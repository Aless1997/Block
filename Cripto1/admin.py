from django.contrib import admin
from django.http import HttpResponse
import csv
from Cripto1.models import BlockchainState, Transaction, UserProfile, Block, SmartContract, AuditLog

class ExportCsvMixin:
    def export_as_csv(self, request, queryset):
        meta = self.model._meta
        field_names = [field.name for field in meta.fields]

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename={}.csv'.format(meta)
        writer = csv.writer(response)

        writer.writerow(field_names)
        for obj in queryset:
            writer.writerow([getattr(obj, field) for field in field_names])

        return response

    export_as_csv.short_description = "Export Selected to CSV"

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = ['id', 'timestamp', 'user', 'action_type', 'severity', 'ip_address', 'success', 'description']
    list_filter = ['action_type', 'severity', 'success', 'timestamp', 'user']
    search_fields = ['user__username', 'description', 'ip_address', 'user_agent']
    readonly_fields = ['timestamp', 'user', 'action_type', 'severity', 'description', 'ip_address', 
                      'user_agent', 'session_id', 'related_object_type', 'related_object_id', 
                      'additional_data', 'success', 'error_message']
    date_hierarchy = 'timestamp'
    list_per_page = 100
    
    actions = ["export_as_csv", "mark_as_critical", "mark_as_high"]
    
    fieldsets = (
        ('Informazioni Base', {
            'fields': ('timestamp', 'user', 'action_type', 'severity', 'success')
        }),
        ('Dettagli Azione', {
            'fields': ('description', 'error_message')
        }),
        ('Informazioni Tecniche', {
            'fields': ('ip_address', 'user_agent', 'session_id')
        }),
        ('Oggetti Correlati', {
            'fields': ('related_object_type', 'related_object_id')
        }),
        ('Dati Aggiuntivi', {
            'fields': ('additional_data',),
            'classes': ('collapse',)
        }),
    )
    
    def mark_as_critical(self, request, queryset):
        queryset.update(severity='CRITICAL')
    mark_as_critical.short_description = "Segna come critico"
    
    def mark_as_high(self, request, queryset):
        queryset.update(severity='HIGH')
    mark_as_high.short_description = "Segna come alto"

@admin.register(BlockchainState)
class BlockchainStateAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in BlockchainState._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in Transaction._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in UserProfile._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True

@admin.register(Block)
class BlockAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in Block._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True

@admin.register(SmartContract)
class SmartContractAdmin(admin.ModelAdmin, ExportCsvMixin):
    list_display = [field.name for field in SmartContract._meta.fields]
    actions = ["export_as_csv"]
    actions_on_top = True
    actions_on_bottom = True
    fields = [field.name for field in SmartContract._meta.fields]



