from django.contrib import admin
from django.http import HttpResponse
import csv
from Cripto1.models import BlockchainState, Transaction, UserProfile, Block, SmartContract

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



