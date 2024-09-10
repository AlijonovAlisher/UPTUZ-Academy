from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User

class UserAdmin(BaseUserAdmin):
    model = User
    ordering = ['-created_at']
    list_display = (
        'email', 'username', 'first_name', 'last_name', 'phone_number', 'is_active', 'is_verified', 'is_staff'
    )
    list_filter = ('is_active', 'is_verified', 'is_staff')
    search_fields = ('email', 'username', 'first_name', 'last_name', 'phone_number')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'phone_number')}),
        (_('Permissions'),
         {'fields': ('is_active', 'is_verified', 'is_staff', 'is_superuser')}),
        (_('Important dates'), {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'first_name', 'last_name', 'phone_number', 'password1', 'password2'),
        }),
    )

    def get_readonly_fields(self, request, obj=None):
        if obj:  # Editing an existing user
            return self.readonly_fields + ('email', 'username')
        return self.readonly_fields

    def save_model(self, request, obj, form, change):
        if not change:  # New user
            obj.set_password(form.cleaned_data['password1'])
        super().save_model(request, obj, form, change)

admin.site.register(User, UserAdmin)
