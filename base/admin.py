from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Teacher_image, Direction, Teacher, Course, Check_Pupil, CustomUser, Pupil_cource, Pupil_image, Pupil



@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'user_type', 'is_active', 'is_staff', 'is_superuser')
    list_filter = ('user_type', 'is_active', 'is_staff', 'is_superuser', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'user_type')
    ordering = ('username',)
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('User Type', {'fields': ('user_type',)}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'first_name', 'last_name', 'user_type', 'password1', 'password2'),
        }),
    )

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        queryset = queryset.prefetch_related('groups', 'user_permissions')
        return queryset




@admin.register(Teacher_image)
class TeacherImageAdmin(admin.ModelAdmin):
    list_display = ('teacher', 'image')
    list_filter = ('teacher', 'image')
    search_fields = ('teacher__username', 'image')
    list_per_page = 10  # Pagination: Show 10 records per page

class ProductImageInline(admin.TabularInline):
    model = Teacher_image
    extra = 0
    fields = ['image']
    readonly_fields = ['image']
    can_delete = True
    verbose_name = "Teacher Image"
    verbose_name_plural = "Teacher Images"
    show_change_link = True  # Adds a link to the inline model

@admin.register(Direction)
class DirectionAdmin(admin.ModelAdmin):
    list_display = ('teacher', 'direction', 'created_on')
    list_filter = ('teacher', 'created_on')
    search_fields = ('teacher__username', 'direction')
    date_hierarchy = 'created_on'  # Adds a date-based drilldown navigation by created_on

class DirectionInlineAdmin(admin.TabularInline):
    model = Direction
    extra = 0
    fields = ['direction', 'created_on']
    readonly_fields = ['created_on']
    can_delete = True
    verbose_name = "Direction"
    verbose_name_plural = "Directions"
    show_change_link = True


@admin.register(Teacher)
class TeacherAdmin(admin.ModelAdmin):
    inlines = [ProductImageInline, DirectionInlineAdmin]
    list_display = ('username', 'first_name', 'last_name', 'phone_number', 'created_on')
    list_filter = ('username', 'created_on')
    search_fields = ('username', 'phone_number', 'first_name', 'last_name')
    ordering = ['-created_on']
    actions = ['make_active', 'make_inactive']

    def make_active(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, "Selected teachers are now active.")

    def make_inactive(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, "Selected teachers are now inactive.")

    make_active.short_description = "Mark selected teachers as active"
    make_inactive.short_description = "Mark selected teachers as inactive"

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        queryset = queryset.prefetch_related('teacher_image_set', 'direction_set')
        return queryset

    def directions_count(self, obj):
        return obj.direction_set.count()
    directions_count.short_description = "Number of Directions"




@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = ('title', 'teacher', 'status', 'pupil_number', 'price', 'total_money', 'start_cource', 'end_cource', 'created_on', 'updated_on')

    list_filter = ('status', 'teacher', 'start_cource', 'end_cource', 'created_on')
    search_fields = ('title', 'teacher__username')
    date_hierarchy = 'start_cource'  # Allows filtering by start date
    ordering = ['-created_on']
    readonly_fields = ['total_money', 'created_on', 'updated_on']  # These fields will be read-only in the admin form
    fieldsets = (
        (None, {
            'fields': ('title', 'description', 'status', 'pupil_number', 'teacher')
        }),
        ('Financial Info', {
            'fields': ('price', 'total_money')
        }),
        ('Dates', {
            'fields': ('start_cource', 'end_cource', 'created_on', 'updated_on')
        }),
    )


class Pupil_cource_inline(admin.TabularInline):
    model = Pupil_cource
    extra = 0


class Pupil_image_inline(admin.TabularInline):
    model = Pupil_image
    extra = 0


@admin.register(Pupil_image)
class Pupil_imageAdmin(admin.ModelAdmin):
    list_display = ('pupil', 'image')
    list_filter = ('pupil', 'image')
    search_fields = ('pupil',)

    ordering = ['-created_on']
    readonly_fields = ['created_on', 'updated_on']


from django.contrib import admin
from .models import Pupil_cource


@admin.register(Pupil_cource)
class Pupil_courceAdmin(admin.ModelAdmin):
    search_fields = ('pupil', 'course__teacher__username')
    ordering = ['-created_on']
    list_display = ('pupil', 'course',)


@admin.register(Pupil)
class PupilAdmin(admin.ModelAdmin):
    inlines = [Pupil_cource_inline, Pupil_image_inline]
    list_display = ('username', "first_name", 'last_name', 'phone_number')
    list_filter = ('username', "first_name", 'phone_number')
    search_fields = ('title',)
    ordering = ['-created_on']
    readonly_fields = ['created_on', 'updated_on']
