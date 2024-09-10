from django.contrib import admin
from .models import CustomUser, Teacher, Direction, Course, Pupil, Pupil_cource, Pupil_image, Teacher_image, Parent, Check_Pupil, Administrator

class DirectionInline(admin.TabularInline):
    model = Direction
    extra = 1

class TeacherImageInline(admin.TabularInline):
    model = Teacher_image
    extra = 1

class PupilImageInline(admin.TabularInline):
    model = Pupil_image
    extra = 1

class PupilCourseInline(admin.TabularInline):
    model = Pupil_cource
    extra = 1

class TeacherAdmin(admin.ModelAdmin):
    inlines = [DirectionInline, TeacherImageInline]
    list_display = ('username', 'first_name', 'last_name', 'phone_number', 'is_active')
    search_fields = ('username', 'first_name', 'last_name')

class PupilAdmin(admin.ModelAdmin):
    inlines = [PupilImageInline, PupilCourseInline]
    list_display = ('username', 'first_name', 'last_name', 'phone_number', 'is_active')
    search_fields = ('username', 'first_name', 'last_name')

class ParentAdmin(admin.ModelAdmin):
    list_display = ('username', 'first_name', 'last_name', 'phone_number')
    search_fields = ('username', 'first_name', 'last_name')

class CourseAdmin(admin.ModelAdmin):
    list_display = ('title', 'teacher', 'status', 'price')
    search_fields = ('title', 'teacher__username')

class AdministratorAdmin(admin.ModelAdmin):
    list_display = ('username',)
    search_fields = ('username',)

# CustomUser uchun adminni kiritamiz
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'user_type', 'email')
    search_fields = ('username', 'email')

# Admin saytida registratsiya qilamiz
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Teacher, TeacherAdmin)
admin.site.register(Pupil, PupilAdmin)
admin.site.register(Parent, ParentAdmin)
admin.site.register(Course, CourseAdmin)
admin.site.register(Administrator, AdministratorAdmin)
