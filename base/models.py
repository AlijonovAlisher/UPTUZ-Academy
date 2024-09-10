from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.core.exceptions import ValidationError
from django.db.models import PositiveBigIntegerField
from django.utils.safestring import mark_safe
from phonenumber_field.modelfields import PhoneNumberField
import re
import uuid
import os
    
class CustomUser(AbstractUser):
    user_type_choices = (
            ('teacher', _('Teacher')),
            ('parent', _('Parent')),
            ('pupil', _('Pupil')),
            ('admin', _('Administrator')),
        )
    user_type = models.CharField(max_length=10,choices=user_type_choices,default='pupil',verbose_name=_("User Type"))


    class Meta:
        verbose_name = _("Custom User")
        verbose_name_plural = _("Custom Users")

    def __str__(self):
        return self.username


def validate_url(value):
    regex = re.compile(
        r'^(http|https)://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if not regex.match(value):
        raise ValidationError('Noto‘g‘ri URL formati')


class Teacher(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False,verbose_name=_("ID"))
    user = models.OneToOneField(CustomUser,on_delete=models.CASCADE,verbose_name=_("User"))
    username = models.CharField(max_length=30,unique=True,verbose_name=_("Username"))
    description = models.TextField(null=True,blank=True,verbose_name=_("Description"))
    first_name = models.CharField(max_length=120,verbose_name=_("First Name"))
    last_name = models.CharField(max_length=120,verbose_name=_("Last Name"))
    maosh = models.BigIntegerField(default=0,verbose_name=_("Salary"))
    status = models.CharField(max_length=10,
        choices=[
            ('active', _('Active')),
            ('completed', _('Completed')),
            ('cancelled', _('Cancelled')),
        ],default='active',verbose_name=_("Status")
    )
    age = models.PositiveSmallIntegerField(validators=[MinValueValidator(16)],verbose_name=_("Age"), null=True, blank=True)
    phone_number = PhoneNumberField(null=False,blank=False,unique=True,verbose_name=_("Phone Number"))
    email = models.EmailField(unique=True,blank=True,null=True,verbose_name=_("Email"))
    image = models.ImageField(upload_to='teachers/',blank=True,verbose_name=_("Image"))
    instagram = models.CharField(max_length=100,blank=True,verbose_name=_("Instagram URL"))
    telegram = models.CharField(max_length=100,blank=True,verbose_name=_("Telegram URL"))
    facebook = models.CharField(max_length=100,blank=True,verbose_name=_("Facebook URL"))
    is_active = models.BooleanField(default=True,verbose_name=_("Is Active"))
    created_on = models.DateTimeField(auto_now_add=True,verbose_name=_("Created On"))
    updated_on = models.DateTimeField(auto_now=True,verbose_name=_("Updated On"))

    def image_tag(self):
        if self.image:
            return mark_safe('<img src="{}" height="50"/>'.format(self.image.url))
        return ""

    def save(self, *args, **kwargs):
        if self.telegram:
            self.telegram = f"https://www.telegram.com/{self.telegram}"
        if self.instagram:
            self.instagram = f"https://www.instagram.com/{self.instagram}"
        if self.facebook:
            self.facebook = f"https://www.facebook.com/{self.facebook}"

        super().save(*args, **kwargs)

    class Meta:
        verbose_name = _("Teacher")
        verbose_name_plural = _("Teachers")

    def __str__(self):
        return f"{self.username}"



class Direction(models.Model):
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE, verbose_name=_("Teacher"))
    direction = models.CharField(max_length=100, verbose_name=_("Direction"))
    description = models.TextField(blank=True, null=True, verbose_name=_("Description"))
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=_("Created On"))
    updated_on = models.DateTimeField(auto_now=True, verbose_name=_("Updated On"))

    class Meta:
        verbose_name = _("Direction")
        verbose_name_plural = _("Directions")

    def __str__(self):
        return self.direction

def upload_to_teacher(instance, filename):
    username = instance.pupil.username
    return f'pupil_images/{username}/{filename}'

class Teacher_image(models.Model):
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE, verbose_name=_("Teacher"))
    image = models.ImageField(upload_to=upload_to_teacher, blank=True, verbose_name=_("Image"))
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=_("Created On"))
    updated_on = models.DateTimeField(auto_now=True, verbose_name=_("Updated On"))

    def __str__(self):
        return f"{self.teacher}'s Image"

    class Meta:
        verbose_name = _("Teacher Image")
        verbose_name_plural = _("Teacher Images")
        ordering = ['-created_on']





class Course(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=100, verbose_name=_("Title"))
    description = models.TextField(verbose_name=_("Description"))
    status = models.CharField(max_length=10, choices=[('active', _('Active')), ('completed', _('Completed')),
                                                      ('cancelled', _('Cancelled'))], default='active',
                               verbose_name=_("Status"))
    pupil_number = models.PositiveSmallIntegerField(validators=[MinValueValidator(2)],
                                                    verbose_name=_("Number of Pupils"))
    teacher = models.ForeignKey(Teacher, on_delete=models.SET_NULL, null=True, blank=True, verbose_name=_("Teacher"))
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name=_("Price"))
    total_money = models.DecimalField(max_digits=10, decimal_places=2, verbose_name=_("Total Money"))
    start_cource = models.DateField(verbose_name=_("Start Date"))
    end_cource = models.DateField(verbose_name=_("End Date"))
    updated_on = models.DateTimeField(auto_now=True, verbose_name=_("Updated On"))
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=_("Created On"))

    # def save(self, *args, **kwargs):
    #     if self.pk is not None:
    #         original = Course.objects.get(pk=self.pk)
    #     if original.total_money != self.total_money:
    #         self.teacher.maosh += (self.total_money - original.total_money) * 0.5
    #     else:  # Creating a new course
    #         self.teacher.maosh += self.total_money * 0.5
    #
    #     self.teacher.save()
    #     super().save(*args, **kwargs)

    class Meta:
        verbose_name = _("Course")
        verbose_name_plural = _("Courses")
        ordering = ['-created_on']

    def __str__(self):
        return self.title


class Pupil(models.Model):
    STATUS_ACTIVE = 'active'
    STATUS_COMPLETED = 'completed'
    STATUS_CANCELLED = 'cancelled'

    STATUS_CHOICES = [
        (STATUS_ACTIVE, _('Active')),
        (STATUS_COMPLETED, _('Completed')),
        (STATUS_CANCELLED, _('Cancelled')),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, verbose_name=_("User"))
    username = models.CharField(max_length=10, unique=True, verbose_name=_("Username"), null=True, blank=True)
    first_name = models.CharField(max_length=100, verbose_name=_("First Name"))
    last_name = models.CharField(max_length=100, verbose_name=_("Last Name"))
    address = models.CharField(max_length=255, blank=True, null=True, verbose_name=_("Address"))
    phone_number = models.CharField(max_length=255, blank=True, null=True, verbose_name=_("Phone number"))
    age = models.PositiveSmallIntegerField(verbose_name=_("Age"))
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_ACTIVE, verbose_name=_("Status"))
    gmail = models.EmailField(null=True, blank=True, verbose_name=_("Gmail"))
    image = models.ImageField(upload_to='pupil', blank=True, null=True, verbose_name=_("Image"))
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=_("Created On"))
    updated_on = models.DateTimeField(auto_now=True, verbose_name=_("Updated On"))

    def image_tag(self):
        if self.image:
            return mark_safe('<img src="{}" height="50"/>'.format(self.image.url))
        return ""

    class Meta:
        verbose_name = _("Pupil")
        verbose_name_plural = _("Pupils")

    def __str__(self):
        return self.username


class Pupil_cource(models.Model):
    pupil = models.OneToOneField(Pupil, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=("Yaratilgan sana"))
    updated_on = models.DateTimeField(auto_now=True, verbose_name=("Yangilangan sana"))

    class Meta:
        verbose_name = "Pupil course"
        verbose_name_plural = "Pupil courses"
        ordering = ['-created_on']

    def __str__(self):
        return f"{self.course}'s Image"

def upload_to_pupil(instance, filename):
    username = instance.pupil.username
    return f'pupil_images/{username}/{filename}'


class Pupil_image(models.Model):
    pupil = models.ForeignKey(Pupil, on_delete=models.CASCADE)
    image = models.ImageField(upload_to=upload_to_pupil, blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=("Yaratilgan sana"))
    updated_on = models.DateTimeField(auto_now=True, verbose_name=("Yangilangan sana"))

    def __str__(self):
        return f"{self.pupil}'s Image"

    class Meta:
        verbose_name = "Pupil image"
        verbose_name_plural = "Pupil images"
        ordering = ['-created_on']

class Parent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    username = models.CharField(max_length=10, unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone_number = PhoneNumberField(null=False, blank=False, unique=True)
    child = models.ForeignKey('Pupil', on_delete=models.SET_NULL, null=True)
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=("Yaratilgan sana"))
    updated_on = models.DateTimeField(auto_now=True, verbose_name=("Yangilangan sana"))

    class Meta:
        verbose_name = _("Parent")
        verbose_name_plural = _("Parents")
        ordering = ['-created_on']

    def __str__(self):
        return self.username

class Check_Pupil(models.Model):
    parent = models.OneToOneField(Pupil, on_delete=models.CASCADE, related_name="parrent_check")
    pupil = models.ForeignKey(Pupil, on_delete=models.CASCADE, related_name='check_pupil')
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=("Yaratilgan sana"))
    updated_on = models.DateTimeField(auto_now=True, verbose_name=("Yangilangan sana"))

    def __str__(self):
        return f"{self.course}'s Image"





class Administrator(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    username = models.CharField(max_length=10, unique=True)
    updated_on = models.DateTimeField(auto_now=True, verbose_name=("Yangilangan sana"))
    created_on = models.DateTimeField(auto_now_add=True, verbose_name=("Yaratilgan sana"))
    class Meta:
        verbose_name = _("Administrator")
        verbose_name_plural = _("Administrators")
        ordering = ['-created_on']

    def __str__(self):
        return self.username

