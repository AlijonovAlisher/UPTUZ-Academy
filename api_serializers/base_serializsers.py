from rest_framework import serializers
from django.contrib.auth import get_user_model
from base.models import Teacher, Pupil, Parent, Administrator
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
User = get_user_model()
CustomUser: object = get_user_model()
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError



User = get_user_model()

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'user_type', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            user_type=validated_data['user_type']
        )
        return user

class PupilSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer()

    class Meta:
        model = Pupil
        fields = [
            'id', 'user', 'first_name', 'last_name',
            'address', 'phone_number', 'age', 'status', 'gmail',
            'image', 'created_on', 'updated_on'
        ]

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        user = CustomUserSerializer().create(user_data)
        pupil = Pupil.objects.create(user=user, **validated_data)
        return pupil

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user')
        user = instance.user

        # Update CustomUser fields
        user.username = user_data.get('username', user.username)
        user.email = user_data.get('email', user.email)
        user.user_type = user_data.get('user_type', user.user_type)
        password = user_data.get('password', None)
        if password:
            user.set_password(password)
        user.save()


        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.address = validated_data.get('address', instance.address)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.age = validated_data.get('age', instance.age)
        instance.status = validated_data.get('status', instance.status)
        instance.gmail = validated_data.get('gmail', instance.gmail)
        instance.image = validated_data.get('image', instance.image)
        instance.save()

        return instance





class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(required=True, allow_blank=False)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        username_or_email = attrs.get('username_or_email')
        password = attrs.get('password')

        # Email yoki username asosida foydalanuvchini autentifikatsiya qilish
        user = None
        if '@' in username_or_email:
            user = authenticate(email=username_or_email, password=password)
        else:
            user = authenticate(username=username_or_email, password=password)

        if user is None:
            raise serializers.ValidationError(_('Invalid login credentials.'))

        attrs['user'] = user
        return attrs
    
    
    
    
    




User = get_user_model()


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(max_length=255, min_length=2)
    password = serializers.CharField(write_only=True, min_length=6)
    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['username_or_email', 'password', 'redirect_url']



class ChangeEmailSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True, write_only=True)
    new_email = serializers.EmailField(required=True)

    def validate(self, attrs):
        current_password = attrs.get('current_password')
        new_email = attrs.get('new_email')
        user = self.context['request'].user

        if not user.check_password(current_password):
            raise serializers.ValidationError({'current_password': 'Current password is incorrect.'})

        if User.objects.filter(email=new_email).exists():
            raise serializers.ValidationError({'new_email': 'This email is already in use.'})

        return attrs

    def save(self):
        user = self.context['request'].user
        new_email = self.validated_data['new_email']
        user.email = new_email
        user.save()

    


class ChangeUsernameSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True, write_only=True)
    new_username = serializers.CharField(required=True)

    def validate(self, attrs):
        current_password = attrs.get('current_password')
        new_username = attrs.get('new_username')
        user = self.context['request'].user

        if not user.check_password(current_password):
            raise serializers.ValidationError({'current_password': 'Current password is incorrect.'})

        if User.objects.filter(username=new_username).exists():
            raise serializers.ValidationError({'new_username': 'This username is already in use.'})

        return attrs

    def save(self):
        user = self.context['request'].user
        new_username = self.validated_data['new_username']
        user.username = new_username
        user.save()



class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return user
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)