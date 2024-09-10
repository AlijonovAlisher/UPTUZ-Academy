from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from acount.models import User
from django.contrib import auth



class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True
    )
    password2 = serializers.CharField(
        max_length=68, min_length=6, write_only=True
    )

    default_error_messages = {
        'username': 'The username should only contain alphanumeric characters'
    }

    class Meta:
        model = User
        fields = ['email', 'username', 'first_name', 'last_name', 'phone_number', 'password', 'password2']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        password2 = attrs.get('password2', '')

        if not username.isalnum():
            raise serializers.ValidationError(self.default_error_messages)

        if password != password2:
            raise serializers.ValidationError({"password": "Passwords must match."})

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "Email already in use."})
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError({"username": "Username already in use."})

        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_number=validated_data['phone_number'],
            password=password
        )
        return user




class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])
        return user.tokens()

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': self.get_tokens({'email': email})
        }




class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(max_length=255, min_length=2)
    password = serializers.CharField(write_only=True, min_length=6)
    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['username_or_email', 'password', 'redirect_url']
        


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



class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': 'Token is expired or invalid'
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')
