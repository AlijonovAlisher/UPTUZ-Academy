from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from api_serializers.base_serializsers import *
from django.contrib.auth import authenticate
from rest_framework import generics, status, views, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes
from django.utils.http import urlsafe_base64_encode



class PupilListCreateView(generics.ListCreateAPIView):
    """
    O'quvchilar ro'yxatini ko'rish va yangi o'quvchi qo'shish uchun view.
    """
    queryset = Pupil.objects.all()
    serializer_class = PupilSerializer
    permission_classes = [permissions.AllowAny]

    def list(self, request, *args, **kwargs):
        """
        O'quvchilar ro'yxatini olish.
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """
        Yangi o'quvchi yaratish.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class PupilRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Pupil.objects.all()
    serializer_class = PupilSerializer
    permission_classes = [permissions.AllowAny]

    def retrieve(self, request, *args, **kwargs):
        """
        O'quvchini ko'rish.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        """
        O'quvchini yangilash.
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        """
        O'quvchini o'chirish.
        """
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        # Asosiy tokenni olish
        token = super().get_token(user)

        # Qo'shimcha ma'lumotlarni token ichiga kiritish
        token['username'] = user.username
        token['email'] = user.email
        token['user_type'] = user.user_type  # Foydalanuvchi turi (masalan, 'teacher', 'parent', 'pupil')

        return token







class LoginView(APIView):
    permission_classes = [permissions.AllowAny]  # Ruxsatlarni ochiq qilish

    def post(self, request, *args, **kwargs):
        username_or_email = request.data.get('username_or_email')
        password = request.data.get('password')

        if not username_or_email or not password:
            return Response({'error': 'Username/Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        user = None
        if '@' in username_or_email:
            user = authenticate(request, email=username_or_email, password=password)
        else:
            user = authenticate(request, username=username_or_email, password=password)

        if user is None:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': user.username,
            'email': user.email,
        }, status=status.HTTP_200_OK)

    def get(self, request,*args,**kwargs):
        return Response({
            'detail': 'This view is a POST method view.'
        }, status=status.HTTP_200_OK)
    






User = get_user_model()



class ChangeEmailView(generics.UpdateAPIView):
    """
    Emailni o'zgartirish uchun view.
    """
    serializer_class = ChangeEmailSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail': 'Email updated successfully.'}, status=status.HTTP_200_OK)


class ChangeUsernameView(generics.UpdateAPIView):
    """
    Username'ni o'zgartirish uchun view.
    """
    serializer_class = ChangeUsernameSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail': 'Username updated successfully.'}, status=status.HTTP_200_OK)
    

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer
    permission_classes = [permissions.AllowAny]


    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        username_or_email = serializer.validated_data.get('username_or_email')
        password = serializer.validated_data.get('password')
        redirect_url = serializer.validated_data.get('redirect_url', '')

        # Authenticate user using either email or username
        user = None
        if '@' in username_or_email:
            user = authenticate(request, email=username_or_email, password=password)
        else:
            user = authenticate(request, username=username_or_email, password=password)

        if user is None:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # If authentication is successful, generate reset token and link
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        current_site = get_current_site(request).domain
        relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
        abs_url = f'http://{current_site}{relative_link}?redirect_url={redirect_url}'

        # Generate JWT token for user (optional, if JWT is part of the flow)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Return response with the reset link and token
        return Response({
            'message': 'Password reset link generated successfully.',
            'reset_link': abs_url,
            'access_token': access_token,
            'refresh_token': str(refresh),
            'username': user.username,
            
            'email': user.email,
        }, status=status.HTTP_200_OK)
        



           
# class SetNewPasswordAPIView(generics.GenericAPIView):
#     serializer_class = SetNewPasswordSerializer
#     permission_classes = [permissions.AllowAny]

#     def patch(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
        
#         return Response({
#             'success': True, 
#             'message': 'Password reset successful'
#         }, status=status.HTTP_200_OK)
        

# from api_serializers.base_serializsers import LoginSerializer


# class LogoutAPIView(generics.GenericAPIView):
#     serializer_class = LogoutSerializer
#     permission_classes = (permissions.IsAuthenticated,)

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(status=status.HTfrom django.utils.encoding import smart_strTP_204_NO_CONTENT)

from django.utils.encoding import smart_str




class SetNewPasswordAPIView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, uidb64, token):
        try:
            # Decode the user ID from the uidb64
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            
            # Validate the token
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_401_UNAUTHORIZED)
            
            # Get the new password from the request data
            new_password = request.data.get('new_password')
            if not new_password:
                return Response({'error': 'New password is required.'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Set the new password
            user.set_password(new_password)
            user.save()
            
            return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': 'An error occurred.'}, status=status.HTTP_400_BAD_REQUEST)