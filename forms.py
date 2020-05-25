from django import forms
from Cyber_Users.models import UserRegister_Model


class UserRegister_Form(forms.ModelForm):
    class Meta:
        model = UserRegister_Model
        fields = ('name','email','password', 'phoneno', 'address')


