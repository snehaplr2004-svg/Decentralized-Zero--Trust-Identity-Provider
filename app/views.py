from django.shortcuts import render
from django.http import HttpResponse
from django.views import View

# Create your views here.
# def Home(request):
#     if(request.method =='GET'):
#         return HttpResponse("Welcome to Django")
class Home(View):
    def get(self, request):
        return HttpResponse('Welcome')
    # defineindex view return index page
# def Index(request):
#     if(request.method =='GET'):
#         return HttpResponse("Index page")
class Index(View):
    def get(self, request):
        return HttpResponse('Welcome to index page')