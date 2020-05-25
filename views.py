import re

from django.contrib import messages
from django.contrib.auth import authenticate
from django.db.models import Q, Count
from django.shortcuts import render, redirect

# Create your views here.
from Cyber_Users.forms import UserRegister_Form
from Cyber_Users.models import UserRegister_Model, UserAdd_Model
#########################

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
import itertools
from sklearn.naive_bayes import MultinomialNB
from sklearn import metrics
from sklearn.linear_model import PassiveAggressiveClassifier
import os

def user_login(request):
	if request.method == "POST":
		name = request.POST.get('name')
		password = request.POST.get('password')
		try:

			check = UserRegister_Model.objects.get(name=name,password=password)
			request.session['userid'] = check.id
			return redirect('user_adddata')
		except:
			pass
		user = authenticate(name=name,password=password)
		if user is not None:
			if user.is_active:


				return redirect('user_adddata')
		else:
			messages.error(request, 'username or password are not match')

			return redirect('user_login')
	return render(request, 'users/user_login.html')


def user_register(request):
	if request.method == "POST":
		forms = UserRegister_Form(request.POST)
		if forms.is_valid():
			forms.save()
			messages.success(request, 'You have been successfully registered')
			return redirect('user_login')
	else:
		forms = UserRegister_Form()

	return render(request,'users/user_register.html',{'form':forms})


def user_adddata(request):
	userid = request.session["userid"]
	obj = UserRegister_Model.objects.get(id=userid)
	attack1 = []
	attack2, attack3, attack4, attack5, attack6, attack7, attack8, attack9 = [], [], [], [], [], [], [], []

	splt = ''
	Entity = ''
	Year = 0
	Records = ''
	Organizationtype = ''
	Method = ''
	txt =''
	Adddata = ''
	ans = ''
	Time = ''
	if request.method == "POST":
		Entity = request.POST.get("entity")
		Year = request.POST.get("year")
		Records = request.POST.get("records")
		Organizationtype = request.POST.get("organizationtype")
		Method = request.POST.get("method")
		txt = request.POST.get("name")
		Time = request.POST.get("time")




		splt = (re.findall(r"[\w']+", str(txt)))

	for f in splt:
		if f in ('IPid', 'FDDI', 'x25', 'rangingdistance'):
			attack1.append(f)
		elif f in ('tcpchecksum', 'mtcp', 'controlflags', 'tcpoffset', 'tcpport'):
			attack2.append(f)
		elif f in ('ICMPID', 'udptraffic', 'udpunicorn', 'datagramid', 'NTP', 'RIP', 'TFTP'):
			attack3.append(f)
		elif f in ('GETID', 'POSTID', 'openBSD', 'appid', 'sessionid', 'transid', 'physicalid'):
			attack4.append(f)
		elif f in ('SYN', 'ACK', 'synpacket', 'sycookies'):
			attack5.append(f)
		elif f in ('serverattack', 'serverid', 'blockbankwidth'):
			attack6.append(f)
		elif f in ('monlist', 'getmonlist', 'NTPserver'):
			attack7.append(f)
		elif f in ('portid', 'FTPID', 'tryion', 'fragflag'):
			attack8.append(f)
		elif f in ('malwareid', 'gethttpid', 'httpid'):
			attack9.append(f)

	if len(attack1) > len(attack2) and len(attack1) > len(attack3) and len(attack1) > len(attack4) and len(
			attack1) > len(attack5) and len(attack1) > len(attack6) and len(attack1) > len(attack7) and len(
		attack1) > len(attack8) and len(attack1) > len(attack9):
		ans = "Man-in-the-middle Attack"
	elif len(attack2) > len(attack1) and len(attack2) > len(attack3) and len(attack2) > len(attack4) and len(
			attack2) > len(attack5) and len(attack2) > len(attack6) and len(attack2) > len(attack7) and len(
		attack2) > len(attack8) and len(attack2) > len(attack9):
		ans = "Phishing and spear phishing attacks"
	elif len(attack3) > len(attack2) and len(attack3) > len(attack1) and len(attack3) > len(attack4) and len(
			attack1) > len(attack5) and len(attack1) > len(attack6) and len(attack1) > len(attack7) and len(
		attack1) > len(attack8) and len(attack1) > len(attack9):
		ans = "Drive-by attack"
	elif len(attack4) > len(attack2) and len(attack4) > len(attack3) and len(attack4) > len(attack1) and len(
			attack4) > len(attack5) and len(attack4) > len(attack6) and len(attack4) > len(attack7) and len(
		attack4) > len(attack8) and len(attack4) > len(attack9):
		ans = "Password attack"
	elif len(attack5) > len(attack2) and len(attack5) > len(attack3) and len(attack5) > len(attack4) and len(
			attack5) > len(attack1) and len(attack5) > len(attack6) and len(attack5) > len(attack7) and len(
		attack5) > len(attack8) and len(attack5) > len(attack9):
		ans = "SQL injection attack"
	elif len(attack6) > len(attack2) and len(attack6) > len(attack3) and len(attack6) > len(attack4) and len(
			attack6) > len(attack5) and len(attack6) > len(attack1) and len(attack6) > len(attack7) and len(
		attack6) > len(attack8) and len(attack6) > len(attack9):
		ans = "Cross-site scripting (XSS) attack"
	elif len(attack7) > len(attack2) and len(attack7) > len(attack3) and len(attack7) > len(attack4) and len(
			attack7) > len(attack5) and len(attack7) > len(attack6) and len(attack7) > len(attack1) and len(
		attack7) > len(attack8) and len(attack7) > len(attack9):
		ans = "Eavesdropping attack"
	elif len(attack8) > len(attack2) and len(attack8) > len(attack3) and len(attack8) > len(attack4) and len(
			attack8) > len(attack5) and len(attack8) > len(attack6) and len(attack8) > len(attack7) and len(
		attack8) > len(attack1) and len(attack8) > len(attack9):
		ans = "Birthday attack"
	elif len(attack9) > len(attack2) and len(attack9) > len(attack3) and len(attack9) > len(attack4) and len(
			attack9) > len(attack5) and len(attack9) > len(attack6) and len(attack9) > len(attack7) and len(
		attack9) > len(attack8) and len(attack9) > len(attack1):
		ans = "Teardrop attack"

	else:
		ans = "Unmalware"
	UserAdd_Model.objects.create(uregid=obj,entity=Entity,year=Year,records=Records,organizationtype=Organizationtype,method=Method,adddata=txt,attackresult=ans,time=Time)


	return render(request,'users/user_adddata.html')

def user_page(request):
	obj = UserAdd_Model.objects.all()
	return render(request,'users/user_page.html',{'object':obj})


def malware(request):
	obj = UserAdd_Model.objects.filter(Q(attackresult='Man-in-the-middle (MitM) attack') | Q(attackresult='Phishing and spear phishing attacks') | Q(
		attackresult='Drive-by attack') | Q(attackresult='Password attack') | Q(
		attackresult='SQL injection attack') | Q(attackresult='Cross-site scripting (XSS) attack') | Q(attackresult='Eavesdropping attack') | Q(
		attackresult='Birthday attack') | Q(attackresult='Teardrop attack'))
	return render(request,'users/malware.html',{'object':obj})

def unmalware(request):
	obj = UserAdd_Model.objects.filter(attackresult='Unmalware')
	return render(request,'users/unmalware.html',{'object':obj})

def breaches_analysis(request):
	chart = UserAdd_Model.objects.values('attackresult','method').annotate(dcount=Count('attackresult'))
	return render(request,'users/breaches_analysis.html',{'objects':chart})

def chart_page(request,chart_type):
	chart = UserAdd_Model.objects.values('year').annotate(dcount=Count('organizationtype'))
	return render(request,'users/chart_page.html',{'chart_type':chart_type,'objects':chart})
def checkdata(request):
   return render(request,'users/check_data.html')
def accuracy(request):
	if request.method == "POST":
		entity = request.POST.get("entity")
		print(entity)
		input=[entity]
		#headline1= request.POST.get('headline1')
		#replacing Body nan with Headline
		#print(os.listdir("../input"))
	df = pd.read_csv('F:/Cyber_Hacking_Breachess/Cyber_Hacking_Breachess/Coding/Cyber_Hacking_Breaches/Cyber_Users/breaches.csv',encoding="ISO-8859-1")
	#replacing Body nan with Headline
	for i in range(0,df.shape[0]-1):
		if(df.F.isnull()[i]):
			df.F[i] = df.A[i]
		
	y = df.E=df.E.astype(str)
	X = df.F=df.F.astype(str)

	#train_test separation
	X_train,X_test,y_train,y_test = train_test_split(X,y,test_size = 0.2)
	#Ans_test=['Kenya parliament passes controversial election law amendment']
	Ans_test=['35 False Matches and 1 Erroneous Arrest As Police Secretly Test Facial Recognition Technology']
	#0

	#Applying tfidf to the data set
	tfidf_vect = TfidfVectorizer(stop_words = 'english')
	tfidf_train = tfidf_vect.fit_transform(X_train)
	tfidf_test = tfidf_vect.transform(X_test)
	tfidf_test1= tfidf_vect.transform(input)
	tfidf_df = pd.DataFrame(tfidf_train.A, columns=tfidf_vect.get_feature_names())

	#Applying Naive Bayes
	clf = MultinomialNB() 
	clf.fit(tfidf_train, y_train)						# Fit Naive Bayes classifier according to X, y
	pred = clf.predict(tfidf_test)					   # Perform classification on an array of test vectors X.
	pred1 = clf.predict(tfidf_test1)					 # Perform classification on an array of test vectors X.
	print('predicted value print')
	print(pred1)
	score = metrics.accuracy_score(y_test, pred)
	print("accuracy:   %0.3f" % score)
	cm = metrics.confusion_matrix(y_test, pred)
	print(cm)

	#Applying Passive Aggressive classifier
	linear_clf = PassiveAggressiveClassifier()
	linear_clf.fit(tfidf_train, y_train)
	pred2 = linear_clf.predict(tfidf_test)
	pred3 = linear_clf.predict(tfidf_test1)
	print(pred2)
	print(pred3)
	score = metrics.accuracy_score(y_test, pred2)
	print("accuracy:   %0.3f" % score)
	cm1 = metrics.confusion_matrix(y_test, pred2)
	print(cm1)
	breach=''
	if pred3=='1':
		print(pred1)
		print('hello')
		breach='Man-in-the-middle (MitM) attac'	
	elif pred3=='2':
		print(pred1)
		print('hello')
		breach='Phishing and spear phishing attacks'
	elif pred3=='3':
		print(pred1)
		print('hello')
		breach='Drive-by attack'
	elif pred3=='4':
		print(pred1)
		print('hello')
		breach='Password attack'
	elif pred3=='5':
		print(pred1)
		print('hello')
		breach='SQL injection attack'
	elif pred3=='6':
		print(pred1)
		print('hello')
		breach='Cross-site scripting (XSS) attack'
	elif pred3=='7':
		print(pred1)
		print('hello')
		breach='Eavesdropping attack'
	elif pred3=='8':
		print(pred1)
		print('hello')
		breach='Birthday attack'
	elif pred3=='9':
		print(pred1)
		print('hello')
		breach='Teardrop attack'	
	else:
		breach='not a fake news'
	d = {'e':breach}	
	return render(request,'users/show.html',d)
