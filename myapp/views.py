from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
import re
#
# username: sangeeta
# admin password: pisb@123


def home(request):
    if request.method == "POST":
        text = request.POST.get('text1')
        choose = request.POST.get('choose')
        context = {}

        if choose == "choose1":
            # Extract numbers from a string greater than 100
            pattern = re.compile(r'\d{3,}')
            matches = pattern.finditer(text)
            ans = list(map(int, [match.group(0) for match in matches]))
            # print(ans)
            context['ans'] = ans

        elif choose == "choose2":
            # Extract date from a url string (yyyy-mm-dd)
            pattern = re.compile(r'\d\d\d\d-\d\d-\d\d')
            matches = pattern.finditer(text)
            ans = [match.group(0) for match in matches]
            context['ans'] = ans

        elif choose == "choose3":
            # Extract strings within single quotes in a string
            pattern = re.compile(r"['][a-zA-Z0-9!@#$%^&*()-_+=]+[']")
            matches = pattern.finditer(text)
            ans = [match.group(0) for match in matches]
            # print(ans)
            context['ans'] = ans

        elif choose == "choose4":
            # Email Validator
            regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            pattern = re.compile(
                r'\b[a-zA-Z0-9.-]*@*[a-zA-Z0-9-]*\.[a-zA-Z0-9]*\b')
            matches = pattern.finditer(text)
            ans = []
            for match in matches:
                if(re.fullmatch(regex, match.group(0))):
                    ans.append("Valid Email")
                else:
                    ans.append("Invalid Email")
            context['ans'] = ans

        elif choose == "choose5":
            # Validate IP addresses and determine class
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
            if re.search(regex, text):
                pattern = re.compile(
                    r'\b25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]\.')
                matches = pattern.finditer(text)
                num = int([match.group(0) for match in matches][0])
                # print(num)
                if 0 <= num <= 127:
                    cl = "Class : A"
                elif 128 <= num <= 191:
                    cl = "Class : B"
                elif 192 <= num <= 223:
                    cl = "Class : C"
                ans = ["Valid Ip address", cl]
            else:
                ans = ["Invalid Ip address"]
            context['ans'] = ans

        elif choose == "choose6":
            # Validate MAC address
            regex = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$"
            pattern = re.compile(regex)
            if re.search(pattern, text):
                ans = ["Valid MAC Address"]
            else:
                ans = ["Invalid MAC Address"]
            context['ans'] = ans

        else:
            # Convert CamelCase to snake_case
            pattern = re.compile(r'([A-Z][a-z]+){2,}')
            matches = pattern.finditer(text)
            ans = []
            for match in matches:
                print(match.group(0))
                s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', match.group(0))
                s = re.sub('__([A-Z])', r'_\1', s)
                s = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower()
                # s = re.sub('([A-Z]+)', r'_\1', match.group(0)).lower()
                ans.append(s)
            context['ans'] = ans

        return render(request, 'myapp/home.html', context)
    else:
        context = {}
        return render(request, 'myapp/home.html', context)


def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        # pnum = request.POST['number']
        # gender = request.POST['gender']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        if pass1 == pass2:
            if User.objects.filter(username=username).exists():
                messages.info(request, "username taken")
                return redirect('signup')
            elif User.objects.filter(email=email).exists():
                messages.info(request, "username taken")
                return redirect('signup')
            else:
                myUser = User.objects.create_user(
                    username=username, email=email, first_name=fname, last_name=lname, password=pass1)
                myUser.save()
                return redirect('login')
                # return render(request, "myappp/login.html")
        else:
            messages.info(request, "Password not matching")
            return redirect('signup')
    else:
        context = {}
        return render(request, 'myapp/signup.html', context)


def userLogin(request):
    if request.method == "POST":
        username = request.POST["login_username"]
        password = request.POST["login_password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Successfully Logged In")
            return redirect('home')
        else:
            return render(request, "myapp/login.html", {"message": "Invalid Credentials"})

    return render(request, "myapp/login.html")
    # return redirect('login')


def userLogout(request):
    logout(request)
    return render(request, "myapp/login.html", {"message": "Logged out."})
