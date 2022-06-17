from unicodedata import name
from django.shortcuts import redirect, render, get_object_or_404
from django.contrib.auth.models import User
from django.contrib import auth, messages
from receitas.models import Receita


def cadastro(request):
    if request.method == 'POST':
        nome = request.POST['nome']
        email = request.POST['email']
        senha1 = request.POST['password1']
        senha2 = request.POST['password2']
    
        #Verificação do campo "Nome" para que não contenha espaços em brancos 
        if campo_vazio(nome):
            messages.error(request, 'O campo Nome não pode ficar com espaços em brancos!')
            return redirect('cadastro')
        
        #Verificação do campo "Email" para que não contenha espaços em brancos 
        if campo_vazio(email):
            messages.error(request, 'O campo Email não pode ficar com espaços em brancos!')
            return redirect('cadastro')
        
        #Verificação se a senha do campo "1" confere com a senha do campo "2"
        if senhas_nao_sao_iguais(senha1, senha2):
            messages.error(request, 'As senhas não são iguais!')
            return redirect('cadastro')
        
        #Função que verifica se o usuário já consta na base de dados como já cadastrado
        if User.objects.filter(username=nome).exists():
            messages.error(request, 'Usuário já cadastrado!')
            return redirect('cadastro')
        
        #Criando um objeto para caso o usuário não esteja cadastrado na base de dados
        user = User.objects.create_user(username=nome, email=email, password=senha1)
        user.save()
        messages.success(request, 'Cadastro realizado com sucesso!')
        return redirect('login')
    
    else:
        return render(request, 'usuarios/cadastro.html')
    
def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        senha = request.POST['senha']
        #Verificação para os campos "email" e "senha" não fiquem em brancos 
        if campo_vazio(email)  or campo_vazio(senha):
            messages.error(request, 'Os campos email e senha não podem ficarem em brancos!')
            return redirect('login')
        print(email, senha)
        #Verifica se o email e o username para prosseguir com login
        if User.objects.filter(email=email).exists():
            nome = User.objects.filter(email=email).values_list('username', flat=True).get()
            user = auth.authenticate(request, username=nome, password=senha)
            if user is not None:
                auth.login(request, user)
                print('Login realizado com sucesso!')
                return redirect('dashboard')
    return render(request, 'usuarios/login.html')

def logout(request):
    auth.logout(request)
    return redirect('index')

def dashboard(request):
    if request.user.is_authenticated:
        id = request.user.id
        receitas = Receita.objects.order_by('-data_receita').filter(pessoa=id)

        dados = { 
            'receitas' : receitas
        }
        return render(request, 'usuarios/dashboard.html', dados)
    else:
        return redirect('index')
           
def cria_receita(request):
    if request.method == 'POST':
        nome_receita = request.POST['nome_receita']
        ingredientes = request.POST['ingredientes']
        modo_preparo = request.POST['modo_preparo']
        tempo_preparo = request.POST['tempo_preparo']
        rendimento = request.POST['rendimento']
        categoria = request.POST['categoria']
        foto_receita = request.FILES['foto_receita']
        user = get_object_or_404(User, pk=request.user.id)
        receita = Receita.objects.create(pessoa=user,nome_receita=nome_receita, ingredientes=ingredientes, modo_preparo=modo_preparo,tempo_preparo=tempo_preparo, rendimento=rendimento,categoria=categoria,  foto_receita=foto_receita)
        receita.save()
        return redirect('dashboard')
    else:
        return render(request, 'usuarios/cria_receita.html')
    
def campo_vazio(campo):
    return not campo.strip()

def senhas_nao_sao_iguais(senha1, senha2):
    return senha1 != senha2