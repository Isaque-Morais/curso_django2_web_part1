from gc import get_objects
from django.shortcuts import get_object_or_404, render, get_list_or_404
from .models import Receita

def index(request):
    receitas = Receita.objects.all()
    
    dados = {
        'receitas': receitas
    }
    
    return render(request, 'index.html', dados)


def receitas (request, receita_id):
    receita = get_object_or_404(Receita, pk=receita_id)
    
    receita_a_exibir = {
        'receita' : receita
    }
    
    return render(request, 'receita.html', receita_a_exibir )
