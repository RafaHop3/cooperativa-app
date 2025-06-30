// URL da API - uses environment variable if available, otherwise fallback to local development URL
const API_URL = window.API_URL || 'http://127.0.0.1:8000';

// Log API URL being used
console.log('script.js using API URL:', API_URL);

// Tabs
function showTab(tabId) {
  const tabs = document.querySelectorAll('.tab-content');
  tabs.forEach(tab => {
    tab.classList.remove('active');
  });
  const tab = document.getElementById(tabId);
  if(tab) tab.classList.add('active');
}

// Galeria dinâmica com autenticação
async function carregarGaleria() {
  const collage = document.getElementById('collage');
  if(!collage) return;
  
  collage.innerHTML = '';
  try {
    // Verificar autenticação antes de fazer a requisição
    if (!isAuthenticated()) {
      window.location.href = 'login.html';
      return;
    }
    
    const resp = await authenticatedFetch('/api/fotos');
    if (!resp || !resp.ok) {
      throw new Error(`Erro ao carregar galeria: ${resp ? resp.status : 'Sem resposta'}`);
    }
    
    const fotos = await resp.json();
    fotos.forEach((src, i) => {
      const img = document.createElement('img');
      // Ensure the URL is properly formed
      img.src = src.startsWith('http') ? src : `${API_URL}/api/fotos/${encodeURIComponent(src)}`;
      img.alt = `Foto ${i+1}`;
      img.loading = 'lazy'; // Lazy load images for better performance
      img.onerror = () => {
        img.src = 'placeholder.jpg';
        img.alt = 'Imagem não disponível';
      };
      collage.appendChild(img);
    });
  } catch (error) {
    console.error('Erro ao carregar galeria:', error);
    collage.innerHTML = '<p style="color:#fff">Não foi possível carregar a galeria.</p>';
  }
}

// Cooperativados dinâmico
async function carregarCooperativados() {
    try {
        // Verificar autenticação antes de fazer a requisição
        if (!isAuthenticated()) {
            window.location.href = 'login.html';
            return;
        }

        const response = await authenticatedFetch('/api/cooperativados');
        
        if (!response || !response.ok) {
            throw new Error(`Erro ao carregar dados: ${response ? response.status : 'Sem resposta'}`);            
        }
        
        const data = await response.json();
        const tbody = document.querySelector('#cooperativados-table tbody');
        tbody.innerHTML = '';
        
        data.forEach(cooperativado => {
            // Sanitizar todos os dados antes de inserir no DOM
            const matricula = sanitizeContent(cooperativado.matricula || '');
            const nome = sanitizeContent(cooperativado.nome || '');
            const cpf = sanitizeContent(cooperativado.cpf || '');
            const valor = cooperativado.valor ? Number(cooperativado.valor).toFixed(2) : '0.00';
            const parcelas = cooperativado.parcelas || 0;
            const titulo = sanitizeContent(cooperativado.titulo || '');
            const partido = sanitizeContent(cooperativado.partido || '');
            const foto = cooperativado.foto ? encodeURIComponent(cooperativado.foto) : '';
            
            const row = document.createElement('tr');
            
            // Construir células individualmente para evitar injeção de HTML
            const tdMatricula = document.createElement('td');
            tdMatricula.textContent = matricula;
            
            const tdNome = document.createElement('td');
            tdNome.textContent = nome;
            
            const tdCpf = document.createElement('td');
            tdCpf.textContent = cpf;
            
            const tdValor = document.createElement('td');
            tdValor.textContent = valor;
            
            const tdParcelas = document.createElement('td');
            tdParcelas.textContent = parcelas;
            
            const tdTitulo = document.createElement('td');
            tdTitulo.textContent = titulo;
            
            const tdPartido = document.createElement('td');
            tdPartido.textContent = partido;
            
            // Criar célula de foto com link seguro
            const tdFoto = document.createElement('td');
            const linkFoto = document.createElement('a');
            linkFoto.href = '#';
            linkFoto.className = 'verFoto';
            linkFoto.textContent = 'Ver foto';
            linkFoto.setAttribute('data-foto', foto);
            linkFoto.setAttribute('data-nome', nome);
            tdFoto.appendChild(linkFoto);
            
            // Anexar todas as células à linha
            row.appendChild(tdMatricula);
            row.appendChild(tdNome);
            row.appendChild(tdCpf);
            row.appendChild(tdValor);
            row.appendChild(tdParcelas);
            row.appendChild(tdTitulo);
            row.appendChild(tdPartido);
            row.appendChild(tdFoto);
            
            tbody.appendChild(row);
        });

        // Adicionar eventos aos links "Ver foto" com segurança
        document.querySelectorAll('.verFoto').forEach(link => {
            link.addEventListener('click', async function(e) {
                e.preventDefault();
                const foto = this.getAttribute('data-foto');
                const nome = this.getAttribute('data-nome');
                
                if (foto) {
                    try {
                        const modalTitle = document.querySelector('#modalFoto .modal-title');
                        const modalBody = document.querySelector('#modalFoto .modal-body');
                        
                        // Limpar conteúdo anterior
                        modalBody.innerHTML = '';
                        modalTitle.textContent = `Foto: ${sanitizeContent(nome)}`;
                        
                        // Criar elemento de imagem programaticamente
                        const img = document.createElement('img');
                        img.className = 'img-fluid';
                        
                        // Usar fetch autenticado para obter a imagem
                        const response = await authenticatedFetch(`/api/fotos/${foto}`);
                        if (response && response.ok) {
                            const blob = await response.blob();
                            const imgUrl = URL.createObjectURL(blob);
                            img.src = imgUrl;
                            modalBody.appendChild(img);
                            $('#modalFoto').modal('show');
                        } else {
                            modalBody.textContent = 'Erro ao carregar imagem';
                            $('#modalFoto').modal('show');
                        }
                    } catch (error) {
                        console.error('Erro ao carregar foto:', error);
                        alert('Erro ao carregar a foto');
                    }
                } else {
                    alert('Foto não disponível');
                }
            });
        });
    } catch (error) {
        console.error('Erro ao carregar cooperativados:', error);
        // Mostrar mensagem de erro na interface
        const alertElement = document.createElement('div');
        alertElement.className = 'alert alert-danger';
        alertElement.textContent = 'Erro ao carregar dados. Por favor, tente novamente mais tarde.';
        
        const container = document.querySelector('.container');
        container.insertBefore(alertElement, container.firstChild);
        
        // Remover alerta após 5 segundos
        setTimeout(() => alertElement.remove(), 5000);
    }
}

// Torna as linhas da tabela clicáveis para abrir a subpágina de cadastro
function enableTableClick() {
    const tbody = document.querySelector('#cooperativados-table tbody');
    tbody.addEventListener('click', function(e) {
        let target = e.target;
        while(target && target.nodeName !== 'TR') target = target.parentElement;
        if(target) {
            window.location.href = '#cadastro';
            showTab('cadastro');
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    if (!isAuthenticated()) {
        window.location.href = 'login.html';
        return;
    }
    
    // Adicionar handler de logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            logout();
        });
    }
    
    showTab('cadastro'); // Abre a aba Cadastro ao iniciar
    carregarGaleria();
    carregarCooperativados();
    enableTableClick();
});
