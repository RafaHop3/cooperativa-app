// Tabs
function showTab(tabId) {
  const tabs = document.querySelectorAll('.tab-content');
  tabs.forEach(tab => {
    tab.classList.remove('active');
  });
  const tab = document.getElementById(tabId);
  if(tab) tab.classList.add('active');
}

// Galeria dinâmica
async function carregarGaleria() {
  const collage = document.getElementById('collage');
  collage.innerHTML = '';
  try {
    const resp = await fetch('http://127.0.0.1:8787/api/fotos');
    const fotos = await resp.json();
    fotos.forEach((src, i) => {
      const img = document.createElement('img');
      img.src = src;
      img.alt = `Foto ${i+1}`;
      collage.appendChild(img);
    });
  } catch (e) {
    collage.innerHTML = '<p style="color:#fff">Não foi possível carregar a galeria.</p>';
  }
}

// Cooperativados dinâmico
async function carregarCooperativados() {
  const tbody = document.querySelector('#cooperativados-table tbody');
  tbody.innerHTML = '';
  try {
    const resp = await fetch('http://127.0.0.1:8787/api/cooperativados');
    const lista = await resp.json();
    lista.forEach(item => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${item.matricula||''}</td>
        <td>${item.nome||''}</td>
        <td>${item.cpf||''}</td>
        <td>${item.valor||''}</td>
        <td>${item.parcelas||''}</td>
        <td>${item.titulo||''}</td>
        <td>${item.partido||''}</td>
        <td>${item.foto ? `<img src="${item.foto}" alt="foto" style="width:60px;height:60px;object-fit:cover;border-radius:8px;">` : ''}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="8">Não foi possível carregar os cooperativados.</td></tr>';
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
  showTab('cadastro'); // Abre a aba Cadastro ao iniciar
  carregarGaleria();
  carregarCooperativados();
  enableTableClick();
});
