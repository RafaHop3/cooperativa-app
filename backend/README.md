# Backend — Cooperativa App

Este backend fornece uma API REST para o app da cooperativa, usando FastAPI e SQLite.

## Como rodar

1. Instale as dependências:
   ```
   pip install -r requirements.txt
   ```
2. Inicie o servidor:
   ```
   uvicorn main:app --reload
   ```

A API estará disponível em http://127.0.0.1:8000

## Endpoints principais
- `GET /api/cooperativados` — Lista todos os cooperativados
- `POST /api/cooperativados` — Adiciona um cooperativado
- `GET /api/fotos` — Lista URLs das fotos
- `POST /api/fotos` — Adiciona uma foto

O banco de dados `cooperativa.db` é criado automaticamente na primeira execução.
