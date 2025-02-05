# Password Generator API

Uma API RESTful robusta e segura para geração e análise de senhas, desenvolvida em .NET 7.

## 🚀 Funcionalidades

- Geração de senhas aleatórias criptograficamente seguras
- Análise de força de senhas
- Personalização completa dos parâmetros de geração
- Cálculo de entropia
- Análise detalhada de composição de caracteres

## 📋 Requisitos

- .NET 7.0 ou superior
- Visual Studio 2022 ou VS Code

## ⚙️ Configuração

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/password-generator-api.git
```

2. Navegue até a pasta do projeto:
```bash
cd password-generator-api
```

3. Restaure as dependências:
```bash
dotnet restore
```

4. Execute o projeto:
```bash
dotnet run
```

## 🔧 Endpoints

### Gerar Senha
```http
GET /api/password/generate
```

#### Parâmetros de Query
| Parâmetro | Tipo | Descrição | Padrão |
|-----------|------|-----------|---------|
| length | int | Comprimento da senha | 12 |
| includeUppercase | bool | Incluir maiúsculas | true |
| includeLowercase | bool | Incluir minúsculas | true |
| includeNumbers | bool | Incluir números | true |
| includeSpecialChars | bool | Incluir caracteres especiais | true |
| excludeSimilarChars | bool | Excluir caracteres similares | false |
| excludeAmbiguousChars | bool | Excluir caracteres ambíguos | false |

#### Exemplo de Resposta
```json
{
  "password": "xK9#mP2$vL5@",
  "timestamp": "2025-02-05T10:30:00Z",
  "entropy": 72,
  "strength": "Forte",
  "characterAnalysis": {
    "uppercase": 3,
    "lowercase": 3,
    "numbers": 3,
    "special": 3
  }
}
```

### Analisar Senha
```http
POST /api/password/analyze
```

#### Corpo da Requisição
```json
"MinhaSenh@123"
```

#### Exemplo de Resposta
```json
{
  "password": "MinhaSenh@123",
  "timestamp": "2025-02-05T10:30:00Z",
  "entropy": 65,
  "strength": "Forte",
  "characterAnalysis": {
    "uppercase": 1,
    "lowercase": 8,
    "numbers": 3,
    "special": 1
  }
}
```

## 🛠️ Tecnologias Utilizadas

- ASP.NET Core 7.0
- Swagger/OpenAPI
- System.Security.Cryptography
- Microsoft.Extensions.Logging

## 🔒 Segurança

- Uso de RandomNumberGenerator para geração criptograficamente segura
- Validações robustas de entrada
- HTTPS por padrão
- CORS configurável
- Logging seguro

## 🔍 Monitoramento

- Health checks em `/health`
- Logging estruturado
- Métricas de performance
- Compressão de resposta

## 📚 Documentação

A documentação completa da API está disponível via Swagger UI em:
```
https://localhost:5001/swagger
```

## ⚠️ Boas Práticas de Senha

A API segue as seguintes recomendações de segurança:
- Mínimo de 8 caracteres
- Combinação de diferentes tipos de caracteres
- Cálculo de entropia para avaliar força
- Opções para evitar caracteres ambíguos
- Geração criptograficamente segura

## 🤝 Contribuindo

1. Fork o projeto
2. Crie sua branch: `git checkout -b feature/nova-funcionalidade`
3. Commit suas mudanças: `git commit -m 'Adiciona nova funcionalidade'`
4. Push para a branch: `git push origin feature/nova-funcionalidade`
5. Abra um Pull Request
