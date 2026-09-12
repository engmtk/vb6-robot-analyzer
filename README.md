# VB6 Gambeta Master — Analisador de executáveis legados

MVP para inventariar executáveis legados VB5/VB6 sem executá-los. O objetivo é recuperar evidências técnicas úteis para documentação e migração, não prometer a reconstrução exata do código-fonte original.

## O que esta versão faz

- valida e interpreta arquivos PE32/PE32+;
- identifica arquitetura, subsistema, entry point, seções e hash SHA-256;
- lista DLLs e funções importadas;
- detecta VB5/VB6 pelo runtime clássico;
- extrai strings ASCII e Unicode;
- identifica URLs, caminhos locais/UNC, Registro, ProgIDs COM, SQL, tabelas e procedures candidatas;
- mascara senhas, tokens e chaves encontradas no formato `chave=valor`;
- infere capacidades como banco, arquivos, rede, COM e interface gráfica;
- exporta relatórios HTML e JSON;
- oferece interface gráfica e execução por linha de comando.

O arquivo analisado **não é iniciado**. Mesmo assim, use apenas executáveis cuja análise esteja autorizada e trabalhe sempre com cópias.

## Executar no Windows

Pré-requisito: Python 3.10 ou superior instalado.

1. Extraia o projeto.
2. Clique duas vezes em `run-windows.bat`.
3. Clique em **Selecionar EXE**.
4. Clique em **Analisar**.
5. Consulte as abas e use **Exportar relatório**.

Não há pacotes Python obrigatórios nesta versão.

## Gerar um único EXE para Windows

Execute `build-exe-windows.bat`. O script instala o PyInstaller e cria:

```text
dist\VB6RobotAnalyzer.exe
```

Esse build precisa ser feito no Windows para produzir um executável Windows.

## Linha de comando

```bat
py -3 main.py C:\Robos\RoboCarga.exe --saida C:\Relatorios
```

## Executar os testes

```bat
py -3 -m unittest discover -s tests -v
```

Os testes criam em memória um pequeno arquivo PE sintético com uma importação do runtime VB6. Nenhum executável de teste é iniciado.

## Como interpretar o resultado

Os níveis de confiança são importantes:

- **alta**: evidência direta, como DLL importada ou URL armazenada no arquivo;
- **média**: padrão encontrado que ainda exige validação humana, como nome de tabela dentro de uma string SQL;
- **baixa**: inferência preliminar que não deve orientar uma migração sozinha.

O timestamp do cabeçalho PE não deve ser usado isoladamente como prova da data real de compilação.

## Limitações do MVP

- ainda não diferencia com segurança `Native Code` de `P-Code`;
- ainda não reconstrói Forms, módulos, classes e eventos VB6;
- não resolve CLSIDs no Registro do Windows;
- não analisa o comportamento em execução;
- não produz pseudocódigo;
- binários compactados ou protegidos podem ocultar imports e strings;
- a máscara de segredos reduz exposição acidental, mas o relatório ainda deve ser tratado como confidencial.

## Próximas evoluções propostas

1. Parser dos cabeçalhos internos do VB5/VB6.
2. Inventário de Forms, controles, módulos, classes e métodos.
3. Resolução local de COM/ActiveX, CLSID, ProgID, DLL e OCX.
4. Integração opcional com Ghidra em modo headless.
5. Grafo de chamadas com nível de confiança.
6. Exportação de arquitetura para `.drawio`.
7. Comparador entre fonte VB6 conhecido e evidências recuperadas.
8. Gerador de esqueleto de migração C# com portas/adaptadores.

## De/para com um projeto VB6 público

Escolha um projeto que tenha:

- fonte completo (`.vbp`, `.frm`, `.bas`, `.cls`);
- EXE compilável ou instruções claras de compilação;
- uma ou duas integrações reais, como arquivo + banco ou HTTP + arquivo;
- poucas dependências comerciais;
- licença permitindo estudo e engenharia reversa do próprio build.

