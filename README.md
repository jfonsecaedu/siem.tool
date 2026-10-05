# SIEM Caseiro — Analisador de Logs Suspeitos

Meu primeiro projeto de cibersegurança, feito para fins de estudos. Script Python que lê logs de autenticação SSH e identifica possíveis ataques de brute force com base em múltiplas tentativas de login falhas vindas do mesmo IP dentro de um intervalo curto de tempo.

## O que ele faz

- Lê um arquivo de log no formato padrão de autenticação do Linux (`auth.log`)
- Usa regex para extrair timestamp, usuário e IP de cada tentativa de login falha
- Agrupa os horários de falha por IP
- Classifica um IP como suspeito quando ele atinge um número mínimo de falhas (`THRESHOLD`) dentro de uma janela de tempo curta (`TIME_WINDOW`), evitando falsos positivos de falhas isoladas e espalhadas ao longo do tempo
- Exibe um resumo no terminal
- Gera um relatório em CSV (`relatorio.csv`) com todos os IPs, total de tentativas e status (Suspeito/Normal)

## Por que esse projeto

Esse é o meu primeiro projeto prático de segurança, feito para aplicar de forma simples e do zero o conceito central de um SOC: detectar padrões suspeitos em logs de autenticação, considerando não só quantidade, mas também o tempo entre as tentativas. A ideia foi construir manualmente a lógica de detecção sem frameworks prontos, para entender de fato como uma ferramenta de SIEM funciona.

## Como rodar

Pré-requisitos: Python 3 instalado

```bash
python3 siem.py
```

Por padrão, o script lê um arquivo `logs.txt` na mesma pasta, no formato:

```
Aug 09 14:50:02 server sshd[7270]: Failed password for invalid user test from 203.0.113.77 port 60598 ssh2
```

Os parâmetros de detecção podem ser ajustados direto na linha de comando, sem editar o código:

```bash
python3 siem.py --log outro_log.txt --threshold 3 --window 30
```

| Opção | Padrão | Descrição |
|---|---|---|
| `--log` | `logs.txt` | Caminho do arquivo de log a analisar |
| `--threshold` | `5` | Tentativas falhas mínimas para considerar um IP suspeito |
| `--window` | `60` | Janela de tempo (em segundos) em que essas tentativas precisam ocorrer |

Para ver todas as opções: `python3 siem.py --help`

## Exemplo de saída

Terminal:

```
===== IPs Suspeitos =====
IP: 203.0.113.77 - 14 tentativas, dentro da janela de 60s

Relatório salvo em relatorio.csv
```

`relatorio.csv`:

| IP | Tentativas Falhas | Status |
|---|---|---|
| 203.0.113.77 | 14 | Suspeito |
| 198.51.100.23 | 3 | Normal |
| 10.0.0.9 | 2 | Normal |
| 192.168.1.10 | 1 | Normal |

## Limitações e próximos passos

- Só reconhece o formato de log de autenticação SSH do Linux
- Não distingue tentativas de usuários diferentes vindas do mesmo IP (todas contam igual para o threshold)
- Próximos passos possíveis: suportar outros formatos de log (ex: logs de aplicação web), gerar alertas automáticos (e-mail/webhook), e visualização em dashboard
