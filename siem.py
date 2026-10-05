import re
import csv
import argparse
from datetime import datetime, timedelta

parser = argparse.ArgumentParser(description="Detector de brute force em logs SSH")
parser.add_argument("--log", default="logs.txt", help="Caminho do arquivo de log")
parser.add_argument("--threshold", type=int, default=5, help="Tentativas mínimas para suspeita")
parser.add_argument("--window", type=int, default=60, help="Janela de tempo em segundos")
args = parser.parse_args()

pattern = r"^(\w{3} \d{2} \d{2}:\d{2}:\d{2}).*Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"

THRESHOLD = args.threshold
TIME_WINDOW = timedelta(seconds=args.window)

ip_timestamps = {}  # horários de falha por IP

with open(args.log, "r") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            timestamp_texto = match.group(1)
            usuario = match.group(2)
            ip = match.group(3)

            timestamp = datetime.strptime(timestamp_texto, "%b %d %H:%M:%S")

            if ip not in ip_timestamps:
                ip_timestamps[ip] = []
            ip_timestamps[ip].append(timestamp)


def eh_suspeito(lista_de_horarios):
    lista_de_horarios.sort()

    for i in range(len(lista_de_horarios) - THRESHOLD + 1):
        janela_inicio = lista_de_horarios[i]
        janela_fim = lista_de_horarios[i + THRESHOLD - 1]

        if (janela_fim - janela_inicio) <= TIME_WINDOW:
            return True

    return False


print("===== IPs Suspeitos =====")
resultados = {}

for ip, horarios in ip_timestamps.items():
    suspeito = eh_suspeito(horarios)
    resultados[ip] = (len(horarios), suspeito)

    if suspeito:
        print(f"IP: {ip} - {len(horarios)} tentativas, dentro da janela de {TIME_WINDOW.seconds}s")

with open("relatorio.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["IP", "Tentativas Falhas", "Status"])  # cabeçalhos (colunas)

    for ip, (total, suspeito) in resultados.items():
        status = "Suspeito" if suspeito else "Normal"
        writer.writerow([ip, total, status])

print("\nRelatório salvo em relatorio.csv")
