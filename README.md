					Welcome to the Privilege Scanner README file!    

Privilege Scanner  
=============

```OFENSIVA```  
**privilege-scanner** é um script em bash que busca binários com permissão SUID no sistema e testa se algum deles permite escalada de privilégios para `root`.  
  
> A ferramenta é apenas para fins educacionais e deve ser usada de forma ética e legal. Não utilize em sistemas sem permissão.  
> Ela **não** abre shelll, deixa em persistência ou modifica o sistema — apenas testa se é possível escalar privilégios.  
  
Uso
-----------
Clone o repositório:  
  
```git clone https://github.com/whoami-a51/privilege-scanner.git```  
```cd privilege-scanner-main```  
```chmod +x privilege-scanner.sh```  
  
Execute como usuário comum (não root):  
```./privilege-scanner.sh```    
  
Como ele funciona
-----------
- Procura por arquivos SUID no sistema (`find / -perm -4000`)  
- Testa alguns binários populares com técnicas conhecidas de escalada de privilégios  
  - `nmap`  
  - `ksu`  
  - `su`  
  - `sudo`  
  - `mount`  
  - `pkexe`  
  - `sg`  
  - `crontab`   
- Gera saída indicando se algum binário oferece escalada  
    
