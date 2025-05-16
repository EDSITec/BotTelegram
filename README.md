<p align="center">
<img src="screenshots/BannerEDSI.png" width="1024" >
</p>

# BOT Telegram & Vision One :robot:

Toma acciones en tu consola de Vision One por mensaje. El Bot se encargará de realizar el trabajo.

### Crea tu BOT de Telegram con BotFather y genera tu Token

[How To](https://core.telegram.org/bots)
<p align="center">
<img src="screenshots/botfather.png" width="400" >
</p>

### Pasos

#### Descarga el Proyecto

```bash
git clone git@github.com:EDSITec/BotTelegram.git
```

#### Modifique API KEY en el archivo engine.py

<p align="center">
<img src="screenshots/aapi.png" width="400" >
</p>

#### Construir la imagen

```bash
docker build -t bot .
```

#### Ejecutar el contenedor

```bash
docker run -e TOKEN_TELEGRAM="YOUR_TELEGRAM_TOKEN" bot
```

Diálogo entre el BOT y el Administrador, donde se le informa las instrucciones para realizar e impactar en su consola de Vision One. Utilizando el comando /help le proporcionara las posibiles acciones que pueda realizar.

<p align="center">
<img src="screenshots/start.png" width="400" >
</p>
<p align="center">
<img src="screenshots/TelegramBot2.png" width="800" >
</p>

### Consulta de tareas disponibles

<p align="center">
<img src="screenshots/help.png" width="400" >
</p>

## Prueba

Puedo validar que el bot este funcionando ejecutando el comando /chiste en Telegram

<p align="center">
<img src="screenshots/chiste.png" width="800" >
</p>


## Proceso :robot:

Dentro de la consola Trend Micro Vision One, debemos generar un API Key la cual va a ser utilizada por el BOT.
Debemos editar el archivo engine.py, modificando el parametro token y agregaremos el valor de la API Key que nos otorga la consola de Vision One.


*** IMPORTANTE: ASIGNAR SOLO LOS PERMISOS NECESARIOS A LA API KEY ***

### Envío IoC al Bot

<p align="center">
<img src="screenshots/ios.png" width="400" >
</p>

### Impacto del IoC en Trend Micro Vision One en sección de indicadores de compromiso

<p align="center">
<img src="screenshots/iocv1.png" width="800" >
</p>

### Indicarle al Bot que aisle un Endpoint

<p align="center">
<img src="screenshots/aislar.png" width="400" >
</p>

### Indicarle al Bot que restablezca un Endpoint

<p align="center">
<img src="screenshots/recuperar.png" width="400" >
</p>

### Impacto del acciones de respuesta globales en Trend Micro Vision One

<p align="center">
<img src="screenshots/respuesta ioc.png" width="800" >
</p>
