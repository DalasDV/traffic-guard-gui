Отдельная учётка trafficreader получает доступ только к журналу TrafficGuard, его CSV и проверке правил. Скрипт traffic-guard-reader проверяет разрешённые команды. Именно его запускает панель через sudo -n.

Если панель уже подключается под root в режиме «Прямое чтение», эта настройка не требуется.

## 1. Подготовьте ключ на своём компьютере

Скачайте файл traffic-guard-reader кнопкой вверху. В командах замените SERVER на IP или домен ноды. При нестандартном порте укажите -P ПОРТ для scp и -p ПОРТ для ssh.

### Linux и macOS

~~~sh
# Создаёт каталог для ключей с правами только для владельца.
install -d -m 0700 "$HOME/.ssh"
# Создаёт приватный ключ и открытый файл .pub.
ssh-keygen -t ed25519 -f "$HOME/.ssh/trafficguard_reader"
# Копирует на сервер скрипт чтения и только открытый ключ.
scp "$HOME/Downloads/traffic-guard-reader" "$HOME/.ssh/trafficguard_reader.pub" root@SERVER:/root/
~~~

### Windows · PowerShell

Если ssh-keygen недоступен, установите OpenSSH Client. Эту команду выполните в PowerShell от администратора.

~~~powershell
# Устанавливает штатный клиент SSH, включая ssh-keygen и scp.
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
~~~

Затем в обычном PowerShell:

~~~powershell
# Создаёт папку для ключей в профиле Windows.
New-Item -ItemType Directory -Force "$HOME/.ssh" | Out-Null
# Создаёт приватный ключ и открытый файл .pub.
ssh-keygen -t ed25519 -f "$HOME/.ssh/trafficguard_reader"
# Копирует на сервер скрипт чтения и только открытый ключ.
scp "$HOME/Downloads/traffic-guard-reader" "$HOME/.ssh/trafficguard_reader.pub" root@SERVER:/root/
~~~

Если браузер сохранил файл в другое место, подставьте его путь в scp.

## 2. Создайте учётку на сервере и выдайте права на чтение

Войдите на ноду как root. Команду adduser выполняйте один раз.

~~~sh
# Создаёт пользователя без парольного входа.
adduser --disabled-password --gecos '' trafficreader
# Устанавливает скрипт чтения. Изменять его может только root.
install -o root -g root -m 0755 /root/traffic-guard-reader /usr/local/sbin/traffic-guard-reader
# Создаёт закрытый SSH-каталог пользователя.
install -d -o trafficreader -g trafficreader -m 0700 /home/trafficreader/.ssh
# Добавляет открытый ключ. SSH разрешит ему только команды чтения из скрипта.
{ printf '%s' 'restrict,command="/usr/local/sbin/traffic-guard-reader ssh" '; cat /root/trafficguard_reader.pub; } >> /home/trafficreader/.ssh/authorized_keys
# Назначает пользователю владельца файла с открытым ключом.
chown trafficreader:trafficreader /home/trafficreader/.ssh/authorized_keys
# Оставляет чтение и запись файла только владельцу.
chmod 600 /home/trafficreader/.ssh/authorized_keys
# Открывает отдельный файл sudoers и проверяет его синтаксис при сохранении.
visudo -f /etc/sudoers.d/trafficguard-reader
~~~

Вставьте в открывшийся файл эту строку. Она разрешает запускать только скрипт чтения с правами root и без запроса пароля. Сам скрипт проверяет все аргументы.

~~~sudoers
trafficreader ALL=(root) NOPASSWD: /usr/local/sbin/traffic-guard-reader *
~~~

## 3. Проверьте доступ и добавьте хост

Команды работают в терминале Linux, macOS и в PowerShell. Пустой вывод первой команды допустим, если событий ещё не было.

~~~sh
# Читает последнюю запись TrafficGuard из журнала ядра.
ssh -i "$HOME/.ssh/trafficguard_reader" trafficreader@SERVER "sudo -n /usr/local/sbin/traffic-guard-reader probe - 0"
# Читает лишь CSV со статистикой TrafficGuard.
ssh -i "$HOME/.ssh/trafficguard_reader" trafficreader@SERVER "sudo -n /usr/local/sbin/traffic-guard-reader csv"
~~~

В панели добавьте учётные данные типа SSH-ключ. Логин — trafficreader, файл — trafficguard_reader без .pub. Укажите парольную фразу, если задали её при создании. У хоста выберите эти учётные данные, режим «sudo -n · помощник TrafficGuard» и нажмите «Проверить».
