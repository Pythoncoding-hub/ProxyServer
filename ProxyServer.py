import socket  # импортируем модуль сокетов
import threading  # модуль для обработки соединений в разных потоках
import configparser  # модуль конфигурации с настройками
import datetime  # модули для управления временем
import sys


class ProxyServer:
    def __init__(self):  # инициализация прокси сервера
        self.config = configparser.ConfigParser()  # создаём объект парсера
        self.config.read("settings.ini")  # читаем файл с настройками

        self.log_entry(F"{self.get_datatime()} [ИНФО] Инициализация прокси сервера")
        self.log_entry(F"{self.get_datatime()} [ИНФО] Чтение файла настроек...")

        self.ip = self.config["settings"]["ip"]
        self.port = int(self.config["settings"]["port"])
        self.max_conn = int(self.config["settings"]["max_conn"])
        self.buffer_size = int(self.config["settings"]["buffer_size"])
        self.blacklist_ip = self.config["blacklist_ip"]["ip"].split()
        self.blacklist_domain = self.config["blacklist_domain"]["domain"].split()

        self.log_entry(F"{self.get_datatime()} [ИНФО] Чтение файла настроек [готово]")

    # функция возврата цвета
    def color(self, color):
        return self.config["colors"][color].split(",")

    # функция записи лога
    def log_entry(self, message):
        if message.find("[ОШИБКА]") != -1:  # если это сообщение об ошибке, ТО
            r, g, b = self.color("error")  # ...установить цвет
        elif message.find("[ВНИМАНИЕ]") != -1:
            r, g, b = self.color("attention")
        else:
            r, g, b = self.color("other")

        print(F"\033[38;2;{r};{g};{b}m{message}\033[0m")  # выводим сообщение в консоль

        with open("log.txt", "a+", encoding="utf-8") as file:  # запись сообщения в лог файл
            file.write(message)
            file.write("\n")

    # функция получения текущей даты и времени
    def get_datatime(self):
        return F"[{datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}]"

    # функция старта сервера
    def start_server(self):
        self.log_entry(F"{self.get_datatime()} [ИНФО] Запуск прокси сервера на {self.ip} порт {self.port}")

        try:
            self.listening()  # начинаем прослушивать входящие соединения
        except KeyboardInterrupt:
            self.log_entry(F"{self.get_datatime()} [ИНФО] Работа сервера прервана")
        finally:
            self.log_entry(F"{self.get_datatime()} [ИНФО] Сервер остановлен")
            sys.exit()

    # функция прослушивания входящих сообщений
    def listening(self):
        try:
            self.log_entry(F"{self.get_datatime()} [ИНФО] Инициализация сокетов...")
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.log_entry(F"{self.get_datatime()} [ИНФО] Инициализация сокетов [готово]")
            self.log_entry(F"{self.get_datatime()} [ИНФО] Привязка сокетов...")
            server_socket.bind((self.ip, self.port))  # привязать сокет для прослушивания
            self.log_entry(F"{self.get_datatime()} [ИНФО] Привязка сокетов [готово]")
            self.log_entry(F"{self.get_datatime()} [ИНФО] Прослушивание входящих соединений...")
            server_socket.listen(self.max_conn)
        except socket.error as error:
            self.log_entry(F"{self.get_datatime()} [ОШИБКА] Не удалось создать сокет: {error}")
            sys.exit(1)

        while True:
            try:
                # принять соединение из клиентского браузера (вернёт кортеж соединение и адрес)
                client_socket, client_address = server_socket.accept()
                self.log_entry(F"{self.get_datatime()} [*] Запрос от клиента {client_address[0]}:{client_address[1]}")
                # создаём новый поток (target - функция для выполнения, args - аргументы функции)
                thread = threading.Thread(target=self.get_request, args=(client_socket, client_address))
                thread.start()  # запускаем поток
            except Exception as error:
                self.log_entry(F"{self.get_datatime()} [ОШИБКА] Не удалось установить соединение: {error}")
                server_socket.close()
                sys.exit(1)

    # функция чтения данных из запроса
    def get_request(self, client_socket, client_address):
        # получаем необходимую информацию из заголовка
        try:
            request = client_socket.recv(self.buffer_size)  # получаем запрос
            header = request.split(b' ')  # список с данными из запроса
            website = header[1]  # получаем адрес сайта и порт
            self.log_entry(F"{self.get_datatime()} [*] {header[0].decode("utf-8")} запрос на подключение к {website.decode("utf-8")}")

            # проверка не защищённого соединения
            if header[0] == b"GET":
                self.log_entry(F"{self.get_datatime()} [ВНИМАНИЕ] Не защищённое соединение с {website.decode("utf-8")} по HTTP запрещено!")
                client_socket.close()
            else:

                site = website.split(b":")[0]  # получаем имя сайта
                port = int(website.split(b":")[1])  # получаем порт сайта

                if client_address[0] in self.blacklist_ip:  # проверка наличия IP-адреса клиента в чёрном списке
                    self.log_entry(F"{self.get_datatime()} [ВНИМАНИЕ] IP адрес {client_address[0]} в чёрном списке")
                    client_socket.close()
                elif site.decode("utf-8") in self.blacklist_domain:  # проверка наличия домена в чёрном списке
                    self.log_entry(F"{self.get_datatime()} [ВНИМАНИЕ] Веб-сайт {site.decode("utf-8")} в чёрном списке")
                    client_socket.close()
                elif header[0] == b"CONNECT":
                    self.log_entry(F"{self.get_datatime()} [*] Запрос на подключение по протоколу HTTPS")
                    self.https_connection(site, port, client_socket, request)

        except Exception as error:
            self.log_entry(F"{self.get_datatime()} [ОШИБКА] Не удалось прочитать запрос на подключение: {error}")
            return

    def https_connection(self, site, port, client_socket, request):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.connect((site, port))  # подключение к сайту по порту
            self.log_entry(F"{self.get_datatime()} [*] Подключение к {site.decode('utf-8')}:{port}")
            client_socket.sendall(request)  # отправка всех данных из буфера клиенту
        except socket.error as error:
            self.log_entry(F"{self.get_datatime()} [ОШИБКА] Не удаётся подключиться к сайту: {error}")

        client_socket.setblocking(False)
        server_socket.setblocking(False)
        self.log_entry(F"{self.get_datatime()} [*] Установлено HTTPS-соединение с {site.decode('utf-8')}:{port}")
        while True:
            try:
                data = client_socket.recv(self.buffer_size)  # получаем все данные у клиента
                server_socket.sendall(data)  # отправка всех данных из буфера на сервер
            except:
                pass

            try:
                data = server_socket.recv(self.buffer_size)  # получаем все данные у сервера
                client_socket.sendall(data)  # отправка всех данных из буфера клиенту
            except:
                pass


def main():
    proxy = ProxyServer()  # инициализация прокси сервера
    proxy.start_server()  # старт прокси сервера

if __name__ == "__main__":
    main()
