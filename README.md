Скрипт позволяет массово проверять HTTP-ответы и размеры файлов/страниц на веб-сервере. Он считывает список путей из файла, отправляет запросы к каждому ресурсу и выводит статус ответа и размер содержимого.

Особенности работы:
Многопоточность: использует пул потоков для параллельной обработки запросов
Оптимизация запросов: сначала отправляет HEAD-запрос для получения размера, и только если не удалось получить информацию - делает GET
Защита от блокировки: между запросами добавляется случайная задержка от 0.1 до 0.3 секунд
Обработка ошибок: корректно обрабатывает ошибки подключения и возвращает код ответа 0
