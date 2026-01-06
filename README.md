# ADWAF | L7-Firewall
AD-WAF решение для фильтрации трафика на уровне L7  
В данном репо только инструкции по исполняемым функциям (FF; Filter-Function). Для сотрудничества пишите в личку, контакты в профиле.

## Структура посылаемого сообщения в фильтр
Данные приходят в следующем формате:
```json
{
  "connectionId": "ID-подключения:string",
  "webUniqueToken": "string::24bytes" // Либо уникальный токен, либо None/False, если stream!=http,
  "webUniqueSessions": [
    {
      "serviceId": "1", // ID-сервиса, к которому выполнялось обращение
      "tcptype": "http", // Тип соединения (http/tcp)
      "webUniqueToken": "string::24bytes",
      "status": "OK|Connection|dropped", // статус соединения
      "analyzeInfo": {"detected": false}, // статус анализа, false - необнаружено, true - обнаружено (что-либо)
      "packets": [
        {
          "type": "client->backend", // Тип направления пакета
          "stream": "R0VUIC9mbGFnJT...:base64string", // Данные пакета в base64
          "timestamp": 1762950737.564821, // timestamp-захвата
          "analyze": false // Если сообщение не было проанализировано до этого, если проанализировано то analyze=True
        }
      ]
    }
  ]
  "packets": [ // Список пакетов за соединение
    {
      "type": "client->backend", // Тип направления пакета
      "stream": "GET / HTTP/1.1\r\nHost: localhost:3113\r\n.....en-US;q=0.8,en;q=0.7\r\n\r\n", // ВСЕГДА в виде bytes
      "timestamp": 1762950737.564821, // timestamp-захвата
      "analyze": false // Если сообщение не было проанализировано до этого, если проанализировано то analyze=True
    }
  ], 
  "packetAnalyzeActual": { // Текущий пакет (который был прислан на анализ)
    "type": "backend->client", // Тип направления пакета
    "stream": "HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6.....\n</ul>\n<hr>\n</body>\n</html>\n" // ВСЕГДА в виде bytes
  }
}
```

```json
{
  "connectionId": "d24dd7d717cdc5c2bf9ffe51",
  "webUniqueToken": "3f21aaad" // Либо уникальный токен, либо None/False, если stream!=http,
  "webUniqueSessions": []
  "packets": [], // Список пакетов за соединение
  "packetAnalyzeActual": { // Текущий пакет (который был прислан на анализ)
    "type": "backend->client", // Тип направления пакета
    "stream": b"<script>alert(1)</script>" // ВСЕГДА в виде bytes
  }
}
```

```json
{
  "status": False,
  "message": "XSS-detected!"
}
```

## Простые примеры обработки сообщения
```python
def general(data):
    stream = data['packetAnalyzeActual']['stream'].decode("utf-8") # вытаскиваем stream
    if "flag{" in stream: # если flag{ есть в stream-object
        return {"status": False}

    return {"status": True} # анализ завершён успешно
```
## Выводим пользователю свой ответ на анализ (замена ответа сервера) + дроп соединения
```python
def general(data):
    stream = data['packetAnalyzeActual']['stream'].decode("utf-8") # вытаскиваем stream
    userMessage = """HTTP/1.1 504 GATEWAY TIMEOUT
Server: aHR0cHM6Ly90Lm1lL3ZlcmltYXNoLzI4MQ==
Content-Type: text/html; charset=utf-8
Connection: close

stop exploit!!!!!!!!!!!!!!!!!!!!!<br>aHR0cHM6Ly90Lm1lL3ZlcmltYXNoLzI4MQ==\n\n"""

    if "flag{" in stream: # если flag{ есть в stream-object
        return {"status": False, "uiDATA": userMessage} # выводим пользователю кастомное сообщение

    return {"status": True} # анализ завершён успешно
```
