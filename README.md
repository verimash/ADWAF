# ADWAF | L7-Firewall
AD-WAF решение для фильтрации трафика на уровне L7  
В данном репо только инструкции по исполняемым функциям (FF; Filter-Function)

## Структура посылаемого сообщения в фильтр
Данные приходят в следующем формате:
```json
{
  "connectionId": "ID-подключения:string", 
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
```python
print("hello world!")
```
