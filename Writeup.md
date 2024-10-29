Видим довольно непонятное описание и ip c портом. 
попробуем тыкнуть его неткатом
![](https://i.imgur.com/v9By5R8.png)

Видим ответ, но вместо HTTP у нас HTCPCP. Некий "Hypertext Coffee Pot Control Protocol"
Его работа подробно описана в [RFC2324](https://datatracker.ietf.org/doc/html/rfc2324)
Стало быть перед нами кофеварка, которая поддерживает следующие методы:
```
BREW
PROPFIND
WHEN
GET
```

У каждой команды своя кофеварка и чтобы до нее добраться отправить запрос на путь /pot-{id}
Конструируем GET([2.1.2](https://datatracker.ietf.org/doc/html/rfc2324#section-2.1.2)) запрос, не забывая заголовок X-scheme ([3](https://datatracker.ietf.org/doc/html/rfc2324#section-3))
```
GET /pot-example HTCPCP/1.0
X-Scheme: coffee
```

![](https://i.imgur.com/Nk23FBB.png)
Кофеврка ждёт запросов, тогда отправим запрос BREW([2.1.1](https://datatracker.ietf.org/doc/html/rfc2324#section-2.1.1))
```
BREW /pot-example?milk-type=Part-Skim HTCPCP/1.0
X-Scheme: coffee
Content-Type: message/coffeepot
Content-Length: 25
  
coffee-message-body=start
```
Подождём немного и проверим состояние методом PROPFIND([2.1.3](https://datatracker.ietf.org/doc/html/rfc2324#section-2.1.3))
```
$ cat brew.txt | nc 192.168.56.133 9006 ; sleep 1 ; cat propfind.txt | nc 192.168.56.133 9006
HTCPCP/1.0 202 Accepted
Connection: close
Server: Goffee/1.0

Your brewing request will be processed shortly.HTCPCP/1.0 200 OK
Connection: close
Content-Type: application/json
Server: Goffee/1.0

{"status":"brewing","drink":{"name":"Coffee","quantity":6.443569,"additions":{"kind":"milk","name":"Part-Skim","quantity":0.000000}}}
```
Экспериментируя можно выяснить, что кофе наливается за 5 секунд, по ~15 мл в секунду, после чего наливается молоко с той же скоростью. По условию нам необходимо 90 мл молока. Значит нам необходимо остановить метод BREW через 11 секунд. Останавливаем методом WHEN([2.1.4](https://datatracker.ietf.org/doc/html/rfc2324#section-2.1.4)).  
![](https://i.imgur.com/nLUCce0.png)

Остается забрать напиток методом GET
![](https://i.imgur.com/FrAGX6w.png)
