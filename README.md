# Joy | Easy | Четыре фрегата
Таск, разработанный мною для школьного финального этапа M*CTF 2023. Внимание: страшный код :D  
Особенно пропатченный кусок стандартной либы из-за её ограничений.

<b>RU</b><br>
В кофейне "Четыре фрегата" появилось передовая кофемашина, позволяющая делать заказ на готовку кофе удаленно! Друг попросил меня заказать у них чашку эспрессо с добавлением 90 мл самого свежего молока. Поможешь мне разобраться с этой чудо-машиной?

<b>EN</b><br>
The "Four Frigates" coffee shop now has an advanced coffee machine that allows you to order your coffee remotely! A friend asked me to order a cup of espresso from them with 90 ml of the freshest milk. Can you help me figure out this marvel of a machine?


# Flag
`mctf{"c0ff33"_mixed_w1th_"m1lk"_:wink:}`

# Administration
## Info
`9006` - port of application

## Launch
Сперва нужно положить в [pots.txt](pots.txt) по номеру для каждой команды, который они будут использоваться для взаимодействия с кофемашиной. Затем можно билдить и запускать.

    # docker-compose build
    # docker-compose up

## Check working

    $ echo -e "GET / HTCPCP/1.0\r\nX-Scheme: coffee\r\n\r\n" | nc 127.0.0.1 9006

## WriteUp
[solve.py](solve.py)
