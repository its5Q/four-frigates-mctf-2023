import socket
import time

IP = 'mctf-game.ru'
PORT = 9006
POT_ID = 'example'

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect((IP, PORT))

print('BREW request')

# BREW method from RFC2324, 2.1.1.
# X-Scheme to mimic the requirement from RFC2324, 3.
# Content-Type and body required by RFC2324, 4.
# Additions formatted according to RFC2324, 3.
c.send(
('''BREW /pot-%s HTCPCP/1.0
X-Scheme: coffee
Content-Type: message/coffeepot
Accept-Additions: milk-type/Part-Skim
Content-Length: 25

coffee-message-body=start''' % (POT_ID, )).encode()
)

print(c.recv(4096).decode())

c.close()

# Brewing time
time.sleep(5)

# Pouring time
time.sleep(90 / 18)

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect((IP, PORT))

print('WHEN request')

# Sending WHEN request to stop pouring milk as per RFC2324, 2.1.4.
c.send(
('''WHEN /pot-%s HTCPCP/1.0
X-Scheme: coffee

''' % (POT_ID, )).encode()
)

print(c.recv(4096).decode())

c.close()

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect((IP, PORT))

print('GET request')

# Retrieving our cup of brewed coffee
c.send(
('''GET /pot-%s HTCPCP/1.0
X-Scheme: coffee

''' % (POT_ID, )).encode()
)

print(c.recv(65535).decode(errors='ignore'))

c.close()