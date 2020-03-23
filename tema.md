# Tema 2

## Informații temă
Punctaj: 20% din total pentru laborator.
Deadline: **27 martie 2020**, se va lucra individual.

**UPDATE**: Predarea soluției se va face într-un repository de github.
Pentru a va inscrie folositi acest link: [https://classroom.github.com/a/9xUyiMpD](https://classroom.github.com/a/9xUyiMpD)

În repository scrieti sub forma de text sau markdown rezultatele voastre, puteți adăuga printscreen-uri din terminal, bucăți de cod și observații sau explicații pentru soluționarea exercițiilor. 

Pentru printscreen, asigurați-vă că este vizibil usernameul cu care faceți apelulrile din terminal.

Grupa 231 - Tudose Bogdan 
## Cerințe

1. Citiți informațiile despre [HTTP/S din capitolul2](https://github.com/senisioi/computer-networks/tree/2020/capitolul2#https). 
2. Citiți informațiile despre [UDP din capitolul2](https://github.com/senisioi/computer-networks/tree/2020/capitolul2#socket)
3. Citiți informațiile despre [TCP din capitolul2](https://github.com/senisioi/computer-networks/tree/2020/capitolul2#tcp)


Rezolvați:
- exercițiile de la sectiune [HTTP](https://github.com/senisioi/computer-networks/tree/2020/capitolul2#exercitii_http) (3%)
- exercitiile de la secțiunea [UDP](https://github.com/senisioi/computer-networks/tree/2020/capitolul2#exercitii_udp) (10%)
- exercițiile de la secțiunea [TCP](https://github.com/senisioi/computer-networks/tree/2020/capitolul2#exercitii_tcp). (7%)



# Solutie cu markdown


## Exerciții HTTP/S
1. Cloudflare are un serviciu DoH care ruleaza pe IP-ul [1.1.1.1](https://blog.cloudflare.com/announcing-1111/). Urmăriți [aici documentația](https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/) pentru request-uri de tip GET către cloudflare-dns și scrieți o funcție care returnează adresa IP pentru un nume dat ca parametru. Indicații: setați header-ul cu {'accept': 'application/dns-json'}.
```python
import requests
import json

def dns(name):
    headers = { "Accept": "application/dns-json"}
    params = { "name": name, "type":"A"}
    response = requests.get("https://1.1.1.1/dns-query", params = params, headers = headers)
    res_j = response.json()
    return res_j['Answer'][0]['data']
 ```  
![alt text](https://raw.githubusercontent.com/nlp-unibuc/tema-2-tudose-bogdan/master/1.png?token=AMH5YCYPR2CMM5VXKNVHW3S6PIPVW)
 
---

2. Executati pe containerul `rt1` scriptul 'simple_flask.py' care deserveste API HTTP pentru GET si POST. Daca accesati in browser [http://localhost:8001](http://localhost:8001) ce observati?
```
```
![alt text](https://raw.githubusercontent.com/nlp-unibuc/tema-2-tudose-bogdan/master/2.png?token=AMH5YC7WJISWPC4JMRMGDWS6PISSG)
---

3. Conectați-vă la containerul `docker-compose exec rt2 bash`. Testati conexiunea catre API-ul care ruleaza pe rt1 folosind curl: `curl -X POST http://rt1:8001/post  -d '{"value": 10}' -H 'Content-Type: application/json'`. Scrieti o metoda POST care ridică la pătrat un numărul definit în `value`. Apelați-o din cod folosind python requests.

Metoda apelata cu python
```python
import requests
import json
number = 10
url = 'http://rt1:8001/post'
headers = {'Content-Type': 'application/json'}
dat= json.dumps({'value':number})
res = requests.post(url, headers = headers, data = dat)
res_j = res.json()
print(res_j['value'])
```
simple_flask.py modificat
```python
from flask import Flask, jsonify
from flask import request

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello World!"


@app.route('/post', methods=['POST'])
def post_method():
    x = request.get_json()
    val = x['value']
    return jsonify({'value':val**2})
    


@app.route('/<name>')
def hello_name(name):
    return "Hello {}!".format(name)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001)


```
---

4. Urmăriți alte exemple de request-uri pe [HTTPbin](http://httpbin.org/)
```
Am aflat de metodele HTTP, GET, POST, PUT, DELETE si de [PATCH](http://httpbin.org/#/HTTP_Methods/patch_patch)
```

---


## Exerciții UDP
1. Executați serverul apoi clientul fie într-un container de docker fie pe calculatorul vostru personal: `python3 udp_server.py` și `python3 udp_client.py "mesaj de trimis"`.

Printscreen cu rezultatul:
![alt text](https://raw.githubusercontent.com/nlp-unibuc/tema-2-tudose-bogdan/master/3.png?token=AMH5YCZJRTSRUP5LTG2JKGC6PIV7S)

---

2. Modificați adresa de pornire a serverului din 'localhost' în IP-ul rezervat descris mai sus cu scopul de a permite serverului să comunice pe rețea cu containere din exterior. 

![alt text](https://raw.githubusercontent.com/nlp-unibuc/tema-2-tudose-bogdan/master/4.png?token=AMH5YC6ROFP3JUISHSYDG7K6PNXXY)
---

3. Porniți un terminal în directorul capitolul2 și atașați-vă la containerul rt1: `docker-compose exec rt1 bash`. Pe rt1 folositi calea relativă montată în directorul elocal pentru a porni serverul: `python3 /elocal/src/udp_server.py`. 
```
ragey@ragey-VirtualBox:~/231/computer-networks/capitolul2/src$ docker-compose exec rt1 bash
root@3b3a786ef7c9:/# python3 /elocal/src/udp_server.py
[LINE:13]# INFO     [2020-03-18 14:52:06,237]  Serverul a pornit pe 0.0.0.0 si portnul portul 10000
[LINE:16]# INFO     [2020-03-18 14:52:06,237]  Asteptam mesaje...


```

---

4. Modificați udp_client.py ca el să se conecteze la adresa serverului, nu la 'localhost'. Sfaturi: puteți înlocui localhost cu adresa IP a containerului rt1 sau chiar cu numele 'rt1'.
```python
# UDP client
import socket
import logging
import sys

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

port = 10000
adresa = 'capitolul2_rt1_1'
server_address = (adresa, port)
mesaj = sys.argv[1]

try:
    logging.info('Trimitem mesajul "%s" catre %s', mesaj, adresa)
    sent = sock.sendto(mesaj.encode('utf-8'), server_address)

    logging.info('Asteptam un raspuns...')
    data, server = sock.recvfrom(4096)
    logging.info('Content primit: "%s"', data)

finally:
    logging.info('closing socket')
    sock.close()
```
---

5. Porniți un al doilea terminal în directorul capitolul2 și rulați clientul în containerul rt2 pentru a trimite un mesaj serverului:  `docker-compose exec rt2 bash -c "python3 /elocal/src/udp_client.py salut"`
```python
ragey@ragey-VirtualBox:~/231/computer-networks/capitolul2/src$ docker-compose exec rt2 bash
WARNING: Some networks were defined but are not used by any service: dmz
root@8427ceefdbca:/# python3 /elocal/src/udp_client.py salut
[LINE:16]# INFO     [2020-03-18 14:53:54,254]  Trimitem mesajul "salut" catre capitolul2_rt1_1
[LINE:19]# INFO     [2020-03-18 14:53:54,259]  Asteptam un raspuns...
[LINE:21]# INFO     [2020-03-18 14:53:54,260]  Content primit: "b'salut'"
[LINE:24]# INFO     [2020-03-18 14:53:54,260]  closing socket
root@8427ceefdbca:/# 

```
---

6. Deschideți un al treilea terminal și atașați-vă containerului rt1: `docker-compose exec rt1 bash`. Utilizați `tcpdump -nvvX -i any udp port 10000` pentru a scana mesajele UDP care circulă pe portul 10000. Apoi apelați clientul pentru a genera trafic.

![alt text](https://raw.githubusercontent.com/nlp-unibuc/tema-2-tudose-bogdan/master/5.png?token=AMH5YC7I4NKISOERNWRDWCS6PNYVY)



---

7. Containerul rt1 este definit în [docker-compose.yml](https://github.com/senisioi/computer-networks/blob/2020/capitolul2/docker-compose.yml) cu redirecționare pentru portul 8001. Modificați serverul și clientul în așa fel încât să îl puteți executa pe containerul rt1 și să puteți să vă conectați la el de pe calculatorul vostru sau de pe rețeaua pe care se află calculatorul vostru.
```
trecem port: 8001:8001/udp

```
![alt text](https://raw.githubusercontent.com/nlp-unibuc/tema-2-tudose-bogdan/master/6.png?token=AMH5YC2TPDV6HKKLB5PI2SK6PS3BQ)

---


## Exerciții TCP

1. Executați serverul apoi clientul fie într-un container de docker fie pe calculatorul vostru personal: `python3 tcp_server.py` și `python3 tcp_client.py "mesaj de trimis"`.
```
prinscreen sau daca a mers la UDP, aici nu mai e necesar
```
---

2. Modificați adresa de pornire a serverului din 'localhost' în IP-ul rezervat '0.0.0.0' cu scopul de a permite serverului să comunice pe rețea cu containere din exterior. Modificați tcp_client.py ca el să se conecteze la adresa serverului, nu la 'localhost'. Pentru client, puteți înlocui localhost cu adresa IP a containerului rt1 sau chiar cu numele 'rt1'.
```
daca mers la UDP, aici nu mai e necesar
```

---

3. Într-un terminal, în containerul rt1 rulați serverul: `docker-compose exec rt1 bash -c "python3 /elocal/src/tcp_server.py"`. 

```
daca mers la UDP, aici nu mai e necesar
```

---

4. Într-un alt terminal, în containerul rt2 rulați clientul: `docker-compose exec rt1 bash -c "python3 /elocal/src/tcp_client.py TCP_MESAJ"`

Printscreen cu rezultatul:
![alt text](https://raw.githubusercontent.com/nlp-unibuc/tema-2-tudose-bogdan/master/7.png?token=AMH5YC26YCNQ35YCPJKXDZ26PS4AQ)

---

5. Mai jos sunt explicați pașii din 3-way handshake captați de tcpdump și trimiterea unui singur byte de la client la server. Salvați un exemplu de tcpdump asemănător care conține și partea de [finalizare a conexiunii TCP](http://www.tcpipguide.com/free/t_TCPConnectionTermination-2.htm). Sfat: Modificați clientul să trimită un singur byte fără să facă recv. Modificați serverul să citească doar un singur byte cu recv(1) și să nu facă send. Reporniți serverul din rt1. Deschideți un al treilea terminal, tot în capitolul2 și rulați tcpdump: `docker-compose exec rt1 bash -c "tcpdump -Snnt tcp"` pentru a porni tcpdump pe rt1. 
```
Flags [S] - cerere de sincronizare de la adresa 172.18.0.2 cu portul 51924 către adresa 172.18.0.3 cu portul 8001
seq 404893835 - primul sequence nr pe care îl setează clientul în mod aleatoriu
win 64240 -  Window Size inițial. 
options [mss 1460,sackOK,TS val 3396262237 ecr 0,nop,wscale 7] -  reprezintă Opțiunile de TCP
length 0 - mesajul SYN nu are payload, conține doar headerul TCP


IP 172.18.0.3.8001 > 172.18.0.2.51924: Flags [S.]
Flags [S.] - . (punct) reprezintă flag de Acknowledgement din partea serverului (172.18.0.3.8001) că a primit pachetul și returnează și un Acknowledgement number: ack  404893836 care reprezintă Sequence number trimis de client + 1
Flags [S.] - în același timp, serverul trimite și el un flag de SYN și propriul Sequence number: seq 482479803
optiunile sunt la fel ca înainte și length 0, mesajul este compus doar din header, fără payload


IP 172.18.0.2.51924 > 172.18.0.3.8001: Flags [.]
Flags [.] - . (punct) este pus ca flack de Ack și se transmite Ack Number ca fiind seq number trimis de server + 1: ack 482479804
length 0, din nou, mesajul este fără payload, doar cu header


IP 172.18.0.2.51924 > 172.18.0.3.8001: Flags [P.]
Flags [P.] - avem P și . (punct) care reprezintă PUSH de mesaj nou și Ack ultimului mesaj 482479804
seq 404893836:404893837 - se trimite o singură literă (un byte) iar numărul de secvență indică acest fapt
ack 482479804 - la orice mesaj, se confirmă prin trimiterea de Ack a ultimului mesaj primit, in acest caz se re-confirmă SYN-ACK-ul de la server
length 1 - se trimite un byte în payload

IP 172.18.0.3.8001 > 172.18.0.2.51924: Flags [.]
Flags [.] - flag de Ack
ack 404893837 - semnifică am primit octeți pana  la  404893837, 404893836:404893837
length 0 - un mesaj de confirmare nu are payload


```
