# Sieťový analyzátor

---

Druhý projekt do predmetu IPK, varianta ZETA: Sniffer paketov. Riešenie by malo spĺňať zadanie v plnom rozsahu. Upravený je výpis ARP a ICMP paketov, bližšie popísaný v súbore `manual.pdf`.

### Odovzdané súbory
- ipk-sniffer.cpp
- Makefile
- README.md
- manual.pdf

### Spustenie
Program podporuje povinné parametre

 - -i | --interface rozhranie - zachytávanie paketov na danom sieťovom rozhraní,

a voliteľné parametre

- -p port - zachytávanie paketov s daným portom v source alebo destination časti,
- -t | --tcp - zachytávanie TCP paketov,
- -u | --udp - zachytávanie UDP paktov,
- --icmp - zachytávanie ICMPv4 alebo ICMPv6 paketov,
- --arp - zachytávanie ARP rámcov,
- -n počet - počet zachytených paketov.

Parametre je možné kombinovať. Implicitne sa vypíše len jeden paket a odchytávajú sa všetky vyššie spomenuté typy paketov s ľubovoľným číslom portu.

### Príklady spustenia

```
$ ./ipk-sniffer --interface lo --udp -p 53
2021-04-23T09:47:10.291+02:00 127.0.0.1 : 53 > 127.0.0.1 : 40125, length 42 bytes
000000:  00 00 00 00 00 00 00 00  00 00 00 00 08 00 45 00   ........ ......E.
0x0010:  00 1c 20 c9 00 00 40 11  5c 06 7f 00 00 01 7f 00   .. ...@. \.......
0x0020:  00 01 00 35 9c bd 00 08  64 e9                     ...5.... d.
```

```
$ ./ipk-sniffer 
enp0s3
lo
any
bluetooth-monitor
nflog
nfqueue
```