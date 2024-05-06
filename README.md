# 👩🏻‍💻 Port Scanners 👩‍💻

<p align="center">
<img src="https://github.com/paolacalle/port_scanners/assets/98432607/026e4b2c-9e47-43cb-a454-2562b2f165e3" width="300" height="300">
</p>

### Overview
This project involves creating custom port scanners from scratch. 

### Libraries Used
We used two python libaries:
* **Scapy**: Used for packet creation and manipulation
* **Socket**: Used for establishing TCP/UDP connections.

### Installation

```bash
git clone https://github.com/paolacalle/port_scanners
```

### Usage
Run scanner via command line:
```bash
python3 port_scanner.py [-options] target
```
Options:
* -mode [connect/syn/udp] - Choose the scanning mode.
* -order [order/random] - Specify the port scanning order.
* -ports [all/known] - Decide the range of ports to scan.

### The Team
