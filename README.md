# scan2

This repository provides a network scanner and brute-force tool. The original `main.py` starts a Qt GUI which requires a graphical environment. A lightweight command line interface is now available via `cli.py` for environments without GUI support.

## Usage

```
python cli.py TARGET -p PORTS [--tool {Nmap,Masscan}] [--speed {Slow (Stealth),Normal,Fast,Aggressive}]
```

Example:

```
python cli.py 192.168.1.0/24 -p 22,80 -t Nmap
```

The script attempts to locate `nmap` or `masscan` in your `PATH`. If the required scanner is not found, an error message is displayed.
