# scan2

This repository provides a network scanner and brute-force tool. The original `main.py` starts a Qt GUI which requires a graphical environment. A lightweight command line interface is now available via `cli.py` for environments without GUI support.

## Usage

```
python cli.py TARGET -p PORTS [--tool {Nmap,Masscan}] [--speed {Slow (Stealth),Normal,Fast,Aggressive}] [--output results.csv]
```

Example:

```
python cli.py 192.168.1.0/24 -p 22,80 -t Nmap

To save results to a CSV file:

```
python cli.py 192.168.1.0/24 -p 22,80 -t Masscan --output scan.csv
```
```

The script attempts to locate `nmap` or `masscan` in your `PATH`. If the required scanner is not found, an error message is displayed.
 4v8f7x-codex/check-and-update-nmap-and-masscan-code

=======
When using Masscan the tool now emits list output via `-oL -` for easier parsing.
 main
