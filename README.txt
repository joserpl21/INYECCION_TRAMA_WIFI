```bash
tx_process	    rx_process
|                      |
|------- Beacon ------>|            The announced SSID is "ap0"
|------- Beacon ------>|
|------- Beacon ------>|
|                      |
--------------------------------------------------------
|<--- Probe request ---| 
|                      |----------- The association process starts now
|--- Probe response -->|
|<------- ACK ---------|
--------------------------------------------------------
|                      |
|<--- Auth request ----|
|-------- ACK -------->|
|                      |
|--- Auth response --->|
|<------- ACK ---------|
--------------------------------------------------------
|                      |
|<--- Assoc request ---|
|-------- ACK -------->|
|                      |
|-- Assoc response --->|
|<------- ACK ---------|
------------------------------------------------------------------------------------
|                      | ------------- The association is completed
|                      |
|                      | ------------- Now the process of sending A-MPDUs can start
|                      |
|--- ADDBA Request --->|               AddBaRequest is an Action frame 
|                      |
|<------- ACK ---------|
|                      |
|<-- ADDBA Response ---|            
|                      |
|-------- ACK -------->|  
|                      |
|-------- A-MPDU ----->|            First A-MPDU
|-------- A-MPDU ----->|
|         ...          |
|-------- A-MPDU ----->|            Last A-MPDU
|                      |
|------ BA Request --->|            Block ACK request
|                      |
|<------- BA  ---------|            Block ACK
```



##Para poder utilizar las librerias de encryptado se necesita ejecutar los siguientes comandos
```bash
pip3 install random2
pip3 install pickle5
pip3 install python-secrets
pip3 install pycryptodome
pip3 install zlib-state
sudo apt-get update -y
sudo apt-get install -y python3-gmpy2
```

Para poder ejecutar los codigos se necesita cambiar el interfaz de tx_process y rx_process
Los comandos de inicio son
python3 tx_process.py rate formaCifrado
python3 rx_process.py rate formaCifrado

rate=>Velocidad (Mbps)
formaCifrado=>1(Cifrado normal AMSDU), 2(Cifrado de los chinos)


