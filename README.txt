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
