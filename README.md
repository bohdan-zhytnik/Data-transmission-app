# Data-transmission-app

This repository contains a simple application for transferring files between devices within the same network using a customized UDP-based protocol. The application is divided into two components:

- **Sender**: Initiates and sends the file.
- **Receiver**: Listens for incoming transfer requests and receives the file.

## Features

- **UDP Transport**: Lightweight, connectionless protocol for fast data transmission.
- **CRC Checksum**: Ensures error-free delivery of each data packet.
- **Hash Verification**: Validates the integrity of the complete file after transfer.
- **Negotiation Phase**: Sender and Receiver exchange supported transfer parameters before starting the file transfer.

## Protocol Overview

1. **Handshake**:  
   - The Sender and Receiver establish an initial connection.  
   - They exchange metadata such as packet size, timeout settings, and CRC polynomial.
2. **Data Transfer**:  
   - The Sender splits the file into packets and computes a CRC checksum for each packet.  
   - Packets are sent over UDP to the Receiver.
3. **Error Control**:  
   - The Receiver verifies each packet using the CRC checksum.  
   - If a packet is corrupted or lost, the Receiver requests retransmission.
4. **Integrity Check**:  
   - After all packets are received, the Receiver computes a file-level hash.  
   - The Sender sends its own hash of the original file.  
   - The Receiver compares hashes to confirm file integrity.
