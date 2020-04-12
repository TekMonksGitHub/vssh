# vssh
Very Secure Shell
---------

Plan to be more secure than SSH.

Public/Private key exchange then handshaking to AES-256.

# Usage - Server Side
(1) Install node.js on server.  
(2) Clone this repository.  
(3) Modify port or host in `conf/vssh.json`.  
(4) Run daemon as `node vsshd.js`.  

# Usage - Client Side
(1) Install node.js on server.  
(2) Clone this repository.  
(3) Login using `node vssh.js <ip> <port>`.  
