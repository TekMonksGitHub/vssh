# vssh
Very Secure Shell
---------

Plan to be more secure than SSH.

Public/Private key exchange then handshaking to AES-256.

Local user repository for custom auth, using SHA512 for shadow passwords.

# Usage - Server Side
(1) Install node.js on server.  
(2) Clone this repository.  
(3) Modify port or host in `conf/vssh.json`. Clients use default port of 8329.  
(4) Run daemon as `node vsshd.js`.  

# Usage - Client Side
(1) Install node.js on server.  
(2) Clone this repository.  
(3) Login using `node vssh.js <user id> <password> <ip> [optional: port]`.
(4) The default port is 8329.  
(5) Out of box login and password - ID: Test User, Password: Test password.
