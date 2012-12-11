Student: Rachel Beasley
SID:860903821
login:rbeas002

To complie code: type "make"
To run: in one terminal type "server number" where number is any foure digit number.
Type in another terminal "client localhost:number filename" where numbe is the same number used in the other terminal and filname is the file you wish to transfer. 

Program "ssl_server.cpp" establishes ssl connection with program "ssl_client.cpp". Client send challenge numbe to server.Server hashes challenge value and signs the hash using RSA and the privatekey in file "rsaprivatekey.pem" and writes signature to client. Client decrypts signature hash using RSA and the public key in file "rsapublickey.pem" to see if it matches hash. Client writes file name to server, server recieves file name and reads from file with a BIO * (if file is avalible) and writes contents to client. Client reads file contents and outputs it. Client and server both close connection. 
