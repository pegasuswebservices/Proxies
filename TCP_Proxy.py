#Several Reasons to Have TCP Proxy

#1) Forward traffic to bounche from host to host
#2) For assessing Network-Based software

#Python Proxies Helps us understand unknown protocols, modify traffic
#being sent (like Burp Proxy), and Create test caes for fuzzers.



#--------WE NEED TO:--------
#display the commmunication between LOCAL and REMOTE machines to the console (hexdump)

#Recive data from INCOMING SOCKET from either LOCAL or REMOTE machine (receive_from)

#Manage traffic diretction between REMOTE and LOCAL MACHINES (proxy_handler)

#Set up listening socket and pass it to our proxy_handler    (server_loop)


import sys
import socket
import threading




#-----------------------------------------

#String of 256 characters
#The order of the character in the string corresponds to it's ASCII value.

#So here, the 65th character in the string is A because   A  in ASCII is 65
#................................................................ !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................

HEX_FILTER = ''.join(
    [(len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])



#chr(i)     converts integer (i) from (0 to 255) into it's corresponding ASCI chracter
#e.g  chr(65) -> A

#repr(chr(i))      creates string representation of the character
#for Printable Characters   repr   outputs the character enclosed in single quotes
#e.g    repr('A')  ->  " 'A' "    ->  three character because '  A   '

#thus is length is 3, the character is printable

#len(repr(chr(i))) == 3    checks length of repr(chr(i)) is exactly 3.
#this is means the character is printable"


#or '.'    means that if the length of the string represetntaion is greater than 3, it is a non-printable character and thus replaced wiht a period '.'



#WHY DISTINGIUSH if Character is Printable or Not?

    #Printable characters have a simple representation

    #Non-printable characters are represented as Escape Sequences
        #e.g  chr(1) -> '\x01' -> length greater than 3.


    #This allos us to ensure that only Printable Characters are included in the
    #HEX_FILTER string;

    #Non-Printable Characters are replaced with a period '.'
#------------------------------------






#Display Communication between LOCAL and REMOTE machines

    #It generats a Hex Dump of a given string or byte sequence.
    #Hex Dump is a representation of Binary (010101) or textual data in human readable format

        #E.G If you have data:    Hello, world!
        #Hex Dump Would Be:       0000  48 65 6C 6C 6F 2C 20 77 6F 72 6C 64 21 01 02 03



#Paramters:
    #src       the input data to be processed (string or btyes)
    #length=16      Number of bytes to display per line
    #show=True      Prints the reults directly in raw hex format.

def hexdump(src, length=16, show=True):

    if isinstance(src, bytes):  #this checks if src  is BYTES.  then decodes it into string
        src = src.decode()
    
    results = list()    #creates empty list to store the formatted hex dump lines.
    


        #remember length variable = 16
    for i in range (0, len(src), length):   #iterates through the length of the input, 16 bytes at a time.
                                    #first iteration i = 0
                                    #second iteration i = 16
                                    #third iteration i = 32 and so on until end of src.
        word = str(src[i:i+length]) #In first iteration, extracts first 16 bytes and converts to string
                                    #Insecond iteration, extracts next 16 bytes (src[16:32]) and converts to string
                                    #continues for every 16 bytes until end of src.
       
        printable = word.translate(HEX_FILTER) #Replaces non printable characters with a .  and leaves printable characters unchanged

        hexa = ' '.join([f'{ord(c) :02X}' for c in word]) #Converts each character into it's two-digit hexadeecmial ASCII Code.
        #e.g (ord(c))     if c = A  it would be converted to 65.   :02X   ensures that performs capital conversions.
        #So it goes through   word   and converts  it  into it's ASCII equivelant.

        #so  hexa  could  end up looking  like this
        #hexa = 0000  48 65 6C 6C 6F 2C 20 77 6F 72 6C 64 21 01 02 03


        hexwidth = length*3 
        #Helps with foramtting and allignment.



        results.append(f'{i:04x} {hexa:<{hexwidth}}{printable}')

        #Remeber this is in the for loop.
        #i    is the starting byte offset for the current chunk.  0, 16, 32   etc
        # :04X   sets width of 4 characters and converts number to lower case hex equivelant

        #hexa < {hexwidth}   for formatting

        #The string containg the human readable characters

        #e.g  example INUPT:
            #i = 0
            #hexa = "48 65 6C 6C 6F" (hex for "Hello")
            #hexwidth = 48
            #printable = "Hello"


        #e.g example OUTPUT:
            #0000  48 65 6C 6C 6F                 Hello



    if show:    #Detects if Show=True
        for line in results:
            print(line) #Prints each line in the list.
    else:
        return results 






#---- Watch The Communicatino going Through the Proxy in real time.

def recieve_from(connection):
    buffer= b"" #Initially set buffer as empty

    connection.settimeout(5) #Maybe extend this if dealing with proxies in other countries



    #Try and Except block for error handling the connection
    try:
        while True: #receive data from teh connection until there is no more data to receive
            
            data = connection.recv(4096)

            if not data: #if no data received break the connection
                break
            
            buffer += data #Append data to the buffer
    


    except Exception as e:  #if there is an error, pass through and keep the loop going until data is received.
        pass
    
    return buffer






#-----Sometimes Want to Modify the Request or Response packets
#BEFORE the proxy sends them

    #--- Perfect Example of this is Burp Suite Proxy

        #--E.G  Web App has client-side SQL Input sanitzatiton
        #   So the safe query hits the proxy,  then in this request_handler
        #   We modify the SQL Query to be malicious.
        #   Proxy then forwards the malicious SQL query to the server.

        #   Thus, we used the Proxy to bypass client-side filtering.


def request_handler(buffer):
    #perform packet modifications
    return buffer



def response_handler(buffer):
    #perform packet modifications
    return buffer








#-------CREATE PROXY HANDLER-----------------

def proxy_handler(client_socket, remote_host, remote_port, receive_first):

    #Create and Connect to the scoket for the remote host.
    remote_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    remote_socket.connect((remote_host, remote_port))


#------Dealing with Server Sending Initailization reqests or Banners

    #If the remote device sends data first, for the connection we need to handle it,

    #E.g FTP servers send a banner first.

    #We capture the data from the remote_socket.. As they sent us the connection initialization request.
    if receive_first:
        remote_buffer = recieve_from(remote_socket)
        hexdump(remote_buffer)


    #Use the response_handler to perform any modifications we want.
    remote_buffer = response_handler(remote_buffer)


    #If the remote_buffer has contents in (i.e If the remote buffer sent their initalization request..
    #Then send tehh remote_buffers initialization request to the client.
    if len(remote_buffer):
        print("[<==] Sending %d bytes to localhost." %len(remote_buffer))
        client_socket.send(remote_buffer)
    
#------------Initialization handling END--------------


    
    #ENTER MAIN LOOP

    #Receives Data From Client
    #Recieves Data From Remote Host.

    #Forwards Data From Proxy to Client
    #Forwards Data From Proxy to Server.
    while True:


        local_buffer = recieve_from(client_socket) #recv data from client and store in local_buffer


        if len(local_buffer): #if data received from client
            line="[==>] Received %d bytes from the localhost." %len(local_buffer)
            print(line)
            hexdump(local_buffer) #allow us to see data in human readable format

            local_buffer = request_handler(local_buffer) #perform modifications

            remote_socket.send(local_buffer) #Forward the modified data to the remote host

            print("[==>] Sent to remote.")


        
        remote_buffer = recieve_from(remote_socket) #receive data from remote



        if len(remote_buffer): #if any data was received from remote
            print("[<== Received %d bytes from remote.]" %len(remote_buffer))

            hexdump(remote_buffer) #allow us to see data in human readable format

            remote_buffer = response_handler(remote_buffer) #perfrom modifications to data

            client_socket.send(remote_buffer) #forward the modified Data to the client.

            print("[==>] Sent to localhost.")

        
        if not len(local_buffer) or not len(remote_buffer): #if no data received from either Client Or Remote
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections.")
            break





#------CONNECTION HANDLER FOR THE PROXY-------OUR DEVICE IS THE PROXY SERVER-------****************

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #Error handling for connection. If fails then program will exit
    try:
        server.bind((local_host, local_port)) #Allow Local Device to interact with Proxy
    
    except Exception as e: #Error handling: If connection fails then exit out
        print('Problem on bind: %r' %e)

        print("[!!] Failed to listen on %s:%d" %(local_host, local_port))

        print("[!!] Check for other listening sockets or correct permissions")
        
        sys.exit(0)
    

    #If binding successful, server starts listenign
    print("[*] Listening on %s:%d"%(local_host, local_port))

    server.listen(5)#Server will backlog of 5 connection attempts at once.
    

    while True:
        client_socket, addr = server.accept() #Serve accepts incoming connection.

        #Print out the local connection information

        line = "> Received incoming connection from %s:%d"%(addr[0],addr[1])

        print(line)

        #Start a Thread to communicate with the remote host
        #When the new connection comes in, we hand it off to the proxy handler to do all the juicy bits and modifications.
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
    
        proxy_thread.start()




def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./TCP_Proxy.py [localhost] [localport]", end='')

        print("[remotehost] [remoteport] [recieve_first]")
        print("Example ./TCP_Proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")

        sys.exit(0)


    #Mapping Input Argumets to The Variables.
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    recieve_first = sys.argv[5]


    if "True" in recieve_first: #If recieve_first set in command line.
        recieve_first = True
    
    else:
        recieve_first = False
    

    server_loop(local_host, local_port, remote_host, remote_port, recieve_first)



if  __name__ == '__main__':
    main()