#cmdline "-s console"
#DEFINE UNICODE
#DEFINE _WIN32_WINNT &h0602
#INCLUDE ONCE "crInc\cKeyExchange\cKeyExchange.bi"
#INCLUDE ONCE "windows.bi"
#INCLUDE ONCE "win\bcrypt.bi"
#INCLUDE ONCE "win\wincrypt.bi"
#Inclib "bcrypt"
SUB Bin2Hex(BYREF sBinary AS STRING, _
            BYREF sHex AS STRING)
' Convert binary string to hex representation
dim nHexLength    AS LONG
    sHex = ""
    nHexLength = LEN(sBinary) * 2
    IF LEN(nHexLength) > 0 THEN
        nHexLength = nHexLength + 1
        sHex = SPACE(nHexLength)
        CryptBinaryToStringA(STRPTR(sBinary), _
                            LEN(sBinary), _
                            CRYPT_STRING_HEXRAW + CRYPT_STRING_NOCRLF, _
                            STRPTR(sHex), _
                            varptr(nHexLength))
         sHex = LEFT(sHex,nHexLength)
    END IF
END SUB

DIM sHex                 AS STRING
DIM ocKeyExchangeClient  AS cKeyExchange
DIM sClientPublicKey     AS STRING
DIM ocKeyExchangeServer  AS cKeyExchange
DIM sServerPublicKey     AS STRING
DIM bResult              AS BOOLEAN

   bResult = ocKeyExchangeClient.GetStartUpStatus()
   
   If bResult = False Then
       
      print "Client cKeyExchange constructor failure"
      print ocKeyExchangeClient.GetLastResult() 
      
   Else
       
      bResult = ocKeyExchangeServer.GetStartUpStatus() 
      
      If bResult = False Then
       
         print "Server cKeyExchange constructor failure"
         print ocKeyExchangeServer.GetLastResult() 
         
     End IF          
       
   End If
   
   If bResult = True Then

      bResult = ocKeyExchangeClient.GeneratePublicKey(sClientPublicKey)
      
   End If
   
   If bResult = True Then
       
      Bin2Hex(sClientPublicKey,sHex)
      print "Client Public Key"
      print sHex
      print
      
   Else
       
      print "Client " + "GeneratePublicKey failed"
      print ocKeyExchangeClient.GetLastResult() 
      
   End If
   
   If bResult = True Then
       
      bResult = ocKeyExchangeServer.GeneratePublicKey(sServerPublicKey)
      
      If bResult = True Then
         Bin2Hex(sServerPublicKey,sHex)
         print "Server Public Key"
         print sHex
         print
      
      Else
       
         print "Server " + "GeneratePublicKey failed"
         print ocKeyExchangeClient.GetLastResult() 
         
      End If    
      
   End If
   
   If bResult = True Then 
       
' Now siumlate sending Client public key to server       
       
      bResult = ocKeyExchangeServer.GenerateSecretKey(sClientPublicKey)
      
      If bResult = True Then
          
         print "Server Secret Key"
         Bin2Hex(ocKeyExchangeServer.GetSecretKey(),sHex)
         print sHex
         print         
          
      Else
       
         print "Server " + "GenerateSecretKey failed"
         print ocKeyExchangeClient.GetLastResult()           
          
      End If
       
   End If
   
   If bResult = True Then 
       
' Now simulate receiving the server public key      
       
      bResult = ocKeyExchangeClient.GenerateSecretKey(sServerPublicKey)
      
      If bResult = True Then
          
         print "Client Secret Key"
         Bin2Hex(ocKeyExchangeClient.GetSecretKey(),sHex)
         print sHex
         print         
          
      Else
       
         print "Client " + "GenerateSecretKey failed"
         print ocKeyExchangeClient.GetLastResult()           
          
      End If
       
   End If   
  
   If bResult = True then
       
' Compare Client and Server secret keys       
       
      If ocKeyExchangeClient.GetSecretKey() = ocKeyExchangeServer.GetSecretKey() Then
          
         print "Secret Keys Match!"
         
      Else
          
         print "Error - Derived Session Keys do not match!"
    
      End If       
       
   End If
   
   print
   print "Press any key..."
   sleep
   