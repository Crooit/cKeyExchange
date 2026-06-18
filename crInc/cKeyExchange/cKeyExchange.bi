' ########################################################################################
' File: cKeyExchange.bi
' Contents: 384 bit Public Key Exchange
' Version: 1.0
' Compiler: FreeBasic 32 & 64-bit
' Copyright (c) 2026 Rick Kelly
' Credits: AFXNova by Jose Roca at: https://github.com/JoseRoca/AfxNova
'
' Released into the public domain for private and public use without restriction
' THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
' EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
' MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
' ########################################################################################

#DEFINE UNICODE
#DEFINE _WIN32_WINNT &h0602

#INCLUDE ONCE "windows.bi"
#INCLUDE ONCE "win\bcrypt.bi"
#INCLUDE ONCE "win\wincrypt.bi"
#INCLUDE ONCE "win\ddk\ddk_ntstatus.bi"
#INCLUDE ONCE "AfxNova\DWSTRING.inc"
#INCLIB "bcrypt"
#INCLIB "crypt32"

' ########################################################################################
' ccKeyExchange Class
' ########################################################################################

Type cKeyExchange Extends Object

   Private:

   lStatus            AS NTSTATUS = STATUS_SUCCESS
   hAlgorithm         AS BCRYPT_ALG_HANDLE = 0
   hKey               AS BCRYPT_KEY_HANDLE = 0
   sSecretKey         AS STRING = ""

   Public:

      DECLARE Constructor
      DECLARE Destructor
      DECLARE FUNCTION GetLastResult() AS DWSTRING
      DECLARE FUNCTION GetStartUpStatus() AS BOOLEAN
      DECLARE FUNCTION GetSecretKey() AS STRING
      DECLARE FUNCTION GeneratePublicKey(BYREF sPublicKey AS STRING) AS BOOLEAN
      DECLARE FUNCTION GenerateSecretKey(BYREF sPartnerPublicKey AS STRING) AS BOOLEAN

End Type

Constructor cKeyExchange

' Open Algorithm Provider

   lStatus = BCryptOpenAlgorithmProvider(VARPTR(hAlgorithm),STRPTR(BCRYPT_ECDH_P384_ALGORITHM),STRPTR(MS_PRIMITIVE_PROVIDER),0)

   If lStatus = STATUS_SUCCESS Then

' Generate Key Pair

      lStatus = BCryptGenerateKeyPair(hAlgorithm,VARPTR(hKey),384,0)

      If lStatus <> STATUS_SUCCESS Then

         BCryptCloseAlgorithmProvider(hAlgorithm,0)
         hAlgorithm = 0

      Else

         lStatus = BCryptFinalizeKeyPair(hKey,0)

         If lStatus <> STATUS_SUCCESS Then
            BCryptCloseAlgorithmProvider(hAlgorithm,0)
            hAlgorithm = 0
            BCryptDestroyKey(hKey)
            hKey = 0

         End If

      End If

   End If

End Constructor
 
Destructor cKeyExchange

   If hAlgorithm <> 0 Then

      BCryptCloseAlgorithmProvider(hAlgorithm,0)
      hAlgorithm = 0

   End If

   If hKey <> 0 Then

      BCryptDestroyKey(hKey)
      hKey = 0

   End If

End Destructor

' =====================================================================================
' Generate a Public Key
' =====================================================================================

PRIVATE FUNCTION cKeyExchange.GeneratePublicKey(BYREF sPublicKey AS STRING) AS BOOLEAN

DIM nKeySize      AS ULONG

   sPublicKey = ""

' Get Public Key

   lStatus = BCryptExportKey(hKey,NULL,STRPTR(BCRYPT_ECCPUBLIC_BLOB),NULL,0,VARPTR(nKeySize),0)    ' Get key size

   If lStatus <> STATUS_SUCCESS Then

      RETURN False
      EXIT FUNCTION

   End If

   sPublicKey = SPACE(nKeySize)
   lStatus = BCryptExportKey(hKey,NULL,STRPTR(BCRYPT_ECCPUBLIC_BLOB),STRPTR(sPublicKey),nKeySize,VARPTR(nKeySize),0)

   If lStatus <> STATUS_SUCCESS Then

      RETURN False

   Else

      RETURN True

   End IF

END FUNCTION

' =====================================================================================
' Generate a Shared Secret Key
' =====================================================================================

PRIVATE FUNCTION cKeyExchange.GenerateSecretKey(BYREF sPartnerPublicKey AS STRING) AS BOOLEAN

DIM hKeyImport         AS BCRYPT_KEY_HANDLE
DIM hSecret            AS BCRYPT_SECRET_HANDLE
DIM nDerivedKeySize    AS ULONG

   sSecretKey = ""

' Import Partner Public key

   lStatus = BCryptImportKeyPair(hAlgorithm,NULL,STRPTR(BCRYPT_ECCPUBLIC_BLOB),VARPTR(hKeyImport),STRPTR(sPartnerPublicKey),LEN(sPartnerPublicKey),0)

   If lStatus <> STATUS_SUCCESS Then

      RETURN False
      EXIT FUNCTION

   End If

' Create the secret

   lStatus = BCryptSecretAgreement(hKey,hKeyImport,VARPTR(hSecret),0)

   If lStatus <> STATUS_SUCCESS Then

      BCryptDestroyKey(hKeyImport)
      RETURN False
      EXIT FUNCTION

   End If

' Once the secret handle has been generated, a symmetric key can be derived.

' Get Derived Key Size

   lStatus = BCryptDeriveKey(hSecret,STRPTR(BCRYPT_KDF_HASH),NULL,NULL,0,VARPTR(nDerivedKeySize),0)

   If lStatus <> STATUS_SUCCESS Then

      BCryptDestroyKey(hKeyImport)
      BCryptDestroySecret(hSecret)
      RETURN False
      EXIT FUNCTION

   End If

   sSecretKey = SPACE(nDerivedKeySize)
   lStatus = BCryptDeriveKey(hSecret,STRPTR(BCRYPT_KDF_HASH),NULL,STRPTR(sSecretKey),nDerivedKeySize,VARPTR(nDerivedKeySize),0)

   BCryptDestroyKey(hKeyImport)
   BCryptDestroySecret(hSecret)

   If lStatus <> STATUS_SUCCESS Then

      RETURN False

   Else

      RETURN True

   End If

END FUNCTION

' =====================================================================================
' Get Shared Secret Key
' =====================================================================================

PRIVATE FUNCTION cKeyExchange.GetSecretKey() AS STRING

   RETURN sSecretKey

End Function

' =====================================================================================
' Get Startup Status
' =====================================================================================

PRIVATE FUNCTION cKeyExchange.GetStartUpStatus() AS BOOLEAN

   RETURN lStatus = STATUS_SUCCESS

End Function

' =====================================================================================
' Get Last Result 
' =====================================================================================

PRIVATE FUNCTION cKeyExchange.GetLastResult() AS DWSTRING

DIM hNT            AS HMODULE
DIM cbLen          AS DWORD
DIM pBuffer        AS WSTRING PTR
DIM dwsMsg         AS DWSTRING


   hNT = LoadLibrary("ntdll.dll")
   If hNT <> 0 Then

      cbLen = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE OR FORMAT_MESSAGE_IGNORE_INSERTS OR FORMAT_MESSAGE_ALLOCATE_BUFFER, _
                             hNT,lStatus,BYVAL MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),cast(LPWSTR, @pBuffer),0,NULL)

      FreeLibrary hNT

      IF cbLen Then

         dwsMsg = *pBuffer
         LocalFree pBuffer

     Else

        dwsMsg = "Unknown"

     End If

   End If

   RETURN HEX(lStatus,8) + " - " + dwsMsg

END FUNCTION
