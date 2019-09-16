#undef  UNICODE
#define UNICODE
#define KEYLENGTH  0x00800000
#define ENCRYPT_BLOCK_SIZE 32
#define ENCRYPT_ALGORITHM CALG_AES_128
#define MS_ENH_RSA_AES_PROV_XP_W L"Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"  

#include <wchar.h>
#include <stdio.h>
#include <windows.h>
#include <strsafe.h>
#include <wincrypt.h>

// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")


// Retrieve and output the system error message for the last-error code
VOID HandleError(LPWSTR lpwsz, DWORD dwError)
{
	HRESULT	hres = NULL;
	LPVOID	lpMsgBuf = NULL;
	LPVOID	lpDisplayBuf = NULL;

	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&lpMsgBuf, 0, NULL);
	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlenW((LPCWSTR)lpMsgBuf) + lstrlenW((LPCWSTR)lpwsz) + 50) * sizeof(WCHAR));

	hres = StringCchPrintfW((LPWSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(WCHAR), L"%s failed with error code %d as follows:\n%s", lpwsz, dwError, lpMsgBuf);
	if (SUCCEEDED(hres))
	{
		wprintf(L"ERROR:\t%s\n", (LPCWSTR)lpDisplayBuf);
	}
	else
	{
		wprintf(L"FATAL ERROR:\tUnable to output error code.\n");
	}

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
}

BOOL IsWindowsXP()
{
	OSVERSIONINFO osvi ={0};
	BOOL bIsWindowsXP = FALSE;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	GetVersionEx(&osvi);

	//wprintf(L"major: %d , minor: %d ", osvi.dwMajorVersion, osvi.dwMinorVersion);

	bIsWindowsXP = (osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 1);

	return bIsWindowsXP;
}

BOOL GetDecryptKey(HANDLE hSourceFile, HCRYPTPROV hCryptProv, HCRYPTKEY* hKey)
{
	DWORD	dwCount = 0;
	BOOL	fReturn = FALSE;
	PBYTE	pbKeyBlob = NULL;  
	DWORD	dwKeyBlobLen = 0;

	// Read the key BLOB length from the source file. 
	fReturn = ReadFile(hSourceFile, &dwKeyBlobLen, sizeof(DWORD), &dwCount, NULL);
	if(fReturn)
	{
		// Allocate a buffer for the key BLOB.
		pbKeyBlob = (PBYTE)GlobalAlloc(GPTR, dwKeyBlobLen);
		if(pbKeyBlob != NULL)
		{
			//-----------------------------------------------------------
			// Read the key BLOB from the source file. 
			fReturn = ReadFile(hSourceFile, pbKeyBlob, dwKeyBlobLen, &dwCount, NULL);
			if(fReturn)
			{
				//----------------------------------------------------------- 
				// Import the key BLOB into the CSP. 
				fReturn = CryptImportKey(hCryptProv, pbKeyBlob, dwKeyBlobLen, 0, 0, hKey);
				if (!fReturn)
				{
					HandleError(L"Error during CryptImportKey!/n", GetLastError());
				}
			}
			else
			{
				HandleError(L"Error reading key BLOB length!\n", GetLastError());
			}
			if(pbKeyBlob)
			{
				GlobalFree(pbKeyBlob);
			}
		}
		else
		{
			HandleError(L"Memory allocation error.\n", E_OUTOFMEMORY); 
			fReturn = FALSE;
		}
	}
	else
	{
		HandleError(L"Error reading key BLOB length!\n", GetLastError());
	}

	return fReturn;
}

BOOL CreateEncryptKey(HANDLE hDestinationFile, HCRYPTPROV hCryptProv, HCRYPTKEY* hKey)
{
	DWORD		dwCount = 0;
	BOOL		fReturn = FALSE;
	PBYTE		pbKeyBlob = NULL; 
	DWORD		dwKeyBlobLen = 0;

	// Create a random session key. 
	fReturn = CryptGenKey(hCryptProv, ENCRYPT_ALGORITHM, KEYLENGTH | CRYPT_EXPORTABLE, hKey);
	if(fReturn)
	{
		wprintf(L"A session key has been created. \n");		
		// If exchange key exist or created successfully
		if (fReturn)
		{
			//-----------------------------------------------------------
			// Determine size of the key BLOB, and allocate memory. 
			fReturn = CryptExportKey(*hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &dwKeyBlobLen);
			if(fReturn)
			{
				wprintf(L"The key BLOB is %d bytes long. \n", dwKeyBlobLen);
				pbKeyBlob = (PBYTE)GlobalAlloc(GPTR, dwKeyBlobLen);
				if(pbKeyBlob != NULL)
				{ 
					wprintf(L"Memory is allocated for the key BLOB. \n");
					//-----------------------------------------------------------
					// Encrypt and export the session key into a simple key BLOB.  
					fReturn = CryptExportKey(*hKey, 0, PLAINTEXTKEYBLOB, 0, pbKeyBlob, &dwKeyBlobLen);
					if(fReturn)
					{
						wprintf(L"The key has been exported. \n");
						//-----------------------------------------------------------
						// Write key BLOB and size of key in Encrypted File
						if(fReturn)
						{
							//-----------------------------------------------------------
							// Write the size of the key BLOB to the destination file. 
							fReturn = WriteFile(hDestinationFile, &dwKeyBlobLen, sizeof(DWORD), &dwCount, NULL);
							if(fReturn)
							{ 
								wprintf(L"A file header has been written. \n");
								//-----------------------------------------------------------
								// Write the key BLOB to the destination file. 
								fReturn = WriteFile(hDestinationFile, pbKeyBlob, dwKeyBlobLen, &dwCount, NULL);
								if(fReturn)
								{ 
									wprintf(L"The key BLOB has been written to the file. \n");
								}
								else
								{
									HandleError(L"Error writing header.\n", GetLastError());
								}
							}
							else
							{
								HandleError(L"Error writing header.\n", GetLastError());
							}
						}
						else
						{
							HandleError(L"Error during CryptDestroyKey.\n", GetLastError());
						}
					} 
					else
					{
						HandleError(L"Error during CryptExportKey!\n", GetLastError());
					} 

					// Free memory.
					if (pbKeyBlob)
					{
						GlobalFree(pbKeyBlob);
					}
				}
				else
				{ 
					HandleError(L"Out of memory. \n", E_OUTOFMEMORY); 
					fReturn = FALSE;
				}
			}
			else
			{  
				HandleError(L"Error computing BLOB length! \n", GetLastError());
			}
		}

	} 
	else
	{
		HandleError(L"Error during CryptGenKey. \n", GetLastError()); 
	}

	return fReturn;
}

BOOL DeriveKeyFromPassword(LPWSTR lpwszPassword, HCRYPTPROV hCryptProv, HCRYPTKEY* hKey)
{ 
	HCRYPTHASH	hHash = NULL;
	BOOL		fReturn = FALSE;

	//-----------------------------------------------------------
	// Create a hash object. 
	fReturn = CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
	if(fReturn)
	{
		wprintf(L"A hash object has been created. \n");
		//-----------------------------------------------------------
		// Hash the password. 
		fReturn = CryptHashData(hHash, (PBYTE)lpwszPassword, lstrlenW(lpwszPassword) * sizeof(WCHAR), 0);
		if(fReturn)
		{
			wprintf(L"The password has been added to the hash. \n");
			//-----------------------------------------------------------
			// Derive a session key from the hash object. 
			fReturn = CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, hKey);
			if(fReturn)
			{
				wprintf(L"An encryption key is derived from the password hash. \n"); 
			}
			else
			{
				HandleError(L"Error during CryptDeriveKey!\n", GetLastError());
			}
		}
		else
		{
			HandleError(L"Error during CryptHashData. \n", GetLastError());
		}
	}
	else
	{ 
		HandleError(L"Error during CryptCreateHash!\n", GetLastError());
	}

	//-----------------------------------------------------------
	// Release the hash object. 
	if(hHash) 
	{
		if(!(CryptDestroyHash(hHash)))
		{
			HandleError(L"Error during CryptDestroyHash.\n", GetLastError()); 
		}

		hHash = NULL;
	}

	return fReturn;
}

BOOL EncryptDecryptFile(HANDLE hSourceFile, HANDLE hDestinationFile, HCRYPTKEY hKey, DWORD dwBufferLen, DWORD dwBlockLen, BOOL fIsDecrypt)
{
	DWORD	dwCount = 0;
	BOOL	fEOF = FALSE; 
	BOOL	fReturn = FALSE;
	PBYTE	pbBuffer = NULL;

	//---------------------------------------------------------------
	// Allocate memory. 
	pbBuffer = (PBYTE)GlobalAlloc(GPTR, dwBufferLen);
	if(pbBuffer)
	{
		wprintf(L"Memory has been allocated for the buffer. \n");
		//---------------------------------------------------------------
		// In a do loop, encrypt the source file, 
		// and write to the source file. 
		do 
		{ 
			//-----------------------------------------------------------
			// Read up to dwBlockLen bytes from the source file. 
			fReturn = ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL);
			if(fReturn)
			{
				if(dwCount < dwBlockLen)
				{
					fEOF = TRUE;
				}

				if (fIsDecrypt)
				{
					//-----------------------------------------------------------
					// Decrypt data.
					fReturn = CryptDecrypt(hKey, 0, fEOF, 0, pbBuffer, &dwCount);
					if(!fReturn)
					{
						HandleError(L"Error during CryptDecrypt. \n", GetLastError());
						break;
					}
				}
				else
				{
					//-----------------------------------------------------------
					// Encrypt data.
					fReturn = CryptEncrypt(hKey, NULL, fEOF, 0, pbBuffer, &dwCount, dwBufferLen);
					if(!fReturn)
					{ 
						HandleError(L"Error during CryptEncrypt. \n", GetLastError()); 
						break;
					} 
				}

				//-----------------------------------------------------------
				// Write the encrypted/decrypted data to the destination file. 
				fReturn = WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL);
				if(!fReturn)
				{ 
					HandleError(L"Error writing ciphertext.\n", GetLastError());
					break;
				}
			}
			else
			{
				HandleError(L"Error reading plainText!\n", GetLastError());
				break;
			}
			//-----------------------------------------------------------
			// End the do loop when the last block of the source file 
			// has been read, encrypted, and written to the destination 
			// file.
		} while(!fEOF);

		//---------------------------------------------------------------
		// Free memory. 
		if(pbBuffer) 
		{
			GlobalFree(pbBuffer); 
		}
	}
	else
	{ 
		HandleError(L"Out of memory. \n", E_OUTOFMEMORY); 
		fReturn = FALSE;
	}

	return fReturn;
}

//-------------------------------------------------------------------
// Code for the function EncryptDecryptAES called by main.
//-------------------------------------------------------------------
// Parameters passed are:
//  lpwszSourceFile, the name of the input, a file.
//  lpwszDestinationFile, the name of the output, an encrypted/decrypted file to be  created.
//  lpwszPassword, either NULL if a password is not to be used or the 
//    string that is the password.
//  fIsDecrypt, if the file is Encrypting must set to FALSE, else TRUE if is Decrypting
BOOL EncryptDecryptAES(LPWSTR lpwszSourceFile, LPWSTR lpwszDestinationFile, LPWSTR lpwszPassword, BOOL fIsDecrypt)
{ 
	//---------------------------------------------------------------
	// Declare and initialize local variables.
	DWORD		dwCount = 0;  
	HCRYPTKEY	hKey = NULL; 
	DWORD		dwBlockLen = 0; 
	DWORD		dwBufferLen = 0; 
	BOOL		fReturn = FALSE; 
	HCRYPTPROV	hCryptProv = NULL; 
	HANDLE		hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE		hDestinationFile = INVALID_HANDLE_VALUE; 

	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFileW(lpwszSourceFile, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_SYSTEM, NULL);
	if(hSourceFile != INVALID_HANDLE_VALUE)
	{
		wprintf(L"The source file, %s, is open. \n", lpwszSourceFile);
		//---------------------------------------------------------------
		// Open the destination file. 
		hDestinationFile = CreateFileW(lpwszDestinationFile, FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hDestinationFile != INVALID_HANDLE_VALUE)
		{
			wprintf(L"The destination file, %s, is open. \n", lpwszDestinationFile);
			//---------------------------------------------------------------
			// Get the handle to the default provider. 
			if (IsWindowsXP())
			{
				fReturn = CryptAcquireContextW(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV_XP_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
			}
			else
			{
				fReturn = CryptAcquireContextW(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
			}
			if(fReturn)
			{
				wprintf(L"A cryptographic provider has been acquired. \n");
				//---------------------------------------------------------------
				// Create the session key.
				if(!lpwszPassword || !lpwszPassword[0]) 
				{ 
					//-----------------------------------------------------------
					// No password was passed.
					// Encrypt the file with a random session key, and write the 
					// key to a file. 
					if(fIsDecrypt)
					{
						//-----------------------------------------------------------
						// Decrypt the file with the saved session key. 
						fReturn = GetDecryptKey(hSourceFile, hCryptProv, &hKey);
					}
					else
					{
						//-----------------------------------------------------------
						// Is Encryption 
						// Create a session key and save it to file.
						fReturn = CreateEncryptKey(hDestinationFile, hCryptProv, &hKey);
					}
				} 
				else 
				{ 
					//-----------------------------------------------------------
					// The file will be encrypted/decrypted with a session key derived 
					// from a password.
					// The session key will be recreated when the file is 
					// decrypted only if the password used to create the key is 
					// available. 
					fReturn = DeriveKeyFromPassword(lpwszPassword, hCryptProv, &hKey);
				} 
			}
			else
			{
				HandleError(L"Error during CryptAcquireContext!\n", GetLastError());
			}
		}
		else
		{
			HandleError(L"Error opening destination file!\n", GetLastError());
			fReturn = FALSE;
		}
	}
	else
	{ 
		HandleError(L"Error opening source file!\n", GetLastError());
		fReturn = FALSE;
	} 
	if (fReturn)
	{
		//---------------------------------------------------------------
		// The session key is now ready. If it is not a key derived from 
		// a  password, the session key encrypted with the private key 
		// has been written to the destination file.

		//---------------------------------------------------------------
		// Determine the number of bytes to encrypt at a time. 
		// This must be a multiple of ENCRYPT_BLOCK_SIZE.
		// ENCRYPT_BLOCK_SIZE is set by a #define statement.
		dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 

		if(fIsDecrypt)
		{
			dwBufferLen = dwBlockLen; 
		}
		else
		{
			//---------------------------------------------------------------
			// Determine the block size. If a block cipher is used, 
			// it must have room for an extra block. 
			if(ENCRYPT_BLOCK_SIZE > 1) 
			{
				dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE; 
			}
			else 
			{
				dwBufferLen = dwBlockLen; 
			}
		}

		// Encrypt file and save it
		EncryptDecryptFile(hSourceFile, hDestinationFile, hKey, dwBufferLen, dwBlockLen, fIsDecrypt);
		
	}
	//---------------------------------------------------------------
	// Close files.
	if(hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if(hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if(hKey)
	{
		if(!(CryptDestroyKey(hKey)))
		{
			HandleError(L"Error during CryptDestroyKey!\n", GetLastError());
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if(hCryptProv)
	{
		if(!(CryptReleaseContext(hCryptProv, 0)))
		{
			HandleError(L"Error during CryptReleaseContext!\n", GetLastError());
		}
	}

	return fReturn; 
} 


INT wmain(INT argc, WCHAR* argv[])
{
	BOOL  fReturn = FALSE;
	WCHAR lpwszSource[MAX_PATH] = {0}; 
	WCHAR lpwszPassword[MAX_PATH] = {0};
	WCHAR lpwszDestination[MAX_PATH] = {0}; 
	WCHAR lpwszDecryptedDestination[MAX_PATH] = {0}; 

	if (argc >= 3)
	{
		StringCchCopyW(lpwszSource, MAX_PATH, argv[1]);
		StringCchCopyW(lpwszDestination, MAX_PATH, argv[2]);
		
		if(argc >= 4)
		{
			StringCchCopyW(lpwszPassword, MAX_PATH, argv[3]);
		}
		else
		{
			StringCchCopyW(lpwszPassword, MAX_PATH, L"");
		}

		if (argc >= 5)
		{
			StringCchCopyW(lpwszDecryptedDestination, MAX_PATH, argv[4]);
		}
		else
		{
			StringCchCopyW(lpwszDecryptedDestination, MAX_PATH, L".\\DecryptedFile");
		}

		//---------------------------------------------------------------
		// Call EncryptFile to do the actual encryption.
		wprintf(L"\n\n--------------------------------------------------------------------\nEncrypting\n\n");

		fReturn = EncryptDecryptAES(lpwszSource, lpwszDestination, lpwszPassword, FALSE);
		if(fReturn)
		{
			wprintf(L"Encryption of the file %s was successful. \n", lpwszSource);
			wprintf(L"The encrypted data is in file %s.\n", lpwszDestination);
		}
		else
		{
			wprintf(L"Error encrypting file with code %d !\n", GetLastError()); 
		}

		// Call EncryptFile to do the Decryption.
		wprintf(L"\n\n--------------------------------------------------------------------\nDecrypting\n\n");
		
		fReturn = EncryptDecryptAES(lpwszDestination, lpwszDecryptedDestination, lpwszPassword, TRUE);
		if(fReturn)
		{
			wprintf(L"Decryption of the file %s was successful. \n", lpwszDestination);
			wprintf(L"The decrypted data is in file %s.\n\n", lpwszDecryptedDestination);
		}
		else
		{
			wprintf(L"Error decrypting file with code %d !\n", GetLastError()); 
		}
	}
	else
	{
		wprintf(L"Usage: <Encryption.exe> <source file> <destination file> [<password>] [<decrypted file destination>]\n");
	}

	return 0;
}