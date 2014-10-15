/*
 * MifareTest.cpp - Example using PC/SC to read and write from Mifare card
 * HID Global http://www.hidglobal.com
 */

#include <Windows.h>
#include <winscard.h>
#include <stdio.h>

#define MAX_APDU_SIZE 255

LONG main()
{
	LONG         lRet = 0;
	SCARDCONTEXT hContext = 0;
	SCARDHANDLE  hCard = 0;
	DWORD        dwAP = 0;
	BYTE         pbSend[MAX_APDU_SIZE];
	BYTE         pbRecv[MAX_APDU_SIZE];
	DWORD        cbSend = 0;
	DWORD        cbRecv = 0;

	if ((lRet = SCardEstablishContext(SCARD_SCOPE_USER, 0, 0, &hContext)) != SCARD_S_SUCCESS)
		return lRet;

	if ((lRet = SCardConnect(hContext, L"OMNIKEY CardMan 5x21-CL 0", SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &hCard, &dwAP)) != SCARD_S_SUCCESS)
	{
		printf("Error connecting to the card (0x%08X)\n", lRet);
		return lRet;
	}

	// Get Data - Read card serial number
	memcpy(pbSend, "\xFF\xCA\x00\x00\x00", 5);
	cbSend = 5;
	cbRecv = MAX_APDU_SIZE;
	if ((lRet = SCardTransmit(hCard, SCARD_PCI_T1, pbSend, cbSend, NULL, pbRecv, &cbRecv)) != SCARD_S_SUCCESS)
		return lRet;

	printf("Card UID: ");
	for (DWORD i = 0; i < cbRecv - 2; i++)
	{
		printf("%02X", pbRecv[i]);
		if (i == cbRecv - 3) printf("\n");
	}

	// Load Key - Default Mifare FF key, P1=0x20 means in non volatile reader memory, P2-key number
	memcpy(pbSend, "\xFF\x82\x20\x00\x06\xFF\xFF\xFF\xFF\xFF\xFF", 11);
	cbSend = 11;
	cbRecv = MAX_APDU_SIZE;
	if ((lRet = SCardTransmit(hCard, SCARD_PCI_T1, pbSend, cbSend, NULL, pbRecv, &cbRecv)) != SCARD_S_SUCCESS)
		return lRet;

	// General Authenticate - Read the documents mentioned in the README :)
	memcpy(pbSend, "\xFF\x86\x00\x00\x05\x01\x00\x01\x60\x00", 10);
	cbSend = 10;
	cbRecv = MAX_APDU_SIZE;
	if ((lRet = SCardTransmit(hCard, SCARD_PCI_T1, pbSend, cbSend, NULL, pbRecv, &cbRecv)) != SCARD_S_SUCCESS)
		return lRet;

	// Update Binary
	memcpy(pbSend, "\xFF\xD6\x00\x01\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 21);
	cbSend = 21;
	cbRecv = MAX_APDU_SIZE;
	if ((lRet = SCardTransmit(hCard, SCARD_PCI_T1, pbSend, cbSend, NULL, pbRecv, &cbRecv)) != SCARD_S_SUCCESS)
		return lRet;

	// Read Binary
	memcpy(pbSend, "\xFF\xB0\x00\x01\x00", 5);
	cbSend = 5;
	cbRecv = MAX_APDU_SIZE;
	if ((lRet = SCardTransmit(hCard, SCARD_PCI_T1, pbSend, cbSend, NULL, pbRecv, &cbRecv)) != SCARD_S_SUCCESS)
		return lRet;

	printf("Block 01: ");
	for (DWORD i = 0; i < cbRecv - 2; i++)
	{
		printf("%02X", pbRecv[i]);
		if (i == cbRecv - 3) printf("\n");
	}

	lRet = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
	lRet = SCardReleaseContext(hContext);
	return lRet;
}