#include "socket_srv.h"
#include "thread_shared.h"

#include "crc64.h"
#include "file_loader.h"
#include "log.h"
#include "program.h"

void *connection_handler(void *socket_desc)
{
	debugLog("\"method\":\"connection_handler\",\"message\":\"inc message\"");

	int sock = *(int*)socket_desc;
	int read_size;
	char client_message[4096];
	struct PrimeHeader primeHeader;
	struct MessageHeader messageHeader;
	int bytesRead = 0;

	char *bufferPtr = (char *)&primeHeader;
	while ((read_size = recv(sock, client_message, sizeof(struct PrimeHeader), 0)) > 0)
	{
		bytesRead += read_size;
		memcpy(bufferPtr, client_message, read_size);
		bufferPtr += read_size;
		if (read_size == -1 || read_size == 0 || bytesRead >= sizeof(struct PrimeHeader))
			break;
	}

	if (bytesRead == 0)
	{
		goto flush;
	}

	uint64_t crc = crc64(0, (const char *)&primeHeader, sizeof(struct PrimeHeader) - sizeof(uint64_t));
	sprintf(client_message, (primeHeader.headercrc == crc) ? "1" : "0");
	if (primeHeader.headercrc != crc)
	{
		goto flush;
	}

	for (int i = 0; i < primeHeader.buffercount; i++)
	{
		bufferPtr = (char *)&messageHeader;
		bytesRead = 0;
		while ((read_size = recv(sock, client_message, 16, 0)) > 0)
		{
			bytesRead += read_size;
			memcpy(bufferPtr, client_message, read_size);
			bufferPtr += read_size;
			if (read_size == -1 || read_size == 0 || bytesRead >= 16)
				break;
		}
		if (bytesRead == 0)
		{
			goto flush;
		}

		char *bufferMsg = (char *)calloc(1, messageHeader.length + 1);
		if (messageHeader.length == 0)
		{
			debugLog("\"method\":\"connection_handler\",\"message\":\"empty message\"");
			sprintf(client_message, "1");
		}
		else
		{
			if (bufferMsg == NULL)
			{
				debugLog("\"method\":\"connection_handler\",\"message\":\"not enough memory to create message buffer\"");
				return (void *)-1;
			}

			char *bufferMsgPtr = bufferMsg;
			bytesRead = 0;
			while ((read_size = recv(sock, client_message, 4096, 0)) > 0)
			{
				bytesRead += read_size;
				memcpy(bufferMsgPtr, client_message, read_size);
				bufferMsgPtr += read_size;

				if (read_size == -1 || read_size == 0 || bytesRead >= messageHeader.length)
					break;
			}
			crc = crc64(0, (const char *)bufferMsg, messageHeader.length);
			sprintf(client_message, (messageHeader.msgcrc == crc) ? "1" : "0");
			if (messageHeader.msgcrc != crc)
			{
				goto flush;
			}
		}

		switch (primeHeader.action)
		{
		case bufferType_loadfile:
		{
			char *file = (char *)bufferMsg;
			//load_file(file);

			if (bufferMsg)
			{
				free(bufferMsg);
				bufferMsg = NULL;
			}
			break;
		}
		case bufferType_pushLmdb:
		{
			char *file = (char *)bufferMsg;
			load_lmdb(file);

			if (bufferMsg)
			{
				free(bufferMsg);
				bufferMsg = NULL;
			}
			break;
		}
		}
	}

flush:

	close(sock);
	free(socket_desc);

	return 0;
}

void* socket_server(void *arg)
{
	int socket_desc, new_socket, c, *new_sock;
	struct sockaddr_in server, client;

	//Create socket
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_desc == -1)
	{
		debugLog("\"method\":\"socket_server\",\"message\":\"Could not create socket\"");
	}

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	//server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_addr.s_addr = inet_addr("0.0.0.0");
	for (int port = 8880; port < 9048; port++)
	{
		server.sin_port = htons(port);
		char message[255] = {};
		//Bind
		if (bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
		{
			debugLog("\"method\":\"socket_server\",\"message\":\"bind failed on port %d\"", port);
			if (port == 9048)
			{
				return (void*)-1;
			}

			continue;
		}
		debugLog("\"method\":\"socket_server\",\"message\":\"bind succeeded on port %d\"", port);
		break;
	}

	//Listen
	listen(socket_desc, 3);

	//Accept and incoming connection
	debugLog("\"method\":\"socket_server\",\"message\":\"waiting for incoming connections\"");
	c = sizeof(struct sockaddr_in);
	while ((new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c)))
	{
		//logDebug("connection accepted");

		pthread_t sniffer_thread;
		new_sock = malloc(1);
		*new_sock = new_socket;

		if (pthread_create(&sniffer_thread, NULL, connection_handler, (void*)new_sock) < 0)
		{
			debugLog("\"method\":\"socket_server\",\"message\":\"could not create thread\"");
			return (void*)-1;
		}

		pthread_join(sniffer_thread, NULL);
		//logDebug("handler assigned");
	}

	if (new_socket < 0)
	{
		debugLog("\"method\":\"socket_server\",\"message\":\"accept failed\"");
		return (void*)-1;
	}

	return 0;
}