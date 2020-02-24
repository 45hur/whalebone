
#include "log.h"

#include <pthread.h>

#include "program.h"
#include "socket_srv.h"

int logging = 1;

void debugLog(const char *format, ...)
{
#ifdef DEBUG
	va_list dbgargptr;
	va_start(dbgargptr, format);
	vfprintf(stdout, format, dbgargptr);
	va_end(dbgargptr);
#endif

	if (getenv("LOG_DEBUG") == NULL)
		return;

	char text[LOG_MESSAGE_MAX - 256] = { 0 };
	va_list argptr;
	va_start(argptr, format);
	vsprintf(text, format, argptr);
	va_end(argptr);

	char message[LOG_MESSAGE_MAX] = { 0 };
	char timebuf[30] = { 0 };
	//time_t rawtime;
	//struct tm * timeinfo;
	//
	//time(&rawtime);
	//timeinfo = localtime(&rawtime);
	//strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	//sprintf(message, "{\"timestamp\":\"%s\",\"tid\":\"%lx\",%s}\n", timebuf, pthread_self(), text);
	sprintf(message, "{%s}\n", text);

	send_message(log_debug, message);
}

void fileLog(const char *format, ...)
{
	if (getenv("LOG_THREAT") == NULL)
		return;

	char text[LOG_MESSAGE_MAX - 256] = { 0 };
	va_list argptr;
	va_start(argptr, format);
	vsprintf(text, format, argptr);
	va_end(argptr);

	FILE *fh = 0;
	char message[LOG_MESSAGE_MAX] = { 0 };
	char timebuf[30] = { 0 };
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);

	send_message(log_audit, message);
}

void contentLog(const char *format, ...)
{
	if (getenv("LOG_CONTENT") == NULL)
		return;

	char text[LOG_MESSAGE_MAX - 256] = { 0 };
	va_list argptr;
	va_start(argptr, format);
	vsprintf(text, format, argptr);
	va_end(argptr);

	FILE *fh = 0;
	char message[LOG_MESSAGE_MAX] = { 0 };
	char timebuf[30] = { 0 };
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);

	send_message(log_content, message);
}

void logEnqueue(int logtype, const char *message)
{
	if (logBuffer->index < logBuffer->capacity && logBuffer->buffer[logBuffer->index].type == log_empty_slot)
	{
		strcpy(logBuffer->buffer[logBuffer->index].message, message);
		logBuffer->buffer[logBuffer->index].type = logtype;
		logBuffer->index++;
	}

	if (logBuffer->index == logBuffer->capacity && logBuffer->buffer[0].type == log_empty_slot)
		logBuffer->index = 0;
}

void *log_proc(void *arg)
{
	while(logging == 1)
	{
		usleep(1000000);
/*
		pthread_mutex_lock(&thread_shared->mutex);
		FILE *fh1 = fopen(C_MOD_LOGDEBUG, "at");
		FILE *fh2 = fopen(C_MOD_LOGAUDIT, "at");
		FILE *fh3 = fopen(C_MOD_LOGFILE, "at");
		if (!fh1) fh1 = fopen(C_MOD_LOGDEBUG, "wt");
		if (!fh2) fh2 = fopen(C_MOD_LOGAUDIT, "wt");
		if (!fh3) fh3 = fopen(C_MOD_LOGFILE, "wt");
		
		if (!fh1 || !fh2 || !fh3)
		{
			if (fh1) fclose(fh1);
			if (fh2) fclose(fh2);
			if (fh3) fclose(fh3);

			fprintf(stderr, "Unable open log file for writing.");

			pthread_mutex_unlock(&thread_shared->mutex);
			continue;
		}
*/
		for (int i = 0; i < logBuffer->capacity; i++)
		{
			if (logBuffer->buffer[i].type != log_empty_slot)
			{
				switch (logBuffer->buffer[i].type)
				{
					case log_debug:
						fprintf(stdout, "%s", logBuffer->buffer[i].message);
						send_message(logBuffer->buffer[i].type, logBuffer->buffer[i].message);
						//fputs(logBuffer->buffer[i].message, fh1);
						break;
					case log_audit:
						//fputs(logBuffer->buffer[i].message, fh2);
						send_message(logBuffer->buffer[i].type, logBuffer->buffer[i].message);
						break;
					case log_content:
						//fputs(logBuffer->buffer[i].message, fh3);
						send_message(logBuffer->buffer[i].type, logBuffer->buffer[i].message);
						break;
					default:
						break;
				}
				logBuffer->buffer[i].type = log_empty_slot;
			}
		}
/*
		pthread_mutex_unlock(&thread_shared->mutex);
		
		fflush(fh1);
		fclose(fh1);
		fflush(fh2);
		fclose(fh2);
		fflush(fh3);
		fclose(fh3);
*/
	}
}