/*
=========================================================================

    bblDiffTool:
    utility for creating IDA Pro idc script base on execution flow stored in database.

    Usage:
		bblDiffTool <option> <optiong_args>
		-gen  <database_name> <table_name> <idc_file_name> <color_number>
		-diff <database_name> <fisrt_table_name> <second_table_name> <idc_file_name> <color_number>
		-diffex <database_name> <fisrt_table_name> <second_table_name> <idc_file_name> <color_number_1> <color_number_2>
	Example:
		-gen  test.db test_1 test_1.idc 16711680
		-diff test.db test_1 test_2 test_2.idc 16711680
		-diffex test.db test_1 test_2 test_3.idc 16711680 16750899
    
	Developed by:

    Shahriyar Jalayeri, Iran Honeynet Chapter
    Shahriyar.j <at > gmail <dot> com
    http://www.irhoneynet.org/

=========================================================================
*/
#include "stdafx.h"
#include <stdlib.h>
#include "sqlite\sqlite3.h"
#pragma comment(lib,"sqlite3.lib")

char idc_start[] = 	"#include <idc.idc>\n\
static assign_color(bbl_start, bbl_end, color)\n\
{\n\
	auto i;\n\
	for ( i = bbl_start; i < bbl_end; i++ )\n\
	{\n\
		SetColor(i, CIC_ITEM, color); }\n\
	}\n\n\
static main()\n\
{\n\
	auto color;\n\
	auto base;\n\
	base  = MinEA() - 0x1000;\n";
char idc_end[] = "}";

bool 
	initDatabase(	const char *szDatabaseName,	
					char *szTableName, 			
					sqlite3 **db, 				
					bool bCreate);			
bool
	genrateTableIdc(	char *szTableName,
						char *szIdcFileName,
						int color,
						sqlite3 *db);

bool
	genrateDiffTableIdc(	char *szFirstTableName,
							char *szSecondTableName,
							char *szIdcFileName,
							int color,
							sqlite3 *db);
bool
	genrateDiffTableIdcEx(	char *szFirstTableName,
							char *szSecondTableName,
							char *szIdcFileName,
							int color_1,
							int color_2,
							sqlite3 *db);

int main(int argc, char* argv[])
{
	sqlite3 *db;

	if ( argc < 4 )
	{
		printf("usage:\n");
		printf(" -gen  <database name> <table name> <idc file name> <color number>\n");
		printf(" -diff <database name> <fisrt table name> <second table name> <idc file name> <color number>\n");
		printf(" -diffex <database name> <fisrt table name> <second table name> <idc file name> <color number 1> <color number 2>\n");
		printf("ex:\n");
		printf(" -gen  test.db test_1 test_1.idc 16711680\n");
		printf(" -diff test.db test_1 test_2 test_2.idc 16711680\n");
		printf(" -diffex test.db test_1 test_2 test_3.idc 16711680 16750899\n");
		return 0;
	}

	if ( !strcmp( argv[1], "-gen" ) )
	{
		if ( !initDatabase( argv[2], NULL, &db, false) )
			return -1;
		genrateTableIdc( argv[3], argv[4] , atoi(argv[5]), db);
	}
	else if ( !strcmp( argv[1], "-diff" ) )
	{
		if ( !initDatabase( argv[2], NULL, &db, false) )
			return -1;
		genrateDiffTableIdc( argv[3], argv[4], argv[5], atoi(argv[6]), db);
	}
	else if ( !strcmp( argv[1], "-diffex" ) )
	{
		if ( !initDatabase( argv[2], NULL, &db, false) )
			return -1;
		genrateDiffTableIdcEx( argv[3], argv[4], argv[5], atoi(argv[6]), atoi(argv[7]), db);
	}
	return 0;
}

bool 
	initDatabase(	const char *szDatabaseName,
					char *szTableName, 			
					sqlite3 **db, 				
					bool bCreate)				
{
	char sqlCreateTable[256] = {0};
	char *szError;
	int commandResult;
	
	printf("Openning \"%s\" database...\n", szDatabaseName);

	// open db handle
	commandResult = sqlite3_open(szDatabaseName, db);
	if ( commandResult )
	{
		printf("[!] Error opening SQLite3 database [ initDatabase() ]: %s\n", sqlite3_errmsg(*db));
		sqlite3_close(*db);
		return false;
	}
	
	return true;
}

bool
	genrateTableIdc(	char *szTableName,
						char *szIdcFileName,
						int color,
						sqlite3 *db)
{
	FILE *bbl_idc;
	char sqlSelect[256];
	char *szError;
	char **results = NULL;
	int commandResult, rows, columns, fcolor;

	if ( szTableName == NULL || strlen(szTableName) > 50 )
	{
		printf("[!] Error table name too big or NULL.\n");
		printf("[!] genrateTableIdc() faild.\n");
		return false;
	}

	fcolor  = _byteswap_ulong(color); // GCC : __builtin_bswap32
	fcolor  = (fcolor << 24) | (fcolor >> 40);
	fcolor &= 0x00FFFFFF;

	printf("Generating \"%s\" IDA idc script base on \"%s\" table...\n", szIdcFileName, szTableName);
	sprintf(sqlSelect, "SELECT bblStart,bblEnd FROM %s;", szTableName);

	commandResult = sqlite3_get_table(	db, 
										sqlSelect, 
										&results, 
										&rows, 
										&columns, 
										&szError);
	if (commandResult)
	{
		printf("[!] Error executing SQLite3 query: %s\n" ,sqlite3_errmsg(db));
		sqlite3_free(szError);
	}else
	{
		bbl_idc = fopen(szIdcFileName, "w");
		fprintf(bbl_idc, idc_start );
		fprintf(bbl_idc, "\tcolor = 0x%p;\n", fcolor);

		for ( int i = 1 ; i < columns*rows; i += 2)
			fprintf(bbl_idc ,"\tassign_color(base + 0x%p, base + 0x%p, color);\n", atoi(results[i+1]), atoi(results[i+2]));

		fprintf(bbl_idc, idc_end );
		fflush(bbl_idc);
		fclose(bbl_idc);
	}
	
	printf("IDA idc script \"%s\" generated successfully.\n", szIdcFileName);
	sqlite3_free_table(results);
	sqlite3_close(db);
	return true;
}

bool
	genrateDiffTableIdc(	char *szFirstTableName,
							char *szSecondTableName,
							char *szIdcFileName,
							int color,
							sqlite3 *db)
{
	FILE *bbl_idc;
	char sqlSelect[256];
	char *szError;
	char **results = NULL;
	int commandResult, rows, columns, fcolor;

	if ( (szFirstTableName  == NULL || strlen(szFirstTableName)  > 50) ||
		 (szSecondTableName == NULL || strlen(szSecondTableName) > 50) )
	{
		printf("[!] Error table name too big or NULL.\n");
		printf("[!] genrateDiffTableIdc() faild.\n");
		return false;
	}

	fcolor  = _byteswap_ulong(color); // GCC : __builtin_bswap32
	fcolor  = (fcolor << 24) | (fcolor >> 40);
	fcolor &= 0x00FFFFFF;

	printf("Generating \"%s\" IDA idc script base on difference of \"%s\" and \"%s\" tables...\n", szIdcFileName, szSecondTableName, szFirstTableName);
	sprintf(sqlSelect, "SELECT bblStart,bblEnd FROM %s WHERE bblStart NOT IN ( SELECT bblStart FROM %s );", szSecondTableName, szFirstTableName);

	commandResult = sqlite3_get_table(	db, 
										sqlSelect, 
										&results, 
										&rows, 
										&columns, 
										&szError);
	if (commandResult)
	{
		printf("[!] Error executing SQLite3 query: %s\n" ,sqlite3_errmsg(db));
		sqlite3_free(szError);
	}else
	{
		bbl_idc = fopen(szIdcFileName, "w");
		fprintf(bbl_idc, idc_start );
		fprintf(bbl_idc, "\tcolor = 0x%p;\n", fcolor);

		for ( int i = 1 ; i < columns*rows; i += 2)
			fprintf(bbl_idc,"\tassign_color(base + 0x%p, base + 0x%p, color);\n", atoi(results[i+1]), atoi(results[i+2]));

		fprintf(bbl_idc, idc_end );
		fflush(bbl_idc);
		fclose(bbl_idc);
	}

	printf("IDA idc script \"%s\" generated successfully.\n", szIdcFileName);
	sqlite3_free_table(results);
	sqlite3_close(db);
	return true;
}


bool
	genrateDiffTableIdcEx(	char *szFirstTableName,
							char *szSecondTableName,
							char *szIdcFileName,
							int color_1,
							int color_2,
							sqlite3 *db)
{
	FILE *bbl_idc;
	char sqlSelect[256];
	char *szError;
	char **results = NULL;
	int commandResult, rows, columns, fcolor;

	if ( (szFirstTableName  == NULL || strlen(szFirstTableName)  > 50) ||
		 (szSecondTableName == NULL || strlen(szSecondTableName) > 50) )
	{
		printf("[!] Error table name too big or NULL.\n");
		printf("[!] genrateDiffTableIdc() faild.\n");
		return false;
	}

	printf("Generating \"%s\" IDA idc script base on difference of \"%s\" and \"%s\" tables...\n", szIdcFileName, szSecondTableName, szFirstTableName);

	fcolor  = _byteswap_ulong(color_1); // GCC : __builtin_bswap32
	fcolor  = (fcolor << 24) | (fcolor >> 40);
	fcolor &= 0x00FFFFFF;

	sprintf(sqlSelect, "SELECT bblStart,bblEnd FROM %s WHERE bblStart NOT IN ( SELECT bblStart FROM %s );", szSecondTableName, szFirstTableName);
	commandResult = sqlite3_get_table(	db, 
										sqlSelect, 
										&results, 
										&rows, 
										&columns, 
										&szError);
	if (commandResult)
	{
		printf("[!] Error executing SQLite3 query: %s\n" ,sqlite3_errmsg(db));
		sqlite3_free(szError);
	}else
	{
		bbl_idc = fopen(szIdcFileName, "w");
		fprintf(bbl_idc, idc_start );
		fprintf(bbl_idc, "\tcolor = 0x%p;\n", fcolor);

		for ( int i = 1 ; i < columns*rows; i += 2)
			fprintf(bbl_idc,"\tassign_color(base + 0x%p, base + 0x%p, color);\n", atoi(results[i+1]), atoi(results[i+2]));
	}

	fcolor  = _byteswap_ulong(color_2); // GCC : __builtin_bswap32
	fcolor  = (fcolor << 24) | (fcolor >> 40);
	fcolor &= 0x00FFFFFF;

	printf("Generating \"%s\" IDA idc script base on difference of \"%s\" and \"%s\" tables...\n", szIdcFileName, szSecondTableName, szFirstTableName);
	sprintf(sqlSelect, "SELECT bblStart,bblEnd FROM %s WHERE bblStart IN ( SELECT bblStart FROM %s );", szSecondTableName, szFirstTableName);

	commandResult = sqlite3_get_table(	db, 
										sqlSelect, 
										&results, 
										&rows, 
										&columns, 
										&szError);
	if (commandResult)
	{
		printf("[!] Error executing SQLite3 query: %s\n" ,sqlite3_errmsg(db));
		sqlite3_free(szError);
	}else
	{
		fprintf(bbl_idc, "\tcolor = 0x%p;\n", fcolor);

		for ( int i = 1 ; i < columns*rows; i += 2)
			fprintf(bbl_idc,"\tassign_color(base + 0x%p, base + 0x%p, color);\n", atoi(results[i+1]), atoi(results[i+2]));

		fprintf(bbl_idc, idc_end );
		fflush(bbl_idc);
		fclose(bbl_idc);
	}

	printf("IDA idc script \"%s\" generated successfully.\n", szIdcFileName);
	sqlite3_free_table(results);
	sqlite3_close(db);
	return true;
}

