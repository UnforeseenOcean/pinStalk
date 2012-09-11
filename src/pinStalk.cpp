/*
=========================================================================

    pinStalk code coverage analysis tool
    PIN toolkit instrumentation module that log the execution flow (basic blocks).

    Usage:
        pin.exe -t pinStalk.dll -db <database_name> -t <table_name> -m <module_name> -- <program_to_run>
		-db : database name you want to create or filled with new data
		-t  : table name in the database
		-m  : module you want to trace its execution
		
    Example :
		pin.exe -t pinStalk.dll -db calc.db -t calc_1st_run -m calc.exe -- calc
    
	Developed by:

    Shahriyar Jalayeri, Iran Honeynet Chapter
    Shahriyar.j <at > gmail <dot> com
    http://www.irhoneynet.org/

=========================================================================
*/

#include <stdlib.h>
#include <stdio.h>
#include <cstdio>
#include <iostream>
#include <fstream>
#include "sqlite/sqlite3.h"
#include "pin.H"
#define TRAN 10000

char dName[256];
char tName[256];
char mName[256];
sqlite3 *globaldb;
ADDRINT lowA,highA;
UINT32 tCount = 0;
FILE *bbl_info, *bbl_idc, *general_info;

bool next_bbl_reached = false;
bool moduleAddress = false;


KNOB<string> KnobOutputDatabase(
    KNOB_MODE_WRITEONCE, 
    "pintool", "db", "coverage.db", 
    "specify database name to store coverage data"
);

KNOB<string> KnobDatabaseTable(
    KNOB_MODE_WRITEONCE, 
    "pintool", "t", "cov_1", 
    "specify table name to store coverage data"
);

KNOB<string> KnobModuleName(
    KNOB_MODE_WRITEONCE, 
    "pintool", "m", "NoModule",
    "specify module full name to coverage"
);

bool 
	insertBblAddress(	int bblStart, 		// [IN] bbl start address
						int bblEnd, 		// [IN] bbl ending address
						int bblSize, 		// [IN] bbl size in byte
						char *szTableName, 	// [IN] table name for inserting results
						sqlite3 *db)		// [IN] db handle
{
	char sqlInsert[256];
	char *szError;
	int commandResult;
	
	if ( strlen(szTableName) > 50 )
	{
		fprintf(general_info,"[!] Error table name too big [Max 50].\n");
		return false;
	}
	
	sprintf(sqlInsert, "INSERT INTO %s( bblStart, bblEnd, bblSize ) VALUES( %d, %d, %d );", szTableName, bblStart, bblEnd, bblSize);
	fprintf(general_info,"[*] Inserting 0x%p - 0x%p into %s ...\n", bblStart, bblEnd, szTableName);
	 
	// execute query and insert data into db
	commandResult = sqlite3_exec(	db, 
									sqlInsert, 
									NULL, 
									NULL, 
									&szError);
	if (commandResult)
	{
		fprintf(general_info,"[!] Error executing SQLite3 statement [ insertBblAddress() ]: %s",sqlite3_errmsg(db));
		sqlite3_free(szError);
		return false;
	}

	fprintf(general_info,"[+] Inserted a value into table.\n");
	return true;
}

bool 
	initDatabase(	const char *szDatabaseName,	// [IN]  database name
					char *szTableName, 			// [IN]	 table name
					sqlite3 **db, 				// [OUT] db handle
					bool bCreate)				// [IN]  create new tbale ( szTableName ) in db or just open a handle 
{
	char sqlCreateTable[256] = {0};
	char *szError;
	int commandResult;
	
	if ( ( strlen(szDatabaseName) > 50 ) || ( strlen(szTableName) > 50 ) )
	{
		fprintf(general_info,"[!] Error table/db name too big [Max 50].\n");
		return false;
	}
	
	// open db handle
	commandResult = sqlite3_open(szDatabaseName, db);
	if ( commandResult )
	{
		fprintf(general_info,"[!] Error opening SQLite3 database [ initDatabase() ]: %s\n", sqlite3_errmsg(*db));
		sqlite3_close(*db);
		return false;
	}
	
	// if bCreate set, create new table szTableName in db
	if ( bCreate )
	{
		sprintf(sqlCreateTable, "CREATE TABLE %s ( bblStart int, bblEnd int, bblSize int );", szTableName);
		fprintf(general_info,"[*] Creating %s...\n", szTableName);
		
		// create table query...
		commandResult = sqlite3_exec(	*db, 
										sqlCreateTable, 
										NULL, 
										NULL, 
										&szError);
		if ( commandResult )
		{
			fprintf(general_info,"[!] Error executing SQLite3 statement [ initDatabase() ] : %s \n",sqlite3_errmsg(*db));
			sqlite3_close(*db);
			sqlite3_free(szError);
			return false;
		}
	
		commandResult = sqlite3_exec(	*db, 
										"BEGIN", 
										NULL, 
										NULL, 
										&szError);
		if ( commandResult )
		{
			fprintf(general_info,"[!] Error executing SQLite3 statement [ initDatabase() ]: %s \n",sqlite3_errmsg(*db));
			sqlite3_close(*db);
			sqlite3_free(szError);
			return false;
		}
		
		fprintf(general_info,"[+] Created %s.\n", szTableName);
	}
	
	return true;
}

bool 
	getModuleAddress(	ADDRINT *lowAddr,	// [OUT] module low address
						ADDRINT *highAddr, 	// [OUT] module high address
						char *szModuleName)	// [IN]  module name
{
	// if module address already found just return true
	if ( moduleAddress )
		return true;
	
	// walk module list and check for specified module
	for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) )
	{
		if ( strstr( IMG_Name(img).c_str(), szModuleName ) )
		{
			// get module addresses
			*highAddr = IMG_HighAddress(img);
			*lowAddr  = IMG_LowAddress(img);
			fprintf(general_info,"[+] Module %s Found : 0x%p -- 0x%p\n", szModuleName, *lowAddr, *highAddr);
			return moduleAddress = true;
		}
	}
	
	fprintf(general_info,"[*] Module %s not found!\n", szModuleName);
	return false;
}

// walk every basic block and log addresses
VOID 
	bbl_walker(	ADDRINT bblAddr,	// [IN] bbl first instruction address
				UINT32 bblSize) 	// [IN] bbl size in byte
{
	char *szError;
	ADDRINT bblStart,bblEnd;
	bblStart = bblAddr;
	bblEnd   = ( bblAddr + bblSize ) - 1;
	
	// just log bbl of specified module
	if ( bblStart >= lowA && bblEnd <= highA )
	{
		// inster address to db
		if ( !insertBblAddress(	(bblStart - lowA), // insert bbl offset only, no more relocation pain
								(bblEnd - lowA), 
								(bblEnd - bblStart), 
								tName, 
								globaldb) )
		{
			fprintf(general_info,"[!] insertBblAddress faild.\n");
		}
		
		// commit transaction and start new one...
		if ( tCount >= TRAN )
		{
			if ( sqlite3_exec(	globaldb, 
								"COMMIT", 
								NULL, 
								NULL, 
								&szError) || 
				sqlite3_exec(	globaldb, 
								"BEGIN", 
								NULL, 
								NULL, 
								&szError) )
			{
				fprintf(general_info,"[!] Error executing SQLite3 statement [ commit/begin transaction ] : %s \n",sqlite3_errmsg(globaldb));
				sqlite3_close(globaldb);
				sqlite3_free(szError);
				PIN_ExitApplication(0);
			}
			tCount = 0;
		}
		// log the result
		fprintf(bbl_info,"Basic Block Hit : 0x%p -- 0x%p\n", bblStart, bblEnd);
		tCount++;
	}
}


// Pin calls this function every time a new instruction is encountered
VOID Trace(TRACE trace, VOID *v)
{
	// get module address space range
	getModuleAddress( &lowA, &highA, mName );
	
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		// maybe module load under specific circumstances ,
		if ( moduleAddress )
		{
			// we are in next basic block
			next_bbl_reached = true;
			for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{	
				// catch bbl first instruction address, bbl size and skip other insructions until next bbl
				if( next_bbl_reached )
				{
					// get bbl size
					UINT32 bbl_size = BBL_Size(bbl);
					// this will skiped instrumenting instructions until next bbl
					next_bbl_reached = false;
					
					// register call_back function before execution of first instuction in current bbl
					INS_InsertCall( ins, 
									IPOINT_BEFORE, 			// call bbl_walker before execution of fisrt instruction in bbl
									(AFUNPTR)bbl_walker, 	// call back function
									IARG_ADDRINT, 
									BBL_Address(bbl),		// pass bbl address to call back
									IARG_UINT32,
									bbl_size,				// pass bbl size to call back
									IARG_END);
				}  
			}
		}
	}
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
	char *szError;
	// commit the remaining transactions...
	if ( sqlite3_exec(globaldb, "COMMIT", NULL, NULL, &szError) )
	{
			fprintf(general_info,"[!] Error executing SQLite3 statement [ commiting transaction ] : %s \n",sqlite3_errmsg(globaldb));
			sqlite3_close(globaldb);
			sqlite3_free(szError);
	}
	
	// flush and close
	fflush(bbl_info);
	fflush(general_info);
	fclose(bbl_info);
    fclose(general_info);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool create a db of coverde basic blocks" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
	char tempStr[256] = {'\0'};
	
	// Initialize symbol table code
	PIN_InitSymbols();

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
	
	// Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);
	
	// Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
	
	strncpy( dName , KnobOutputDatabase.Value().c_str(), sizeof(dName)-1 );
	strncpy( tName , KnobDatabaseTable.Value().c_str(), sizeof(tName)-1 );
	strncpy( mName , KnobModuleName.Value().c_str(), sizeof(mName)-1 );

	// fuck the stack overflow!
	sprintf(tempStr , "%s_%s_bbl_info.txt", mName, tName);
	bbl_info     = fopen(tempStr, "w");
	memset(tempStr, 0, sizeof(tempStr)-1 );
	sprintf(tempStr , "%s_%s_general_info.txt", mName, tName);
	general_info = fopen(tempStr, "w");
	
	// initilize database and create table
	if ( !initDatabase(	dName, 
						tName, 
						&globaldb, 
						true ) ) 
	{
		// call Fini before exiting the application...
		PIN_ExitApplication(0);	
	}
	
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
