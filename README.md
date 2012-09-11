    
	pinStalk code coverage analysis tool
    PIN toolkit instrumentation module that log the execution flow (basic blocks).

    Usage:
        pin.exe -t pinStalk.dll -db <database_name> -t <table_name> -m <module_name> -- <program_to_run>
		-db : database name you want to create or filled with new data
		-t  : table name in the database
		-m  : module you want to trace its execution
		
    Example :
		pin.exe -t pinStalk.dll -db calc.db -t calc_1st_run -m calc.exe -- calc
		
	
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
	
	**compiled with Pin Kit rev 43611.**