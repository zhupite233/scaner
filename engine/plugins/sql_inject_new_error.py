# --*-- coding: utf-8 ---
import re
from engine.logger import scanLogger as logger
'''
错误型sql注入，结合sql插件使用，在注入请求返回的内容中查找是否存在database错误信息
'''


def check_db_error(content):
    try:
        if content.find("SQLite error") >= 0:
            return True, "SQLite", "SQLite error"
        if content.find("You have an error in your SQL syntax") >= 0:
            return True, "mysql", "You have an error in your SQL syntax"
        if content.find("supplied argument is not a valid MySQL") >= 0:
            return True, "mysql", "supplied argument is not a valid MySQL"
        if content.find('Microsoft JET contentbase Engine') >= 0:
            return True, "access", "Microsoft JET contentbase Engine"
        if content.find('Microsoft JET Database Engine') >= 0:
            return True, "access", "Microsoft JET Database Engine"
        if content.find('Microsoft OLE DB Provider for SQL Server') >= 0:
            return True, "mssql", "Microsoft OLE DB Provider for SQL Server"
        if content.find('System.content.SqlClient.SqlException') >= 0:
            return True, "mssql", "System.content.SqlClient.SqlException"
        if content.find('System.content.SqlClient.SqlException') >= 0:
            return True, "mssql", "System.content.SqlClient.SqlException"
        if content.find('System.content.OleDb.OleDbException') >= 0:
            return True, "mssql", "System.content.OleDb.OleDbException"
        if content.find("[Microsoft][ODBC Microsoft Access Driver]") >= 0:
            return True, "access", "[Microsoft][ODBC Microsoft Access Driver]"
        if content.find("[Microsoft][ODBC SQL Server Driver]") >= 0:
            return True, "mssql", "[Microsoft][ODBC SQL Server Driver]"
        if content.find("Microsoft OLE DB Provider for ODBC Drivers") >= 0:
            return True, "mssql", "Microsoft OLE DB Provider for ODBC Drivers"
        if content.find("Microsoft OLE DB Provider for ODBC Drivers") >= 0:
            return True, "mssql", "Microsoft OLE DB Provider for ODBC Drivers"
        if content.find("java.sql.SQLException: Syntax error or access violation") >= 0:
            return True, "oracle", "java.sql.SQLException: Syntax error or access violation"
        if content.find("PostgreSQL query failed: ERROR: parser:") >= 0:
            return True, "PostgreSQL", "PostgreSQL query failed: ERROR: parser:"
        if content.find("invalid input syntax for") >= 0:
            return True, "PostgreSQL", "invalid input syntax for"
        if content.find("XPathException") >= 0:
            return True, "XPath", "XPathException"
        if content.find("supplied argument is not a valid ldap") >= 0:
            return True, "LDAP", "supplied argument is not a valid ldap"
        if content.find("javax.naming.NameNotFoundException") >= 0:
            return True, "LDAP", "javax.naming.NameNotFoundException"
        if content.find("DB2 SQL error:") >= 0:
            return True, "db2", "DB2 SQL error:"
        if content.find('[IBM][JDBC Driver]') >= 0:
            return True, "db2", "[IBM][JDBC Driver]"

        if content.find("Dynamic SQL Error") >= 0:
            return True, "Interbase", "Dynamic SQL Error"
        if content.find("Sybase message:") >= 0:
            return True, "sybase", "Sybase message:"
        ora_test = re.search("ORA-[0-9]{4,}", content)
        if ora_test:
            return True, "oracle", "ORA"
        return False, "", ""
    except Exception, e:
        logger.error("File:sql_inject_new_error.py, check_db_error:" + str(e))
        return False, "", ""
