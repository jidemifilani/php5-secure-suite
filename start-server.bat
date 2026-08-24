@echo off
REM Starts PHP5 Secure Suite on the real PHP 5.6.40 runtime installed at C:\xampp\php56.
REM MariaDB (from the existing XAMPP install) must already be running.
C:\xampp\php56\php.exe -S 0.0.0.0:8050 -t "%~dp0public" "%~dp0router.php"
