��    &      L  5   |      P  J   Q     �  '   �  �   �  �   l  "        >  &   R     y     �     �  �   �  <   y  �  �     �     �     �      �     �  %   	  .   =	     l	  $   {	     �	     �	     �	     �	      
     (
     E
     c
     �
     �
     �
     �
     �
  (   �
  �  �
  V   m  	   �  2   �  �     �   �  /   �     �  ?   �          ,     L  �   f  I   '  &  q     �  $   �     �  )   �  /     2   =  8   p     �     �      �  &   �     "     5  !   Q     s     �     �     �     �     �     �     �  ,   �                  !      %                             $                            	   &       
                                  "                                          #            - Program for secure cleaning of free space on ext2/3 partitions
Syntax:   [options]  - Device is mounted in read-write mode: --nounrm		Do NOT wipe undelete information
--nowfs			Do NOT wipe free space on file system
-v|--verbose		Verbose output
-V|--version		Print version number
 -h|--help		Print help
-l|--license		Print license information
-n|--iterations NNN	Number of passes (>0, default: 25)
--nopart		Do NOT wipe free space in partially used blocks Checking if file system is mounted Closing file system File system invalid or dirty, flushing Filesystem has errors: Nothing selected for wiping. Opening file system Options:
-b|--superblock <off>	Superblock offset on the given filesystems
-B|--blocksize <size>	Block size on the given filesystems
-f|--force		Wipe even if the file system has errors PLEASE do NOT set this program's suid bit. Use sgid instead. Program for secure cleaning of free space on ext2/3 partitions.

This program is Free Software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

 Reading block bitmap from Setting signal handlers Using pattern Wiping free space on file system Wiping undelete data on Wiping unused space in used blocks on during checking if the file system is mounted: during closing during iterating over a directory on during iterating over blocks on during malloc while working on during opening during opening a scan of during reading block bitmap from during reading of a block on during reading of an inode on during writing of a block on error random unknown version while flushing while trying to set a signal handler for Project-Id-Version: e 2wfs
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2007-04-24 11:48+0200
PO-Revision-Date: 2007-04-24 11:48+0200
Last-Translator: Bogdan Drozdowski <bogdan@bogdan.org.pl>
Language-Team: Polish
MIME-Version: 1.0
Content-Type: text/plain; charset=ISO-8859-2
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=3; plural=(n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);
  - Program do bezpiecznego czyszczenia pustego miejsca na partycjach ext2/3
Sk�adnia:   [opcje]  - Urz�dzenie jest zamontowane do odczytu i zapisu: --nounrm		NIE czy�� informacji s�u��cych do odzyskiwania plik�w
--nowfs			NIE czy�� pustego miejsca na systemie plik�w
-v|--verbose		Wy�wietlaj szczeg�y dzia�ania
-V|--version		Wy�wietl numer wersji
 -h|--help		Wy�wietl pomoc
-l|--license		Wy�wietl informacje o licencji
-n|--iterations NNN	Liczba przej�� (>0, domy�lne: 25)
--nopart		NIE czy�� pustego miejsca w cz�ciowo u�ywanych blokach Sprawdzanie, czy system plik�w jest zamontowany Zamykam system plik�w System plik�w nieprawid�owy lub ma niezapisane zmiany, zapisuj� System plik�w zawiera b��dy: Nie wybrano nic do czyszczenia. Otwieranie systemu plik�w Opcje:
-b|--superblock <off>	Pozycja Superbloku na podanych systemach plik�w
-B|--blocksize <size>	Rozmiar bloku na podanych systemach plik�w
-f|--force		Czy�� nawet gdy system plik�w ma b��dy PROSZ� NIE ustawiaj bitu suid dla tego programu. Zamiast tego, u�yj sgid. Program do bezpiecznego czyszczenia pustego miejsca na systemach plik�w ext2/3

Niniejszy program jest wolnym oprogramowaniem; mo�esz go
rozprowadza� dalej i/lub modyfikowa� na warunkach Powszechnej
Licencji Publicznej GNU, wydanej przez Fundacj� Wolnego
Oprogramowania - wed�ug wersji 2-giej tej Licencji lub ktorej�
z p�niejszych wersji.

Niniejszy program rozpowszechniany jest z nadziej�, i� b�dzie on
u�yteczny - jednak BEZ JAKIEJKOLWIEK GWARANCJI, nawet domy�lnej
gwarancji PRZYDATNO�CI HANDLOWEJ albo PRZYDATNO�CI DO OKRE�LONYCH
ZASTOSOWA�.

 Czytam bitmap� blok�w z Ustawianie procedur obs�ugi sygna��w U�ywam wzorca Czyszcz� puste miejsce na systemie plik�w Czyszcz� dane s�u��ce do odzyskiwania plik�w na Czyszcz� nieu�ywane miejsce w u�ywanych blokach na podczas sprawdzania, czy system plik�w jest zamontowany: podczas zamykania podczas iterowania katalogu na podczas iterowania po blokach na przy alokacji pami�ci podczas pracy na podczas otwierania podczas otwierania skanu na podczas czytania bitmapy blok�w z podczas czytania bloku z podczas czytania i-w�z�a z podczas zapisu bloku na b��d losowy nieznany wersja podczas zapisu systemu na dysk podczas ustawiania procedury obs�ugi sygna�u 