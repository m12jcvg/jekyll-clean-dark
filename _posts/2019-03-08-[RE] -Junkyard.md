---
layout: post
title: "Insomnihack 2019 RE Junkyard"
date: 2019-03-18 00:00:00
description: CTF: Insomnihack 2019, Categoria: Reversing, Problema: Junkyard
tags: 
 - RE Insomnihack CTFWriteup
---

# Junkyard

Al entrar al main del binario lo primero que observamos es que requiere que 
vengan 2 parametros (3 tomando en cuenta que el parametro 0 siempre es el nombre 
del programa, a su vez esto ya se habia indicado en el problema e incluso nos 
daban el primer parametro):



![cmp rbp+var_844,3](main.png)

Al continuar con el análisis podemos observar que el binario contiene muchas 
funciones inútiles y constantemente lleva a cabo ciclos y comparaciones sin 
sentido con la finalidad de hacer más dificil el análisis del binario.

La primera parte interesante para nuestro análisis es cuando manda llamar
una funcion a la cual le pasa cada uno de los parametros y dependiendo del
resultado prosigue la ejecución o no.

![Validación de longitud de los parametros](size_param.png)

Como podemos observar lo que hace es validar que los parametros tengan una 
longitud > 0xF (ja = jump above) y longitud <= 0x3F (setbe = set byte if 
below or equal). Si las condiciones antes descritas se cumplen para ambos 
parametros continua con la ejecucion del programa.

Posteriormente ejecutara una sumatoria para calcular un numero que sera usado
posteriormente para obtener el flag correcto. Dicho número se calcula a 
base de lo siguiente:

def calculo(_usuario):
	r = 0
	for c in _usuario:
		r += hex(c)*2 ^ 0x3627
	return r

arreglo = [0x75, 0x0CE, ..., 0x148DC, 0x1497A, 0x14C27]
ebx = ord(pwd[0]] - 0x30
eax = arreglo[ord(pwd[2])]
eax += ebx
eax += 0x27a
sumatoria = calculo(_usuario) + eax # 0xd9dc8 + eax

![Cálculo de sumatoria](sumatioria1.png)

Una vez obtenida la sumatoria realiza un ciclo para sumar dicho valor a 
cada elemento del arreglo mencionado anteriormente.

![array](ciclo_array.png)

Lo anterior se requiere ya que sera un elemento del arreglo el que sirva 
de base para calcular un MD5 que le permitira saber si procede o no a
llamar las respectivas APIs de aes_decrypt para imprimir el flag.

Para calcular el indice del elemento que servira como input del MD5 realiza 
la  siguiente operacion:

indice = 0x9f - ord(pwd[0])

Una vez obtenido dicho indice convierte el valor en un string en su 
representacion decimal.

![Calculo](calculo_desde_array.png)

Una vez obtenido dicho valor lleva a cabo una serie de procesos que convierten
el string en otro string pero concatenando los codigos ascii de cada char,
es decir:

'12345' = '3132333435'

para posteriormente tomar un substring de longitud 4 a partir del 6 caracter,
en este caso tomaria '3343' y obtiene el valor MD5 de dicho valor.

![MD5](md5_ascii.png)

finalmente procedera a comparar mediante la funcion strcnmp el hash obtenido
contra uno que tiene almacenado dentro del binario y que corresponde al
string 7303, si esto es verdadero procedera con las llamadas correspondientes
para intentar imprimir el flag.

![Comparacion hash](strcnmp.png)

Con toda esta información podemos deducir que requerimos un password que 
cumpla con lo siguiente: 0xF < len(paswd) <= 0x3F. Ademas de que el primer
y tercer caracter seran usados para que obtengamos un numero de al menos 
5 digitos que en su tercer y cuarto digito sean 7 y 0 respectivamente para
que al ser convertidos a ascii nos de como resultado 3X3X37303X y de esa
manera pueda obtener el string 7303 que se usa para el md5.

Cabe mencionar que al ejecutar el aes_decrypt en ocasiones da un error
sin embargo con la información anterior se codifico un script para que 
pruebe todas las combinaciones que cumplan con los requisitos anteriores
hasta que el programa nos de el flag.



