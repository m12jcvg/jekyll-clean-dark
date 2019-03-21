---
layout: post
title: "Rebase-Fix - MITRE 19"
date: 2019-03-09 16:21:06
tags: CTFWriteup Reversing MITRE Stripped UPX
description: CTF Mitre Cyber Challenge, Categoria RE
---

Archivo: [REbase-fix](/assets/posts/rebasefix/rebasefix)
Servidor: rev.tamuctf.com:7224

```
$ file REbase-fix
REbase-fix: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
```

<p style='text-align: justify;'>
Como podemos ver a partir del resultado de file el binario es "stripped" por lo que tendremos que lidiar con
identificar las funciones que realmente nos interesa. Sin embargo al cargarlo en IDA podemos notar que solo contiene
4 funciones adicionales al entry point
</p>

![Init]({{ '/assets/posts/rebasefix/init.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Además al buscar los strings del ejecutable nos topamos con lo siguiente
</p>

![Strings Init]({{ '/assets/posts/rebasefix/sinit.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Una vez determinado que el binario esta empaquetado con UPX procedemos a descomprimirlo para obtener un binario sobre 
el cual poder trabajar.
</p>

```
upx -d rebasefix
```

<p style='text-align: justify;'>
Procedemos a cargar este binario nuevamente en IDA y al ver los strings podemos ver que ahora si tenemos algo con que trabajar, 
ademas de que ahora si podemos observar todas las funciones que contiene el binario. A su vez se pueden identificar facilmente 3 strings
de interes: "Usage: ./REbase flag", "Congratulations!" y "Try Again :(" que nos serviran para tomar como punto de partida para el análisis.
</p>

![Strings Unpacked]({{ '/assets/post/rebasefix/sunpacked.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Al ir a la seccion donde se encuentra referenciado el string "Congratulations!" podemos ver que los 3 strings son refernciados en la misma función
por lo que podemos concentrarnos en esa sección e ignorar lo demas.
</p>

![Main]({{ '/assets/post/rebasefix/main.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Como podemos observar hay 6 funciones en esa seccion que deberiamos identificar, algunas podemos deducir que es lo que hacen por ver los parametros
y confirmarlo en tiempo de ejecucion.
</p>

```
	sub_4098B0: print, se manda llamar en 0x401F9F, 0x40207D y 0x40208B y en los 3 casos se le pasa el offset de un string como parametro.
```

```
	sub_408440: exit, normalmente las funciones que tienen un ayuda de "Usage" despues de imprimirla terminan la ejecución (lo podemos confirmar 
	en tiempo de ejecucion) y el parametro es el 1 lo que indicaria un termino de programa con error lo cual hace sentido.
```

```
	sub_401BED: process_input, en la imagen no se ve sin embargo la funcion contiene 2 variables locales y una de ellas sirve para comparar si debe
	ejecutarse o imprimir la ayuda, lo anterior lo decide en base a un valor numerico por lo que podemos asumir que puede que sean ARGV y ARGC donde
	var_60 = ARGC, ademas de que posteriormente le suma 8 a ARGC combinado con el usage podemos asumir que esta accediendo al input que pasamos en consola.
	
	Posteriormente en tiempo de ejecucion se confirma lo anterior.
```

```
	sub_408DF0: Llamada en 0x402030 y 0x40204B, en el primer caso recibe el resultado de sub_401BED y en el segundo caso el string que se creo en la variable var_50
		
	sub_409A70: Llamada en 0x40203A y 0x402055, en ambos casos se le pasa 0xA como parametro.
	
	Ambas funciones combinadas mandan los caracteres a pantalla aunque cabe recalcar que es hasta sub_409A70 cuando se hace el flush a pantalla, para nuestro caso
	no importa por lo que podemos renombrarlas tambien como print
```

```
	sub_401098: recibe 2 parametros, 1 corresponde a la salida de sub_401BED y otro al string que se almacena en var_50, a su vez el resultado lo compara para validar si 
	es 0 para en base a eso decidir que salto hacer, por lo que podemos asumir que es un tipo de strcmp que compara ambos strings.
```
<p style='text-align: justify;'>
Si observamos el valor de la variable var_50 vemos que termina en el caracter = por lo que como primera opcion seria intentar decodificarlo con base64 sin embargo aunque lo decodifica
no nos da ningún flag legible por lo que podemos asumir que tiene algo adicional.

Con todo lo anterior podemos afocarnos a sub_401BED para ver de que manera procesa nuestro input.
</p>

![sub_401BED]({{ '/assets/post/rebasefix/sub_401bed.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
	Dentro de la función podemos encontrar un alfabeto definido por lo que procedemos a buscar/codificar un script que decofique base64 con un alfabeto 
	personalizado e intentar nuevamente decodificar var_50.
</p>

<p style='text-align: justify;'>
Aunque codificar un script no es complicado preferí utilizar el sitio https://www.malwaretracker.com/decoder_base64.php que permite realizar lo anterior y proceder a obtener el flag.
</p>

